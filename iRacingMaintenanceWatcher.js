/**
 * iRacing maintenance watcher
 * Auths with Legacy Auth persists cookies polls at set interval from endpoint;
 * sends Discord webhooks only on state change.
 */
import dotenv from "dotenv";
import axios from "axios";
import { wrapper } from "axios-cookiejar-support";
import { CookieJar } from "tough-cookie";

import fs from "fs";
import crypto from "crypto";

dotenv.config();

const IR_AUTH_URL = "https://members-ng.iracing.com/auth";
const IR_HEALTH_URL = "https://members-ng.iracing.com/data/constants/categories";

const EMAIL = (process.env.IR_EMAIL || "").trim();
const PASSWORD = process.env.IR_PASSWORD || "";
const DISCORD_WEBHOOK_URL = (process.env.DISCORD_WEBHOOK_URL || "").trim();

const POLL_SECONDS = Number(process.env.POLL_SECONDS || 120); //default 2 minutes
const LOG_LEVEL = (process.env.LOG_LEVEL || "info").toLowerCase();

const COOKIES_PATH = process.env.IR_COOKIE_JAR || "./iracing_cookies.txt";
const STATE_PATH = process.env.IR_STATE_FILE || "./iracing_maintenance_state.json";
const HTTP_TIMEOUT = 20000;

if (!EMAIL || !PASSWORD || !DISCORD_WEBHOOK_URL) {
    console.error("Missing required env: IR_EMAIL, IR_PASSWORD, DISCORD_WEBHOOK_URL");
    process.exit(1);
}

function log(level, msg) {
    const levels = ["error", "warn", "info", "debug"];
    if (levels.indexOf(level) <= levels.indexOf(LOG_LEVEL)) {
        const ts = new Date().toISOString();
        console.log(`${ts} ${level.toUpperCase()} ${msg}`);
    }
}

//Iracing wants the format Base64( SHA256( password + lowercase(email) ) )
function hashPassword(email, password) {
    const lowered = (email || "").trim().toLowerCase();
    const buf = crypto.createHash("sha256").update(password + lowered, "utf8").digest();
    return buf.toString("base64");
}

//Just get the current time as string
function utcNowISO() {
    return new Date().toISOString();
}

//Loads the currently saved state from the json file
function loadState() {
    try {
        if (fs.existsSync(STATE_PATH)) {
            return JSON.parse(fs.readFileSync(STATE_PATH, "utf8"));
        }
    } catch {
        log("warn", "Could not read state file; starting fresh.");
    }
    return { in_maintenance: null, last_change: null };
}

//Saves the current state in the json file (so we do not loose it if the script breaks)
function saveState(inMaintenance) {
    const state = { in_maintenance: inMaintenance, last_change: utcNowISO() };
    fs.writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
}

//Send the webhook message with the http client
async function sendDiscord(title, description, colorHex) {
    try {
        await axios.post(
            DISCORD_WEBHOOK_URL,
            {
                embeds: [
                    {
                        title,
                        description,
                        color: Number(colorHex),
                        timestamp: utcNowISO()
                    }
                ]
            },
            { timeout: HTTP_TIMEOUT }
        );
    } catch (e) {
        log("warn", `Discord webhook failed: ${e?.response?.status || ""} ${e?.message}`);
    }
}

//We watch if the status respone is maintenance, if yes we make a message and set our flag
function interpretResponse(status, body) {
    if (status === 503) {
        let msg = "Service is in maintenance.";
        try {
            if (body && typeof body === "object") {
                const m = body.message || msg;
                const note = body.note;
                msg = note ? `${m}\n${note}` : m;
            }
        } catch { }
        return { inMaintenance: true, message: msg };
    }
    return { inMaintenance: false, message: null };
}

//just logging into iRacing with our http client and waiting for the result
async function iracingAuth(http) {
    const payload = { email: EMAIL, password: hashPassword(EMAIL, PASSWORD) };
    const resp = await http.post(IR_AUTH_URL, payload, {
        timeout: HTTP_TIMEOUT,
        headers: { "Content-Type": "application/json" }
    });
    if (resp.status !== 200) {
        throw new Error(`Auth failed: ${resp.status} ${resp.statusText} :: ${resp.data ? JSON.stringify(resp.data) : ""}`);
    }
    log("info", "Authenticated successfully.");
}

//When iRacing gets mad at us for the rate we send messages, we just wait for a bit
function maybeBackoffForRateLimit(resp) {
    const limit = Number(resp.headers?.["x-ratelimit-limit"] || 0);
    const remaining = Number(resp.headers?.["x-ratelimit-remaining"] || 0);
    const reset = Number(resp.headers?.["x-ratelimit-reset"] || 0);
    if (!limit) return 0;
    if (remaining <= Math.max(1, Math.floor(limit / 20))) {
        const now = Math.floor(Date.now() / 1000);
        if (reset > now) return Math.min(reset - now, 120);
    }
    return 0;
}

//Builds the GET request to the server
async function makeHttp() {
    const jar = new CookieJar(); // in-memory; persists while process runs
    const http = wrapper(
        axios.create({
            jar,
            withCredentials: true,
            timeout: HTTP_TIMEOUT,
            maxRedirects: 5, // <- important so Set-Cookie on redirects is captured
            headers: { "User-Agent": "iracing-maintenance-watch-node/1.0 (+discord)" },
            validateStatus: () => true
        })
    );
    return { http, jar }; // <- return both
}

//Just send our poll requjest once, if we get unauthorized, authenticate again
async function pollOnce(http) {
    let resp = await http.get(IR_HEALTH_URL);
    log("debug", "Polling iRacing");
    if (resp.status === 401) {
        log("info", "401 (unauthorized). Re-authenticating…");
        await iracingAuth(http);
        resp = await http.get(IR_HEALTH_URL);
    }
    const backoff = maybeBackoffForRateLimit(resp);
    if (backoff > 0) {
        log("info", `Rate limit near; pausing ${backoff}s.`);
        await new Promise((r) => setTimeout(r, backoff * 1000));
    }
    return interpretResponse(resp.status, resp.data);
}

//We format the time since we last had a change
function formatDuration(ms) {
    const sec = Math.floor(ms / 1000);
    const units = [
        ["week", 7 * 24 * 3600],
        ["day", 24 * 3600],
        ["hour", 3600],
        ["minute", 60],
        ["second", 1],
    ];
    const parts = [];
    let remaining = sec;
    for (const [name, size] of units) {
        if (remaining >= size) {
            const qty = Math.floor(remaining / size);
            parts.push(`${qty} ${name}${qty !== 1 ? "s" : ""}`);
            remaining %= size;
            if (parts.length === 2) break; // keep it short
        }
    }
    return parts.length ? parts.join(" ") : "0 seconds";
}


async function main() {
    const { http, jar } = await makeHttp();

    //If the script is started and we do not have a login cookie yet, we need to get one

    try {
        await iracingAuth(http);
    } catch (e) {
        log("error", `Initial auth failed: ${e.message}`);
    }

    try {
        const serialized = jar.serializeSync(); // tough-cookie v4 has serializeSync
        log("debug", `Cookies after auth (serializeSync): ${JSON.stringify(serialized.cookies || [])}`);

        // Also confirm what cookies are considered valid for the domain:
        const cookiesForMembers = jar.getCookiesSync("https://members-ng.iracing.com");
        log("debug", `Cookies visible for members-ng.iracing.com: ${cookiesForMembers.map(c => c.key + "=" + c.value).join("; ") || "(none)"}`);
    } catch (e) {
        log("warn", `Cookie debug failed: ${e.message}`);
    }


    //first check
    const state = loadState();
    log("info", `Polling every ${POLL_SECONDS}s. Current state: ${JSON.stringify(state)}`);

    let stopping = false;
    const stop = () => {
        if (!stopping) {
            stopping = true;
            log("info", "Shutting down…");
            setTimeout(() => process.exit(0), 200);
        }
    };
    //We stop the program when we get a stop signal so we do not just ctrl c it
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);

    
    // keep track of possible state change in progress
    let pendingChange = null; // { target: boolean, seen: number }

    while (!stopping) {
        
        log("debug", `in loop`);
        try {
            const { inMaintenance, message } = await pollOnce(http);
            const prev = state.in_maintenance;
            const now = Date.now();
            const lastChangeMs = state.last_change ? Date.parse(state.last_change) : now;

            if (prev === null) {
                // First observation → one status message (no duration)
                state.in_maintenance = inMaintenance;
                saveState(inMaintenance);

                const title = "iRacing Status";
                if (inMaintenance) {
                    await sendDiscord(`${title}: Maintenance`, message || "Service is in maintenance.", 0xe67e22);
                } else {
                    await sendDiscord(`${title}: Online`, "API responding normally.", 0x2ecc71);
                }

            } else if (inMaintenance !== prev) {
                // Potential change detected: require two consecutive confirmations
                if (pendingChange && pendingChange.target === inMaintenance) {
                    pendingChange.seen += 1;
                } else {
                    pendingChange = { target: inMaintenance, seen: 1 };
                }

                if (pendingChange.seen >= 2) {
                    // Confirmed change → compute duration of the previous state
                    const elapsed = now - lastChangeMs;

                    if (inMaintenance) {
                        const uptime = formatDuration(elapsed);
                        const desc = `Maintenance started.\n(Uptime: ${uptime})`;
                        await sendDiscord("iRacing entered maintenance", desc, 0xe67e22);
                    } else {
                        const downtime = formatDuration(elapsed);
                        const desc = `Service restored.\n(Downtime: ${downtime})`;
                        await sendDiscord("iRacing is back online", desc, 0x2ecc71);
                    }

                    state.in_maintenance = inMaintenance;
                    saveState(inMaintenance);       // updates last_change to now
                    pendingChange = null;           // reset guard
                }

            } else {
                // No change → clear any partial guard
                pendingChange = null;
            }

        } catch (e) {
            log("warn", `Poll error: ${e.message}`);
        }
        log("debug", `Sleeping ${POLL_SECONDS}s before next poll`);
        await new Promise((r) => setTimeout(r, POLL_SECONDS * 1000));
    }
}

// Start the main function and handle errors
main().catch((e) => {
    console.error(e);
    process.exit(1);
});