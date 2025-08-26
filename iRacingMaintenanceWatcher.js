/**
 * iRacing maintenance watcher
 * Auths with Legacy Auth persists cookies polls at set interval from endpoint;
 * sends Discord webhooks only on state change.
 */

require("dotenv").config(); //We need this
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios").default; //HTTP Client
const { CookieJar } = require("tough-cookie");
const FileCookieStore = require("tough-cookie-file-store2");
const { wrapper } = require("axios-cookiejar-support");

const IR_AUTH_URL = "https://members-ng.iracing.com/auth";
const IR_HEALTH_URL = "https://members-ng.iracing.com/data/constants/categories";

const EMAIL = process.env.IR_EMAIL;
const PASSWORD = process.env.IR_PASSWORD;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL;

const POLL_SECONDS = Number(process.env.POLL_SECONDS || 300); //default 5 minutes
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
    const resp = await http.post(IR_AUTH_URL, payload, { timeout: HTTP_TIMEOUT });
    if (resp.status !== 200) throw new Error(`Auth failed: ${resp.status} ${resp.statusText}`);
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
    const abs = path.resolve(COOKIES_PATH);
    const dir = path.dirname(abs);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    const jar = new CookieJar(new FileCookieStore(abs));
    const http = wrapper(
        axios.create({
            jar,
            withCredentials: true,
            timeout: HTTP_TIMEOUT,
            headers: { "User-Agent": "iracing-maintenance-watch-node/1.0 (+discord)" },
            validateStatus: () => true
        })
    );
    return http;
}

//Just send our poll requjest once, if we get unauthorized, authenticate again
async function pollOnce(http) {
    let resp = await http.get(IR_HEALTH_URL);
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


async function main() {
    const http = await makeHttp();

    //If the script is started and we do not have a login cookie yet, we need to get one
    try {
        if (!fs.existsSync(COOKIES_PATH) || fs.statSync(COOKIES_PATH).size === 0) {
            log("info", "No cookie jar yet; authenticating.");
            await iracingAuth(http);
        }
    } catch (e) {
        log("warn", `Cookie check/auth issue: ${e.message}`);
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
        try {
            const { inMaintenance, message } = await pollOnce(http);
            const prev = state.in_maintenance;

            if (prev === null) {
                // first observation of any status is always sent to check
                state.in_maintenance = inMaintenance;
                saveState(inMaintenance);

                const title = "iRacing Status";
                if (inMaintenance) {
                    await sendDiscord(`${title}: Maintenance`, message || "Service is in maintenance.", 0xe67e22);
                } else {
                    await sendDiscord(`${title}: Online`, "API responding normally.", 0x2ecc71);
                }

            } else if (inMaintenance !== prev) {
                // possible change detected
                if (pendingChange && pendingChange.target === inMaintenance) {
                    pendingChange.seen += 1;
                } else {
                    pendingChange = { target: inMaintenance, seen: 1 };
                }

                // we wait for a second confirming status so that we do not send it when the api just sends one code
                if (pendingChange.seen >= 2) {
                    if (inMaintenance) {
                        await sendDiscord("iRacing entered maintenance", message || "Service is in maintenance.", 0xe67e22);
                    } else {
                        await sendDiscord("iRacing is back online", "API responding normally.", 0x2ecc71);
                    }
                    state.in_maintenance = inMaintenance;
                    saveState(inMaintenance);
                    pendingChange = null; // reset guard
                }

            } else {
                pendingChange = null;
            }

        } catch (e) {
            log("warn", `Poll error: ${e.message}`);
        }

            await new Promise((r) => setTimeout(r, POLL_SECONDS * 1000));
        }
    }
    
    // Start the main function and handle errors
    main().catch((e) => {
        console.error(e);
        process.exit(1);
    });