![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)

# iRacingMaintenanceWatcher

A Node.js script that watches the iRacing API for maintenance and posts status updates to a Discord webhook.

Note:

- I do not provide support for this script or guarantee that it will always work.

- iRacing may change their API at any time.

------------------------------------------------------------

## How to Use

1. Rename `dotenv` to `.env` and fill in all required variables.

2. Install dependencies:

	- npm install

3. Run the script in one of two ways:

  
Directly:
- node iRacingMaintenanceWatcher.js

With pm2 (recommended):
- pm2 start ecosystem.config.js
- pm2 save

------------------------------------------------------------

## What It Does

- Polls the iRacing API every 120 seconds (default, configurable).

- On each poll, checks if the service is:

	- online

	- or in maintenance

- If a state change is observed:

	- Waits for a second confirmation

		- Sends a Discord embed to the configured webhook with:

			* Current status

			* Uptime or downtime duration (calculated from the last change timestamp)

------------------------------------------------------------

## License

This project is licensed under the MIT License.

See the [LICENSE](./LICENSE) file for details.