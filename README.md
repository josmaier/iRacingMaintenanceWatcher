![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)
# iRacingMaintenanceWatcher
Script that watches the iRacing API for maintenance.

I do not provide support for this script or guarantee that it stays working

# How to use

Rename the dotenv file to .env and add all required variables.
Afterwards either:
    - npm install
    - node iRacingMaintenanceWatcher.js

Or:
    -npm install
    -pm2 start ecosystem.config.js

# What it actually does
The script pulls from the iRacing api every 120 seconds (default).
If it observes a state change in the iRacing status, it logs it and waits for a confirming second status message. If the status is the same both times it sends out a discord embed to the specified webhook url.
It includes up/downtime by just subtracting current time from last time and formatting it to a better format.

# License

This project is licensed under the MIT License.  
See the [LICENSE](./LICENSE) file for details.