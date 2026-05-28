# StaticVoid

API-driven Gmail spam filtering. Parses raw MIME payloads to permanently delete messages matching configurable blocklist criteria.

StaticVoid is a Google Apps Script utility that automatically monitors the Gmail Spam folder and permanently deletes aggressive spam, bypassing the 30-day Trash cycle entirely. 

While Gmail's native filters can only send mail to the Spam or Trash folders, StaticVoid leverages the Advanced Gmail API to execute a true delete operation (`Gmail.Users.Threads.remove`), keeping the mailbox clean and secure.

## Features

- **Permanent Deletion:** Bypasses the Trash folder, permanently destroying matching threads via direct API drops to save storage space and remove risk.
- **Dual-Layer Inspection Engine:** Combines fast envelope metadata evaluations (Layer 1) with full MIME payload parsing (Layer 2) to decode base64 body content, evaluate message text, and extract URLs.
- **Modular Configuration:** Centralizes all rules within a single `CONFIG` block, making it simple to manage blocklists, whitelist overrides, and system toggles.
- **Modern Exploit Detection:** Includes built-in defenses against advanced spam tactics, including Unicode emoji subject abuse and Gmail "Reaction" payload exploits.
- **Smart TLD Escaping:** Automatically handles character escaping for complex top-level domains like `web.id` or `pro` to be added directly to the blocklist without manual regex styling.
- **Command Center Dashboard:** Deployable as a web app interface to monitor active rule definitions and trigger manual firewall sweeps asynchronously.

## Installation & Setup

1. Go to [script.google.com](https://script.google.com) and create a new project.
2. Create a script file named `src/staticvoid.js` and paste the core engine code.
3. Create a HTML file named `src/dashboard.html` and paste the dashboard interface code.
4. **Required Step:** On the left-hand menu, click the **+** next to **Services** in the left sidebar menu. Scroll down, select **Gmail API**, and click **Add**. *(The script will fail to execute if this service is missing).*
5. Edit the `CONFIG` block at the top of `src/staticvoid.js` to define the targeted spam patterns and whitelist conditions.
6. Save the project files.

## Automation

To configure StaticVoid to run automatically in the background:

1. Click the **Triggers** icon (the clock graphic) in the left sidebar menu.
2. Click the **Add Trigger** button in the bottom right corner.
3. Set the function to run to `main`.
4. Set the deployment to `Head`.
5. Select **Time-driven** for the event source.
6. Choose the preferred interval (e.g., an **Hour timer** or **Minutes timer**).
7. Save the trigger settings.

## License

This project is licensed under the [GNU GPLv3 License](LICENSE). 

*Note: This project is a heavily modified fork of the original [Spam Zero](https://github.com/spamzero/spamzero) script, upgraded to utilize REST API functionality, modular configuration blocks, and advanced payload parsing techniques.*
