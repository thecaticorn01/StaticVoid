# MailDrop: A Modern Firewall for Your Inbox

MailDrop is a Google Apps Script utility that automatically monitors your Gmail Spam folder and **permanently deletes** highly aggressive or targeted spam, bypassing the 30-day Trash cycle entirely. 

While Gmail's native filters can only send mail to the Spam or Trash folders, MailDrop leverages the Advanced Gmail API to execute a true "hard delete" (`Gmail.Users.Threads.remove`), keeping your email pristine.

## Features

- **Hard Deletion:** Bypasses the Trash folder, permanently destroying matching threads.
- **Modular Configuration:** Easily add bad TLDs, exact phrases, or Regex patterns to a single `CONFIG` block.
- **Raw Header Parsing:** Scans the raw email source to catch hidden routing data, forged headers, or invisible tracking pixels.
- **Modern Payload Detection:** Includes built-in filters for modern spam tactics, including Unicode emoji subject abuse and Gmail "Reaction" abuse.
- **Smart TLD Escaping:** Add domains like `web.id` or `co.uk` to the blocklist without worrying about regex string escaping.

## Installation & Setup

1. Go to [script.google.com](https://script.google.com) and create a new project.
2. Copy the contents of `maildrop.js` and paste it into the editor.
3. **Crucial Step:** On the left-hand menu, click the **+** next to **Services**. Scroll down, select **Gmail API**, and click **Add**. *(If you do not do this, the hard delete function will fail).*
4. Edit the `CONFIG` block at the top of the script to include the specific spam patterns you are targeting.
5. Save the project.

## Automation

To have MailDrop run automatically:
1. Click the **Clock icon** (Triggers) on the left-hand menu.
2. Click **Add Trigger** (bottom right).
3. Set the function to run to `main`.
4. Choose **Time-driven** for the event source.
5. Select an appropriate interval (e.g., an **Hour timer**).

## License

This project is licensed under the [GNU GPLv3 License](LICENSE). 

*Note: This project is a heavily modified fork of the original [Spam Zero](https://github.com/spamzero/spamzero) script, upgraded to utilize REST API functionality and modern parsing techniques.*
