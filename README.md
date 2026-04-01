# VaultGuard
<p align="center">
<img alt="VaultGuard lockscreen" src="https://github.com/user-attachments/assets/24ad6462-21e5-4b94-b4b5-2c3e9be2df16" />
</p>

<p align="center">
<img alt="Version" src="https://img.shields.io/badge/version-2.1.0-blue.svg?cacheSeconds=2592000" />
<img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg" />
</p>


VaultGuard is a secure, beautiful, and highly customizable lockscreen plugin for Obsidian. It protects your vault from unauthorized access with industry-standard encryption, while offering personalization features to match your unique workflow and style.

This plugin is built with a security-first mindset, ensuring your sensitive notes remain private. It has been hardened for stability and performance, providing a seamless and reliable user experience.

## Features

### Security
- Strong Encryption: Utilizes AES-GCM, an authenticated encryption standard that provides both confidentiality and data integrity.
- Resilient Key Derivation: Implements PBKDF2 with a high iteration count (250,000) and a secure random salt to protect your password against modern brute-force attacks.
- Password Strength Meter: Integrated zxcvbn analysis gives you real-time, intelligent feedback to help you choose a strong and secure password.

### Personalization
- Dynamic Backgrounds: Set a video, image, or solid color as your lockscreen background. Use the defaults, add from a web URL, or upload your own files.
- Personalized Greeting: Display a custom username on the lockscreen with your choice of font, weight (bold), and style (italic).
- UI Scaling & Sizing: Adjust the overall size of lockscreen elements and the width of the password input to perfectly fit your display and preference.

### Functionality
- Optional Full Vault Encryption: For maximum security, enable the option to encrypt every .md file in your vault. Files are decrypted automatically upon unlock.
- Performant Processing: Note encryption/decryption is performed in batches, preventing UI freezes even in vaults with thousands of notes.
- Resilient Operation: A single corrupted note will not halt the entire decryption process, ensuring you can always access the rest of your vault.
- Auto-Lock Timer: Automatically lock your vault after a configurable period of inactivity.

## Installation
## From the Community Plugins Store (Not approved yet)
1. Open Settings in Obsidian.
2. Go to Community Plugins and make sure "Restricted mode" is off.
3. Click Browse and search for "VaultGuard".
4. Click Install, and then click Enable.
5. Open the VaultGuard settings to set your master password!

## Manual Installation
1. Download the latest main.js, manifest.json, and styles.css from the releases page.
2. Download the latest zxcvbn.js and bg.mp4 from the main page.
3. Navigate to your Obsidian vault's plugin folder: <YourVault>/.obsidian/plugins/.
4. Create a new folder named VaultGuard.
5. Place the five downloaded files inside this new folder.
6. In Obsidian, go to Settings -> Community Plugins and enable "VaultGuard".

## Getting Started
- Set Your Password: After installing, go to the VaultGuard settings tab. You will be prompted to create your master password.
- Lock Your Vault:
	- Click the Lock icon in the left ribbon.
	- Use the command palette (Ctrl/Cmd + P) and run "VaultGuard: Lock Vault".
	- Wait for the auto-lock timer to expire (if enabled).
- Customize: Head back to the VaultGuard settings at any time (while unlocked) to change your password, configure the auto-lock timer, and customize your lockscreen.


## ⚠️ CRITICAL: Read Before Enabling Note Encryption

This plugin offers a powerful feature to Encrypt Notes on Disk. Before you enable this, you must understand and accept the following risks:

FORGOTTEN PASSWORDS CANNOT BE RECOVERED.
If you enable note encryption and forget your password, your notes will be PERMANENTLY AND IRREVOCABLY LOST. There is no "Forgot Password" feature. There is no backdoor. We cannot help you recover your files.

ALWAYS BACK UP YOUR VAULT.
This is critical for all users, but it is ESSENTIAL if you enable note encryption. Back up your vault before you enable this feature for the first time, and maintain regular backups. If anything goes wrong (e.g., file corruption, software bug), a backup is your only safeguard.

This feature provides a very high level of security, but it comes with significant personal responsibility. Please proceed with extreme caution.

## Contributing

This plugin is for the community. If you find a bug, have a feature request, or want to contribute to the code, please feel free to open an issue or pull request on the GitHub repository.

## License

This plugin is released under the MIT License. See the LICENSE file for more details.
