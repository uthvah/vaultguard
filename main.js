/*
 * VaultGuard: The Lockscreen for Obsidian
 * Refactored with best practices and bug fixes
 */

const obsidian = require('obsidian');

// ============================================================================
// CONSTANTS
// ============================================================================

const IV_LENGTH = 12;
const SALT_LENGTH = 16;
const MAGIC_HEADER = "VAULTGUARD_ENCRYPTED_V1::";
const NOTE_PROCESSING_BATCH_SIZE = 20;
const PBKDF2_ITERATIONS = 250000;

const DEFAULT_SETTINGS = {
    autoLockTime: 15,
    encryptNotes: false,
    visual: {
        username: 'User',
        activeBackgroundId: 'local-video',
        backgrounds: [
            { id: 'local-video', type: 'video', value: 'local', isDefault: true },
            { id: 'default-color-1', type: 'color', value: '#2c3e50', isDefault: true },
            { id: 'default-image-1', type: 'image', value: 'https://images.unsplash.com/photo-1502790671504-542ad42d5189?w=800', isDefault: true },
        ],
        uiScale: 100,
        inputWidth: 340,
        fontFamily: 'System Default',
        fontWeight: '500',
        fontStyle: 'normal'
    }
};

// ============================================================================
// CRYPTOGRAPHY UTILITIES
// ============================================================================

function bufferToBase64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToBuffer(b64) {
    const binary = window.atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

async function deriveKey(password, salt, iterations = PBKDF2_ITERATIONS) {
    const encoder = new TextEncoder();
    const rawPassword = encoder.encode(password);
    const baseKey = await crypto.subtle.importKey(
        'raw',
        rawPassword,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    const derivedKey = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt,
            iterations,
            hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
    try { rawPassword.fill(0); } catch (e) {}
    return derivedKey;
}

async function encryptData(key, data) {
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const plaintext = encoder.encode(JSON.stringify(data));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        plaintext
    );
    const outputBuffer = new Uint8Array(iv.length + ciphertext.byteLength);
    outputBuffer.set(iv, 0);
    outputBuffer.set(new Uint8Array(ciphertext), iv.length);
    try { plaintext.fill(0); } catch (e) {}
    return bufferToBase64(outputBuffer);
}

async function decryptData(key, b64) {
    const buffer = base64ToBuffer(b64);
    const dataArray = new Uint8Array(buffer);
    const iv = dataArray.slice(0, IV_LENGTH);
    const ciphertext = dataArray.slice(IV_LENGTH);
    try {
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );
        return JSON.parse(new TextDecoder().decode(decryptedBuffer));
    } catch (err) {
        throw new Error('Decryption failed. Invalid password or corrupted data.');
    }
}

// ============================================================================
// PROGRESS MODAL
// ============================================================================

class ProgressModal extends obsidian.Modal {
    constructor(app, title, totalItems) {
        super(app);
        this.title = title;
        this.totalItems = totalItems;
        this.processedItems = 0;
        this.failedItems = 0;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.addClass('vaultguard-progress-modal');
        
        contentEl.createEl('h2', { text: this.title });
        
        this.statusEl = contentEl.createEl('p', { 
            text: `Processing: 0 / ${this.totalItems}`,
            cls: 'progress-status'
        });
        
        this.progressBarWrapper = contentEl.createDiv({ cls: 'progress-bar-wrapper' });
        this.progressBar = this.progressBarWrapper.createDiv({ cls: 'progress-bar' });
        this.progressBar.style.width = '0%';
        
        this.detailsEl = contentEl.createEl('p', { 
            text: '',
            cls: 'progress-details'
        });
    }

    updateProgress(processed, failed = 0) {
        this.processedItems = processed;
        this.failedItems = failed;
        const percentage = Math.round((processed / this.totalItems) * 100);
        
        this.statusEl.textContent = `Processing: ${processed} / ${this.totalItems}`;
        this.progressBar.style.width = `${percentage}%`;
        
        if (failed > 0) {
            this.detailsEl.textContent = `${failed} file(s) failed`;
            this.detailsEl.style.color = 'var(--text-error)';
        }
    }

    complete() {
        if (this.failedItems > 0) {
            this.statusEl.textContent = `Completed with ${this.failedItems} error(s)`;
            this.statusEl.style.color = 'var(--text-error)';
        } else {
            this.statusEl.textContent = 'Completed successfully!';
            this.statusEl.style.color = 'var(--text-success)';
        }
        
        setTimeout(() => this.close(), 500);
    }
}

// ============================================================================
// MAIN PLUGIN CLASS
// ============================================================================

class VaultGuardPlugin extends obsidian.Plugin {
    constructor(app, manifest) {
        super(app, manifest);
        
        // State initialization
        this.state = {
            isLocked: true,
            encryptionKey: null,
            settings: this.deepClone(DEFAULT_SETTINGS)
        };
        
        // UI references
        this.lockScreenEl = null;
        this.idleTimer = null;
        
        // Bind methods
        this.resetIdleTimer = this.resetIdleTimer.bind(this);
        this.handleBeforeUnload = this.handleBeforeUnload.bind(this);
    }

    async onload() {
        console.log('VaultGuard: Loading plugin...');
        
        // Load settings and data
        await this.loadPluginData();
        
        // Show lock screen IMMEDIATELY if locked (before workspace is ready)
        if (this.state.isLocked) {
            // Add lock screen to DOM immediately to hide vault content
            this.showLockScreenImmediately();
            
            // Then enhance it when workspace is ready
            this.app.workspace.onLayoutReady(() => {
                this.enhanceLockScreen();
            });
        }
        
        // Add settings tab
        this.addSettingTab(new VaultGuardSettingsTab(this.app, this));
        
        // Add commands
        this.addCommand({
            id: 'lock-vault',
            name: 'Lock Vault',
            callback: () => this.lock()
        });
        
        // Add ribbon icon
        this.addRibbonIcon("lock", "Lock Vault", () => this.lock());
        
        // Register event listeners
        this.registerDomEvent(document, 'mousemove', this.resetIdleTimer);
        this.registerDomEvent(document, 'keydown', this.resetIdleTimer);
        this.registerDomEvent(document, 'mousedown', this.resetIdleTimer);
        
        // Start idle timer if unlocked
        if (!this.state.isLocked) {
            this.resetIdleTimer();
        }
        
        console.log('VaultGuard: Plugin loaded successfully');
    }

    onunload() {
        console.log('VaultGuard: Unloading plugin...');
        this.removeLockScreen();
        clearTimeout(this.idleTimer);
    }

    // ========================================================================
    // DATA PERSISTENCE
    // ========================================================================

    async loadPluginData() {
        try {
            // Load zxcvbn password strength library from a trusted CDN
            if (!window.zxcvbn) {
                const script = document.createElement('script');
                script.src = 'https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js';
                document.head.appendChild(script);

                // Wait for the script to load before continuing
                            await Promise.race([
                new Promise((resolve, reject) => {
                    script.onload = resolve;
                    script.onerror = reject;
                }),
                new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('timeout')), 5000)
                )
            ]);
                console.log("VaultGuard: zxcvbn.js loaded successfully from CDN.");
            }
        } catch (e) {
            console.warn("VaultGuard: Failed to load zxcvbn.js from CDN. Password strength checking disabled.");
        }

        const storedData = await this.loadData() || {};
        
        // Merge visual preferences
        if (storedData.visualPrefs) {
            this.state.settings.visual = this.mergeDeep(
                DEFAULT_SETTINGS.visual,
                storedData.visualPrefs
            );
        }
        
        // Determine if vault is locked
        this.state.isLocked = !!(storedData?.salt && storedData?.encryptedSettings);
        
        console.log('VaultGuard: Data loaded. Vault locked:', this.state.isLocked);
    }

    async saveSettings() {
        if (this.state.isLocked) {
            console.warn('VaultGuard: Cannot save settings while locked');
            return;
        }

        const storedData = await this.loadData() || {};

        if (!storedData.salt || !this.state.encryptionKey) {
            console.error('VaultGuard: Encryption key not available. Saving visual settings only.');
            await this.saveData({
                ...storedData,
                visualPrefs: this.state.settings.visual
            });
            return;
        }

        const sensitiveSettings = {
            encryptNotes: this.state.settings.encryptNotes,
            autoLockTime: this.state.settings.autoLockTime
        };

        const encryptedSettings = await encryptData(
            this.state.encryptionKey,
            sensitiveSettings
        );

        await this.saveData({
            salt: storedData.salt,
            encryptedSettings,
            visualPrefs: this.state.settings.visual
        });

        this.resetIdleTimer();
    }

    // ========================================================================
    // LOCK/UNLOCK OPERATIONS
    // ========================================================================

    async lock() {
        if (this.state.isLocked) {
            return;
        }

        console.log('VaultGuard: Locking vault...');

        // Encrypt notes if enabled
        if (this.state.settings.encryptNotes && this.state.encryptionKey) {
            const files = this.app.vault.getMarkdownFiles();
            const progressModal = new ProgressModal(
                this.app,
                'Encrypting Notes',
                files.length
            );
            progressModal.open();

            await this.processAllNotes('encrypt', (processed, failed) => {
                progressModal.updateProgress(processed, failed);
            });

            progressModal.complete();
        }

        // Clear sensitive state
        this.state.isLocked = true;
        this.state.encryptionKey = null;
        clearTimeout(this.idleTimer);

        // Show lock screen
        this.showLockScreen();
    }

    async unlock(password, triggerEl) {
        const stored = await this.loadData();
        
        if (!stored?.salt) {
            console.error('VaultGuard: No salt found in stored data');
            return false;
        }

        try {
            const saltBuf = new Uint8Array(base64ToBuffer(stored.salt));
            const key = await deriveKey(password, saltBuf);
            const decryptedSettings = await decryptData(key, stored.encryptedSettings);

            // Show success feedback
            this.showSuccessFeedback(triggerEl);

            // Update state
            this.state.encryptionKey = key;
            this.state.settings.encryptNotes = !!decryptedSettings.encryptNotes;
            this.state.settings.autoLockTime = decryptedSettings.autoLockTime ?? DEFAULT_SETTINGS.autoLockTime;
            this.state.isLocked = false;

            console.log('VaultGuard: Vault unlocked successfully');
            new obsidian.Notice('Vault unlocked!');

            // Decrypt notes if enabled
            if (this.state.settings.encryptNotes) {
                const files = this.app.vault.getMarkdownFiles();
                const progressModal = new ProgressModal(
                    this.app,
                    'Decrypting Notes',
                    files.length
                );
                progressModal.open();

                await this.processAllNotes('decrypt', (processed, failed) => {
                    progressModal.updateProgress(processed, failed);
                });

                progressModal.complete();
            }

            // Remove lock screen
            this.removeLockScreen();

            // Start idle timer
            this.resetIdleTimer();

            return true;
        } catch (err) {
            console.error('VaultGuard Unlock Error:', err.message);
            return false;
        }
    }

    async setPassword(password) {
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
        const key = await deriveKey(password, salt);

        this.state.encryptionKey = key;

        const sensitive = {
            encryptNotes: this.state.settings.encryptNotes,
            autoLockTime: this.state.settings.autoLockTime
        };

        const encryptedSettings = await encryptData(key, sensitive);

        await this.saveData({
            salt: bufferToBase64(salt),
            encryptedSettings,
            visualPrefs: this.state.settings.visual
        });

        try { salt.fill(0); } catch (e) {}

        this.state.isLocked = false;
        this.resetIdleTimer();

        console.log('VaultGuard: Password set successfully');
    }

    async changePassword(currentPassword, newPassword) {
        const stored = await this.loadData();
        
        if (!stored?.salt) {
            return "Password not set.";
        }

        try {
            const saltBuf = new Uint8Array(base64ToBuffer(stored.salt));
            const key = await deriveKey(currentPassword, saltBuf);
            await decryptData(key, stored.encryptedSettings);

            // Current password is correct, set new password
            await this.setPassword(newPassword);
            return null;
        } catch (err) {
            return "Current password is incorrect.";
        }
    }

    // ========================================================================
    // NOTE ENCRYPTION/DECRYPTION
    // ========================================================================

    async processAllNotes(mode, progressCallback) {
        const files = this.app.vault.getMarkdownFiles();
        let processedCount = 0;
        let failedCount = 0;

        for (let i = 0; i < files.length; i += NOTE_PROCESSING_BATCH_SIZE) {
            const batch = files.slice(i, i + NOTE_PROCESSING_BATCH_SIZE);
            const operations = batch.map(file => 
                mode === 'encrypt' ? this.encryptNote(file) : this.decryptNote(file)
            );

            const results = await Promise.allSettled(operations);
            
            results.forEach((result, index) => {
                if (result.status === 'rejected') {
                    failedCount++;
                    console.error(
                        `VaultGuard: Note "${batch[index].path}" failed to ${mode}:`,
                        result.reason
                    );
                }
            });

            processedCount += batch.length;
            
            if (progressCallback) {
                progressCallback(processedCount, failedCount);
            }
        }

        if (failedCount > 0) {
            new obsidian.Notice(
                `VaultGuard: ${failedCount} file(s) failed to ${mode}. Check console for details.`
            );
        }

        console.log(`VaultGuard: ${mode} completed. Processed: ${processedCount}, Failed: ${failedCount}`);
    }

    async encryptNote(file) {
        const content = await this.app.vault.read(file);
        
        // Skip if already encrypted
        if (content.startsWith(MAGIC_HEADER)) {
            return;
        }

        if (!this.state.encryptionKey) {
            throw new Error("Encryption key not available.");
        }

        const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this.state.encryptionKey,
            new TextEncoder().encode(content)
        );

        const outputBuffer = new Uint8Array(iv.length + ciphertext.byteLength);
        outputBuffer.set(iv, 0);
        outputBuffer.set(new Uint8Array(ciphertext), iv.length);

        const payload = MAGIC_HEADER + bufferToBase64(outputBuffer);
        await this.app.vault.modify(file, payload);
    }

    async decryptNote(file) {
        const content = await this.app.vault.read(file);
        
        // Skip if not encrypted
        if (!content.startsWith(MAGIC_HEADER)) {
            return;
        }

        if (!this.state.encryptionKey) {
            throw new Error("Decryption key not available.");
        }

        const bytes = base64ToBuffer(content.substring(MAGIC_HEADER.length));
        const arr = new Uint8Array(bytes);
        const iv = arr.slice(0, IV_LENGTH);
        const ciphertext = arr.slice(IV_LENGTH);

        const plainBuf = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this.state.encryptionKey,
            ciphertext
        );

        const decoded = new TextDecoder().decode(plainBuf);
        await this.app.vault.modify(file, decoded);
    }

    // ========================================================================
    // LOCK SCREEN UI
    // ========================================================================

    showLockScreenImmediately() {
        if (this.lockScreenEl) {
            console.warn('VaultGuard: Lock screen already showing');
            return;
        }

        console.log('VaultGuard: Showing lock screen immediately');

        // Create a minimal lock screen ASAP to hide vault content
        this.lockScreenEl = document.createElement('div');
        this.lockScreenEl.className = 'vaultguard-screen vaultguard-screen-loading';
        this.lockScreenEl.style.opacity = '1';
        
        // Simple background while loading
        this.lockScreenEl.style.backgroundColor = 'var(--background-primary)';
        
        document.body.appendChild(this.lockScreenEl);
    }

    enhanceLockScreen() {
        if (!this.lockScreenEl) {
            return;
        }

        console.log('VaultGuard: Enhancing lock screen');

        // Remove loading class and rebuild with full UI
        this.lockScreenEl.classList.remove('vaultguard-screen-loading');
        this.lockScreenEl.style.backgroundColor = '';
        this.lockScreenEl.innerHTML = '';

        // Create titlebar for dragging
        this.lockScreenEl.createDiv({ cls: 'vaultguard-titlebar' });

        // Create main content area
        const mainContentEl = this.lockScreenEl.createDiv({ 
            cls: 'vaultguard-main-content' 
        });

        // Add background
        mainContentEl.appendChild(this.createBackgroundElement());

        // Add overlay
        mainContentEl.appendChild(this.createOverlayElement());

        // Add content (username + password)
        mainContentEl.appendChild(this.createContentElement());

        // Focus input after a short delay to ensure rendering is complete
        setTimeout(() => {
            const input = this.lockScreenEl?.querySelector('.vaultguard-input');
            if (input) {
                input.focus();
            }
        }, 150);
    }

    showLockScreen() {
        if (this.lockScreenEl) {
            console.warn('VaultGuard: Lock screen already showing');
            return;
        }

        console.log('VaultGuard: Showing lock screen');

        // Create lock screen container
        this.lockScreenEl = document.createElement('div');
        this.lockScreenEl.className = 'vaultguard-screen';

        // Create titlebar for dragging
        this.lockScreenEl.createDiv({ cls: 'vaultguard-titlebar' });

        // Create main content area
        const mainContentEl = this.lockScreenEl.createDiv({ 
            cls: 'vaultguard-main-content' 
        });

        // Add background
        mainContentEl.appendChild(this.createBackgroundElement());

        // Add overlay
        mainContentEl.appendChild(this.createOverlayElement());

        // Add content (username + password)
        mainContentEl.appendChild(this.createContentElement());

        // Append to body
        document.body.appendChild(this.lockScreenEl);

        // Focus input after a short delay to ensure rendering is complete
        setTimeout(() => {
            const input = this.lockScreenEl?.querySelector('.vaultguard-input');
            if (input) {
                input.focus();
            }
        }, 150);
    }

   removeLockScreen() {
    if (!this.lockScreenEl) {
         console.log('VaultGuard: lockScreenEl is null, returning early');
        return;
    }
    console.log('VaultGuard: lockScreenEl at remove time:', this.lockScreenEl === document.querySelector('.vaultguard-screen'));
    console.log('VaultGuard: Removing lock screen');
    this.lockScreenEl.classList.add('is-leaving');

    const el = this.lockScreenEl;
    this.lockScreenEl = null;

    const cleanup = () => {
        if (el && el.parentNode) {
            el.remove();
        }
    };

    el.addEventListener('animationend', cleanup, { once: true });
    setTimeout(cleanup, 500);
}

    createContentElement() {
        const content = document.createElement('div');
        content.className = 'vaultguard-content';

        const visual = this.state.settings.visual;

        // Apply CSS custom properties
        content.style.setProperty('--vaultguard-ui-scale', (visual.uiScale / 100).toString());
        content.style.setProperty('--vaultguard-input-width', `${visual.inputWidth}px`);

        // Username display
        const username = content.createEl('div', { cls: 'vaultguard-username' });
        username.textContent = visual.username;
        username.style.setProperty('--vaultguard-font-family', 
            visual.fontFamily === 'System Default' ? 'inherit' : visual.fontFamily
        );
        username.style.setProperty('--vaultguard-font-weight', visual.fontWeight);
        username.style.setProperty('--vaultguard-font-style', visual.fontStyle);

        // Password input
        content.appendChild(this.createPasswordInputElement());

        return content;
    }

    createPasswordInputElement() {
        const wrapper = document.createElement('div');
        wrapper.className = 'vaultguard-password-wrapper';

        const input = document.createElement('input');
        input.className = 'vaultguard-input';
        input.type = 'password';
        input.placeholder = 'Password';

        input.addEventListener('keydown', async (ev) => {
            if (ev.key === 'Enter') {
                ev.preventDefault();
                const password = input.value.trim();
                
                if (!password) {
                    return;
                }

                const isSuccess = await this.unlock(password, input);
                
                if (!isSuccess) {
                    this.showInvalidCredentialsMessage(input);
                }
            }
        });

        wrapper.appendChild(input);
        return wrapper;
    }

    createBackgroundElement() {
        const activeId = this.state.settings.visual.activeBackgroundId;
        const bg = this.state.settings.visual.backgrounds.find(b => b.id === activeId) 
                   || this.state.settings.visual.backgrounds[0];

        if (!bg) {
            return document.createElement('div');
        }

        const { value, type } = bg;

        // Solid color background
        if (type === 'color') {
            const el = document.createElement('div');
            el.className = 'vaultguard-background-media';
            el.style.backgroundColor = value;
            return el;
        }

        // Image or video background
        const media = document.createElement(type === 'video' ? 'video' : 'img');
        media.className = 'vaultguard-background-media';

        if (type === 'video') {
            Object.assign(media, {
                loop: true,
                muted: true,
                autoplay: true,
                playsInline: true
            });
        }

        // Set source
        if (value === 'local') {
            const extension = type === 'video' ? 'mp4' : 'jpg';
            media.src = this.app.vault.adapter.getResourcePath(
                `${this.manifest.dir}/bg.${extension}`
            );
        } else if (value && value.startsWith('http')) {
            media.src = value;
        } else {
            media.src = this.app.vault.adapter.getResourcePath(value);
        }

        return media;
    }

    createOverlayElement() {
        const overlay = document.createElement('div');
        overlay.className = 'vaultguard-overlay';
        return overlay;
    }

    // ========================================================================
    // UI FEEDBACK
    // ========================================================================

    showSuccessFeedback(el) {
        el.classList.add('is-success');
        setTimeout(() => el.classList.remove('is-success'), 1000);
    }

    showInvalidCredentialsMessage(input) {
        const wrap = input.parentElement;
        wrap.classList.add('is-error');
        input.classList.add('is-error');
        input.value = '';
        
        setTimeout(() => {
            wrap.classList.remove('is-error');
            input.classList.remove('is-error');
            input.focus();
        }, 500);
    }

    // ========================================================================
    // IDLE TIMER
    // ========================================================================

    resetIdleTimer() {
        clearTimeout(this.idleTimer);

        const timeoutMinutes = this.state.settings.autoLockTime;

        if (this.state.isLocked || !timeoutMinutes || timeoutMinutes <= 0) {
            return;
        }

        this.idleTimer = setTimeout(() => {
            new obsidian.Notice('Vault locked due to inactivity.');
            this.lock();
        }, 60000 * timeoutMinutes);
    }

    handleBeforeUnload(event) {
        if (this.state.settings.encryptNotes && !this.state.isLocked) {
            event.preventDefault();
            event.returnValue = 'Your notes are not encrypted. Are you sure you want to close?';
            return event.returnValue;
        }
    }

    // ========================================================================
    // UTILITIES
    // ========================================================================

    deepClone(obj) {
        return JSON.parse(JSON.stringify(obj));
    }

    mergeDeep(target, source) {
        const output = { ...target };
        
        if (target && typeof target === 'object' && source && typeof source === 'object') {
            Object.keys(source).forEach(key => {
                if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                    output[key] = this.mergeDeep(target[key] || {}, source[key]);
                } else {
                    output[key] = source[key];
                }
            });
        }
        
        return output;
    }
}

// ============================================================================
// ADD BACKGROUND MODAL
// ============================================================================

class AddBackgroundModal extends obsidian.Modal {
    constructor(app, plugin) {
        super(app);
        this.plugin = plugin;
    }

    onOpen() {
        this.contentEl.empty();
        this.contentEl.createEl('h2', { text: 'Add New Background' });
        this.contentEl.createEl('p', { 
            text: 'Add a background from a web URL, a solid color, or a local file.' 
        });

        let type = 'image';
        let textComponent;

        new obsidian.Setting(this.contentEl)
            .setName('Source Type')
            .addDropdown(dd => dd
                .addOption('image', 'Image URL')
                .addOption('video', 'Video URL')
                .addOption('color', 'Solid Color (Hex)')
                .onChange(value => type = value)
            );

        new obsidian.Setting(this.contentEl)
            .setName('Source Value')
            .addText(text => {
                text.setPlaceholder('Enter URL or #hex code...');
                textComponent = text;
            });

        new obsidian.Setting(this.contentEl)
            .addButton(btn => btn
                .setButtonText('Add from Source')
                .setCta()
                .onClick(() => {
                    this.addBackground(type, textComponent.getValue());
                })
            );

        this.contentEl.createEl('h4', { text: 'Or Upload a Local File' });
        
        new obsidian.Setting(this.contentEl)
            .setDesc('The file will be copied into the plugin folder.')
            .addButton(btn => btn
                .setButtonText('Choose File...')
                .onClick(() => {
                    const input = document.createElement('input');
                    input.type = 'file';
                    input.accept = 'image/*,video/*';
                    input.onchange = async (ev) => {
                        const file = ev.target.files?.[0];
                        if (file) {
                            await this.handleLocalFile(file);
                        }
                    };
                    input.click();
                })
            );
    }

    async handleLocalFile(file) {
        const targetDir = `${this.plugin.manifest.dir}/backgrounds`;
        
        if (!await this.app.vault.adapter.exists(targetDir)) {
            await this.app.vault.adapter.mkdir(targetDir);
        }

        const ext = file.name.split('.').pop();
        const name = `user-bg-${Date.now()}.${ext}`;
        const path = `${targetDir}/${name}`;

        await this.app.vault.adapter.writeBinary(path, await file.arrayBuffer());

        const type = file.type.startsWith('video') ? 'video' : 'image';
        this.addBackground(type, path);
    }

    async addBackground(type, value) {
        if (!value) {
            new obsidian.Notice('Source value cannot be empty.');
            return;
        }

        const id = `user-${Date.now()}`;
        this.plugin.state.settings.visual.backgrounds.push({
            id,
            type,
            value,
            isDefault: false
        });

        this.plugin.state.settings.visual.activeBackgroundId = id;
        await this.plugin.saveSettings();
        this.close();
    }

    onClose() {
        this.contentEl.empty();
        this.plugin.app.setting.openTabById(this.plugin.manifest.id);
    }
}

// ============================================================================
// SETTINGS TAB
// ============================================================================

class VaultGuardSettingsTab extends obsidian.PluginSettingTab {
    async display() {
        const { containerEl } = this;
        containerEl.empty();
        containerEl.createEl('h2', { text: 'VaultGuard Settings' });

        const storedData = await this.plugin.loadData();

        if (!storedData?.salt) {
            this.renderSetInitialPassword(containerEl);
        } else if (this.plugin.state.isLocked) {
            containerEl.createEl('p', { 
                text: 'Unlock your vault to change settings.' 
            });
        } else {
            this.renderFullSettings(containerEl);
        }
    }

    renderSetInitialPassword(containerEl) {
        containerEl.createEl('p', { 
            text: 'Welcome to VaultGuard! Please set a master password to secure your vault.' 
        });

        const setting = new obsidian.Setting(containerEl)
            .setName('Set Master Password');

        this.createPasswordStrengthUI(setting, async (newPass) => {
            await this.plugin.setPassword(newPass);
            new obsidian.Notice('Password set successfully!');
            this.display();
        });
    }

    renderFullSettings(containerEl) {
        // ====================================================================
        // SECURITY SECTION
        // ====================================================================
        
        containerEl.createEl('h3', { text: 'Security' });

        const changePasswordSetting = new obsidian.Setting(containerEl)
            .setName('Change Master Password')
            .setDesc('You must provide your current password to set a new one.');

        const currentPassInput = changePasswordSetting.controlEl.createEl('input', {
            attr: {
                type: 'password',
                placeholder: 'Current password',
                style: 'margin-right: 5px;'
            }
        });

        const newPassInput = changePasswordSetting.controlEl.createEl('input', {
            attr: {
                type: 'password',
                placeholder: 'New password',
                style: 'margin-right: 5px;'
            }
        });

        const confirmButton = changePasswordSetting.controlEl.createEl('button', {
            text: 'Change'
        });

        this.createPasswordStrengthUI(changePasswordSetting, null, newPassInput);

        confirmButton.addEventListener('click', async () => {
            const currentPass = currentPassInput.value;
            const newPass = newPassInput.value;

            if (!currentPass || !newPass) {
                new obsidian.Notice('Please fill out all fields.');
                return;
            }

            if (window.zxcvbn && zxcvbn(newPass).score < 2) {
                new obsidian.Notice('New password is too weak.');
                return;
            }

            const error = await this.plugin.changePassword(currentPass, newPass);

            if (error) {
                new obsidian.Notice(error);
            } else {
                new obsidian.Notice('Password changed successfully!');
                currentPassInput.value = '';
                newPassInput.value = '';
            }
        });

        // ====================================================================
        // GENERAL SECTION
        // ====================================================================
        
        containerEl.createEl('h3', { text: 'General' });

        new obsidian.Setting(containerEl)
            .setName('Auto-lock timer')
            .setDesc('Lock the vault after a period of inactivity. Set to 0 to disable.')
            .addText(text => text
                .setPlaceholder('minutes')
                .setValue(String(this.plugin.state.settings.autoLockTime))
                .onChange(async value => {
                    const parsed = parseInt(value, 10);
                    this.plugin.state.settings.autoLockTime = isNaN(parsed) ? 0 : parsed;
                    await this.plugin.saveSettings();
                })
            );

        // ====================================================================
        // VAULT ENCRYPTION SECTION
        // ====================================================================
        
        containerEl.createEl('h3', { text: 'Vault Encryption' });

        new obsidian.Setting(containerEl)
            .setName('Encrypt notes on disk')
            .setDesc(this.createWarningFragment())
            .addToggle(toggle => toggle
                .setValue(this.plugin.state.settings.encryptNotes)
                .onChange(async value => {
                    this.plugin.state.settings.encryptNotes = value;
                    await this.plugin.saveSettings();
                    new obsidian.Notice(
                        `Note encryption will be ${value ? 'ENABLED' : 'DISABLED'} on the next lock event.`
                    );
                })
            );

        // ====================================================================
        // APPEARANCE SECTION
        // ====================================================================
        
        containerEl.createEl('h3', { text: 'Appearance' });

        new obsidian.Setting(containerEl)
            .setName('Username')
            .setDesc('Display name shown on the lock screen.')
            .addText(text => text
                .setValue(this.plugin.state.settings.visual.username)
                .onChange(async value => {
                    this.plugin.state.settings.visual.username = value;
                    await this.plugin.saveSettings();
                })
            );

        new obsidian.Setting(containerEl)
            .setName('Font Family')
            .setDesc('Font for the username on the lock screen.')
            .addDropdown(d => d
                .addOption('System Default', 'System Default')
                .addOption('Arial, sans-serif', 'Arial')
                .addOption('Georgia, serif', 'Georgia')
                .addOption('Verdana, sans-serif', 'Verdana')
                .addOption('Courier New, monospace', 'Courier New')
                .setValue(this.plugin.state.settings.visual.fontFamily)
                .onChange(async v => {
                    this.plugin.state.settings.visual.fontFamily = v;
                    await this.plugin.saveSettings();
                })
            );

        const fontStyleSetting = new obsidian.Setting(containerEl)
            .setName('Font Style');

        fontStyleSetting.controlEl.createEl('span', {
            text: 'Bold',
            attr: { 'style': 'margin-right: 5px;' }
        });

        fontStyleSetting.addToggle(t => t
            .setValue(this.plugin.state.settings.visual.fontWeight === 'bold')
            .onChange(async v => {
                this.plugin.state.settings.visual.fontWeight = v ? 'bold' : '500';
                await this.plugin.saveSettings();
            })
        );

        fontStyleSetting.controlEl.createEl('span', {
            text: 'Italic',
            attr: { 'style': 'margin-left: 20px; margin-right: 5px;' }
        });

        fontStyleSetting.addToggle(t => t
            .setValue(this.plugin.state.settings.visual.fontStyle === 'italic')
            .onChange(async v => {
                this.plugin.state.settings.visual.fontStyle = v ? 'italic' : 'normal';
                await this.plugin.saveSettings();
            })
        );

        new obsidian.Setting(containerEl)
            .setName('UI Scale')
            .setDesc('Adjust the size of the username and password input.')
            .addSlider(s => s
                .setLimits(75, 150, 5)
                .setValue(this.plugin.state.settings.visual.uiScale)
                .setDynamicTooltip()
                .onChange(async v => {
                    this.plugin.state.settings.visual.uiScale = v;
                    await this.plugin.saveSettings();
                })
            );

        new obsidian.Setting(containerEl)
            .setName('Input Width')
            .setDesc('Adjust the width of the password input.')
            .addSlider(s => s
                .setLimits(280, 440, 10)
                .setValue(this.plugin.state.settings.visual.inputWidth)
                .setDynamicTooltip()
                .onChange(async v => {
                    this.plugin.state.settings.visual.inputWidth = v;
                    await this.plugin.saveSettings();
                })
            );

        // ====================================================================
        // BACKGROUND SECTION
        // ====================================================================
        
        containerEl.createEl('h4', { text: 'Lockscreen Background' });
        this.renderThumbnailGrid(containerEl);
    }

    renderThumbnailGrid(containerEl) {
        const grid = containerEl.createDiv({ cls: 'vaultguard-thumbnail-grid' });

        this.plugin.state.settings.visual.backgrounds.forEach(bg => {
            const item = grid.createDiv({ cls: 'vaultguard-thumbnail-item' });

            if (bg.id === this.plugin.state.settings.visual.activeBackgroundId) {
                item.addClass('is-active');
            }

            const src = (bg.value && bg.value.startsWith('http')) || bg.type === 'color'
                ? bg.value
                : this.app.vault.adapter.getResourcePath(bg.value);

            if (bg.type === 'image') {
                item.createEl('img', {
                    cls: 'thumbnail-image',
                    attr: { src }
                });
            } else {
                const iconContainer = item.createDiv({ cls: 'thumbnail-icon' });

                if (bg.type === 'video') {
                    iconContainer.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="2.18" ry="2.18"></rect><line x1="7" y1="2" x2="7" y2="22"></line><line x1="17" y1="2" x2="17" y2="22"></line><line x1="2" y1="12" x2="22" y2="12"></line><line x1="2" y1="7" x2="7" y2="7"></line><line x1="2" y1="17" x2="7" y2="17"></line><line x1="17" y1="17" x2="22" y2="17"></line><line x1="17" y1="7" x2="22" y2="7"></line></svg>`;
                } else if (bg.type === 'color') {
                    iconContainer.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2.69l5.66 5.66a8 8 0 1 1-11.31 0z"></path></svg>`;
                    iconContainer.style.backgroundColor = bg.value;
                }
            }

            item.addEventListener('click', async () => {
                this.plugin.state.settings.visual.activeBackgroundId = bg.id;
                await this.plugin.saveSettings();
                this.display();
            });

            if (!bg.isDefault) {
                const deleteBtn = item.createEl('button', { cls: 'delete-btn' });
                deleteBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`;

                deleteBtn.addEventListener('click', async ev => {
                    ev.stopPropagation();

                    if (confirm('Are you sure you want to delete this background?')) {
                        if (bg.value && !bg.value.startsWith('http') && bg.type !== 'color') {
                            await this.app.vault.adapter.remove(bg.value)
                                .catch(e => console.error('VaultGuard: Failed to delete background file', e));
                        }

                        this.plugin.state.settings.visual.backgrounds = 
                            this.plugin.state.settings.visual.backgrounds.filter(b => b.id !== bg.id);

                        if (this.plugin.state.settings.visual.activeBackgroundId === bg.id) {
                            this.plugin.state.settings.visual.activeBackgroundId = 'local-video';
                        }

                        await this.plugin.saveSettings();
                        this.display();
                    }
                });
            }
        });

        const addBtn = grid.createDiv({ cls: 'vaultguard-thumbnail-item add-new-btn' });
        addBtn.createDiv({ cls: 'thumbnail-icon' }).innerHTML = 
            `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>`;

        addBtn.addEventListener('click', () => {
            new AddBackgroundModal(this.app, this.plugin).open();
        });
    }

    createWarningFragment() {
        const frag = document.createDocumentFragment();
        frag.append('When enabled, all .md files will be encrypted on manual lock and decrypted on unlock. ');

        const strong = document.createElement('strong');
        strong.textContent = 'WARNING: This is an irreversible action. Always back up your vault before enabling.';
        strong.style.color = 'var(--text-error)';
        frag.appendChild(strong);

        return frag;
    }

    createPasswordStrengthUI(setting, onSetCallback, inputEl = null) {
        const input = inputEl || setting.controlEl.createEl('input', {
            attr: {
                type: 'password',
                placeholder: 'Enter password'
            }
        });

        if (!inputEl) {
            const btn = setting.controlEl.createEl('button', { text: 'Set Password' });
            btn.addEventListener('click', async () => {
                const val = input.value;

                if (!val) {
                    new obsidian.Notice('Password cannot be empty.');
                    return;
                }

                if (window.zxcvbn && zxcvbn(val).score < 2) {
                    new obsidian.Notice('Password is too weak.');
                    return;
                }

                await onSetCallback(val);
                input.value = '';
            });
        }

        const container = document.createElement('div');
        container.className = 'password-strength-container';
        container.style.display = 'none';
        setting.infoEl.appendChild(container);

        const barWrap = document.createElement('div');
        barWrap.className = 'password-strength-bar-wrapper';
        container.appendChild(barWrap);

        const bar = document.createElement('div');
        bar.className = 'password-strength-bar';
        barWrap.appendChild(bar);

        const text = document.createElement('div');
        text.className = 'password-strength-text';
        container.appendChild(text);

        input.addEventListener('input', () => {
            const val = input.value;

            if (window.zxcvbn && val) {
                container.style.display = '';
                const res = zxcvbn(val);
                bar.className = 'password-strength-bar strength-' + res.score;
                text.textContent = res.feedback.warning || ' ';
            } else {
                container.style.display = 'none';
            }
        });
    }
}

module.exports = VaultGuardPlugin;