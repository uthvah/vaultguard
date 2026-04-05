/*
 * VaultGuard: The Lockscreen for Obsidian
 * Refactored with best practices and bug fixes
 */

import * as obsidian from 'obsidian';
import { zxcvbn, zxcvbnOptions } from '@zxcvbn-ts/core';
import { dictionary, translations } from '@zxcvbn-ts/language-en';

zxcvbnOptions.setOptions({ dictionary, translations });

// ============================================================================
// CONSTANTS
// ============================================================================

const IV_LENGTH = 12;
const SALT_LENGTH = 16;
const MAGIC_HEADER = "VAULTGUARD_ENCRYPTED_V1::";
const NOTE_PROCESSING_BATCH_SIZE = 20;
const PBKDF2_ITERATIONS = 250000;
const LS_GUARD_KEY_PREFIX = 'locksidian_v1_guard';

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
        fontStyle: 'normal',
        clockFormat: '24h',
        clockStyle: 'digital',
        overlayOpacity: 30,
        widgets: {
            showDate: true,
            showUsername: true,
            clock: true,
        },
        inputRadius: 100,
        shakeIntensity: 6,
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
        true, // extractable: required so computeSentinelHmac can export raw bytes for HMAC
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

    static create(app, title, totalItems) {
        if (totalItems <= 3) return null;
        const m = new ProgressModal(app, title, totalItems);
        m.open();
        return m;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.addClass('vaultguard-progress-modal');

        contentEl.createEl('h2', { text: this.title });

        const svg = contentEl.createSvg('svg', { attr: { viewBox: '0 0 60 60', width: '80', height: '80' } });
        svg.style.display = 'block';
        svg.style.margin = '0 auto 16px';
        svg.createSvg('circle', { attr: { cx: '30', cy: '30', r: '26', fill: 'none',
            stroke: 'var(--background-modifier-border)', 'stroke-width': '5' } });
        this.progressRing = svg.createSvg('circle', { attr: {
            cx: '30', cy: '30', r: '26', fill: 'none',
            stroke: 'var(--interactive-accent)', 'stroke-width': '5',
            'stroke-dasharray': '163.4', 'stroke-dashoffset': '163.4',
            'stroke-linecap': 'round', transform: 'rotate(-90 30 30)'
        } });

        this.statusEl = contentEl.createEl('p', { cls: 'progress-status',
            text: `0 / ${this.totalItems}` });
        this.fileEl = contentEl.createEl('p', { cls: 'progress-details', text: '' });
    }

    updateProgress(processed, failed = 0, currentFile = '') {
        this.processedItems = processed;
        this.failedItems = failed;
        const offset = 163.4 * (1 - processed / this.totalItems);
        this.progressRing.setAttribute('stroke-dashoffset', String(offset));
        this.statusEl.textContent = `${processed} / ${this.totalItems}`;
        if (currentFile) {
            this.fileEl.textContent = currentFile.split('/').pop();
        }
        if (failed > 0) {
            this.progressRing.setAttribute('stroke', 'var(--text-error)');
        }
    }

    complete() {
        if (this.failedItems > 0) {
            this.statusEl.textContent = `${this.failedItems} error(s)`;
            this.statusEl.style.color = 'var(--text-error)';
        } else {
            this.progressRing.setAttribute('stroke', 'var(--text-success)');
            this.statusEl.textContent = 'Done';
        }
        setTimeout(() => this.close(), 800);
    }
}

// ============================================================================
// ANALOGUE CLOCK HELPERS
// ============================================================================

function buildAnalogueClockSVG() {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 200 200');
    svg.setAttribute('class', 'vg-analogue-clock');
    svg.setAttribute('aria-hidden', 'true');

    // Outer ring
    const ring = document.createElementNS(ns, 'circle');
    ring.setAttribute('cx', '100'); ring.setAttribute('cy', '100');
    ring.setAttribute('r', '88');
    ring.setAttribute('fill', 'none');
    ring.setAttribute('stroke', 'rgba(255,255,255,0.30)');
    ring.setAttribute('stroke-width', '1.5');
    svg.appendChild(ring);

    // Hour tick marks — 12 ticks, 4 quarter ticks longer/bolder
    for (let i = 0; i < 12; i++) {
        const isQ = i % 3 === 0;
        const angle = (i * 30) * Math.PI / 180;
        const inner = isQ ? 75 : 80;
        const tick = document.createElementNS(ns, 'line');
        tick.setAttribute('x1', (100 + Math.sin(angle) * inner).toFixed(3));
        tick.setAttribute('y1', (100 - Math.cos(angle) * inner).toFixed(3));
        tick.setAttribute('x2', (100 + Math.sin(angle) * 86).toFixed(3));
        tick.setAttribute('y2', (100 - Math.cos(angle) * 86).toFixed(3));
        tick.setAttribute('stroke', isQ ? 'rgba(255,255,255,0.70)' : 'rgba(255,255,255,0.40)');
        tick.setAttribute('stroke-width', isQ ? '2.5' : '1.5');
        tick.setAttribute('stroke-linecap', 'round');
        svg.appendChild(tick);
    }

    // Hour hand — short and thick
    const hourHand = document.createElementNS(ns, 'line');
    hourHand.setAttribute('x1', '100'); hourHand.setAttribute('y1', '108');
    hourHand.setAttribute('x2', '100'); hourHand.setAttribute('y2', '52');
    hourHand.setAttribute('stroke', 'rgba(255,255,255,0.92)');
    hourHand.setAttribute('stroke-width', '4.5');
    hourHand.setAttribute('stroke-linecap', 'round');
    hourHand.setAttribute('class', 'vg-clock-hour-hand');
    svg.appendChild(hourHand);

    // Minute hand — long and slender
    const minuteHand = document.createElementNS(ns, 'line');
    minuteHand.setAttribute('x1', '100'); minuteHand.setAttribute('y1', '105');
    minuteHand.setAttribute('x2', '100'); minuteHand.setAttribute('y2', '26');
    minuteHand.setAttribute('stroke', 'rgba(255,255,255,0.78)');
    minuteHand.setAttribute('stroke-width', '2.5');
    minuteHand.setAttribute('stroke-linecap', 'round');
    minuteHand.setAttribute('class', 'vg-clock-minute-hand');
    svg.appendChild(minuteHand);

    // Second hand — hair-thin with counterweight tail
    const secondHand = document.createElementNS(ns, 'line');
    secondHand.setAttribute('x1', '100'); secondHand.setAttribute('y1', '118');
    secondHand.setAttribute('x2', '100'); secondHand.setAttribute('y2', '22');
    secondHand.setAttribute('stroke', 'rgba(255,255,255,0.58)');
    secondHand.setAttribute('stroke-width', '1.5');
    secondHand.setAttribute('stroke-linecap', 'round');
    secondHand.setAttribute('class', 'vg-clock-second-hand');
    svg.appendChild(secondHand);

    // Center cap
    const cap = document.createElementNS(ns, 'circle');
    cap.setAttribute('cx', '100'); cap.setAttribute('cy', '100');
    cap.setAttribute('r', '4');
    cap.setAttribute('fill', 'rgba(255,255,255,0.90)');
    svg.appendChild(cap);

    return svg;
}

function updateAnalogueClock(svgEl, dateEl) {
    const now = new Date();
    const h = now.getHours() % 12;
    const m = now.getMinutes();
    const s = now.getSeconds();

    // Smooth continuous motion — each hand interpolates sub-unit
    const hourDeg   = h * 30 + m * 0.5 + s * (0.5 / 60);
    const minuteDeg = m * 6 + s * 0.1;
    const secondDeg = s * 6;

    const hourHand   = svgEl.querySelector('.vg-clock-hour-hand');
    const minuteHand = svgEl.querySelector('.vg-clock-minute-hand');
    const secondHand = svgEl.querySelector('.vg-clock-second-hand');

    if (hourHand)   hourHand.setAttribute('transform',   `rotate(${hourDeg.toFixed(3)}, 100, 100)`);
    if (minuteHand) minuteHand.setAttribute('transform', `rotate(${minuteDeg.toFixed(3)}, 100, 100)`);
    if (secondHand) secondHand.setAttribute('transform', `rotate(${secondDeg.toFixed(3)}, 100, 100)`);

    if (dateEl) {
        dateEl.textContent = now.toLocaleDateString(undefined, {
            weekday: 'long', month: 'long', day: 'numeric'
        });
    }
}

// ============================================================================
// WIDGET REGISTRY
// Each entry: { id, label, alwaysOn, isEnabled(visual)?, render(plugin) }
// - alwaysOn: never filtered by user prefs
// - isEnabled: optional extra gate (e.g. clock respects clockFormat setting)
// - render: returns an HTMLElement; may set plugin.clockInterval etc.
// To add a new widget: push a new descriptor here and add a toggle in settings.
// ============================================================================

const WIDGET_REGISTRY = [
    {
        id: 'clock',
        label: 'Clock',
        alwaysOn: false,
        isEnabled: (visual) => visual.clockFormat !== 'off',
        render(plugin) {
            const visual  = plugin.state.settings.visual;
            const widgets = visual.widgets ?? {};
            const el = document.createElement('div');
            el.className = 'vg-time-widget';

            let dateEl = null;
            if (widgets.showDate !== false) {
                dateEl = document.createElement('div');
                dateEl.className = 'vaultguard-date';
            }

            if (visual.clockStyle === 'analogue') {
                const svg = buildAnalogueClockSVG();
                el.appendChild(svg);
                if (dateEl) el.appendChild(dateEl);
                updateAnalogueClock(svg, dateEl);
                plugin.clockInterval = setInterval(() => updateAnalogueClock(svg, dateEl), 1000);
            } else {
                const clockEl = document.createElement('div');
                clockEl.className = 'vaultguard-clock';
                el.appendChild(clockEl);
                if (dateEl) el.appendChild(dateEl);
                plugin.updateClock(clockEl, dateEl);
                plugin.clockInterval = setInterval(() => plugin.updateClock(clockEl, dateEl), 1000);
            }
            return el;
        }
    },
    {
        id: 'login',
        label: 'Login',
        alwaysOn: true,
        render(plugin) {
            const visual = plugin.state.settings.visual;
            const widgets = visual.widgets ?? {};
            const card = document.createElement('div');
            card.className = 'vg-login-card';
            if (widgets.showUsername !== false) {
                const username = document.createElement('div');
                username.className = 'vaultguard-username';
                username.textContent = visual.username;
                card.appendChild(username);
            }
            card.appendChild(plugin.createPasswordInputElement());
            return card;
        }
    }
];

// ============================================================================
// MAIN PLUGIN CLASS
// ============================================================================

class VaultGuardPlugin extends obsidian.Plugin {
    constructor(app, manifest) {
        super(app, manifest);
        
        // State initialization
        this.state = {
            encryptionKey: null,
            settings: this.deepClone(DEFAULT_SETTINGS),
            phase: 'LOCKED', // 'SETUP' | 'LOCKED' | 'UNLOCKED' | 'PROCESSING' | 'TAMPERED'
            isProcessing: false,
        };

        // UI references
        this.lockScreenEl = null;
        this.idleTimer = null;
        this.clockInterval = null;
        this._focusTrapListener = null;
        
        // Bind methods
        this.resetIdleTimer = this.resetIdleTimer.bind(this);
    }

    get isLocked() {
        return this.state.phase === 'LOCKED' || this.state.phase === 'TAMPERED';
    }

    async onload() {
        
        // Load settings and data
        await this.loadPluginData();
        
        // Show lock screen IMMEDIATELY if locked (before workspace is ready)
        if (this.isLocked) {
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
        if (!this.isLocked) {
            this.resetIdleTimer();
        }
    }

    onunload() {
        this.removeLockScreen();
        clearTimeout(this.idleTimer);
    }

    // ========================================================================
    // DATA PERSISTENCE
    // ========================================================================

    async loadPluginData() {
        const storedData = await this.loadData() || {};

        if (storedData.visualPrefs) {
            this.state.settings.visual = this.mergeDeep(
                DEFAULT_SETTINGS.visual,
                storedData.visualPrefs
            );
        }

        const hasCredentials = !!(storedData?.salt && storedData?.encryptedSettings);
        const guardExists = await this.sentinelExists();
        const lsGuard = this._lsRead();
        const hasLS = !!(lsGuard?.salt);

        if (!hasCredentials && !guardExists && !hasLS) {
            // All three stores empty — genuine fresh install or new vault.
            // Because _lsKey is scoped to this vault's path, a stale entry from
            // any other vault will never appear here, so this check is trustworthy.
            this.state.phase = 'SETUP';

        } else if (!hasCredentials) {
            // At least one external guard survives without credentials — suspicious.
            // (guardExists=true means the sentinel file is present despite data.json
            //  being gone; hasLS=true means this vault's LS record exists without
            //  matching credentials — either way something is wrong.)
            this.state.phase = 'TAMPERED';
            console.warn('VaultGuard: guard(s) present but credentials missing — tamper detected');

        } else {
            // Credentials present — vault has been set up at some point

            // Bootstrap LS if absent (Obsidian reinstall or first run after update)
            // Do not treat absence of LS alone as tamper — it can be wiped by Obsidian reinstall
            if (!hasLS) {
                this._lsWrite(storedData.salt);
            }

            // Only compare salts when LS existed BEFORE this load (hasLS, not just-written)
            const saltMismatch = hasLS && (lsGuard.salt !== storedData.salt);

            if (saltMismatch) {
                // data.json salt differs from trusted LS record — possible swap attack
                this.state.phase = 'TAMPERED';
                console.warn('VaultGuard: salt mismatch between data.json and localStorage — tamper suspected');
            } else if (!guardExists && hasLS) {
                // Sentinel missing but LS proves this device previously completed a successful
                // unlock — the sentinel should still be present. Suspicious.
                this.state.phase = 'TAMPERED';
                console.warn('VaultGuard: sentinel missing on a previously-unlocked device — tamper suspected');
            } else {
                this.state.phase = 'LOCKED';
            }
        }
    }

    // ========================================================================
    // SENTINEL GUARD
    // ========================================================================

    /**
     * A localStorage key scoped to this specific vault path.
     * Using a global key meant any vault on the same machine could pollute
     * another vault's guard record, causing false tamper positives on fresh
     * installs. The vault adapter's basePath (desktop) or vault name (mobile)
     * gives us a stable, vault-unique identifier.
     */
    get _lsKey() {
        const adapter = this.app.vault.adapter;
        const id = (adapter.basePath ?? this.app.vault.getName())
            .replace(/[^a-zA-Z0-9_-]/g, '_')
            .slice(-60);
        return `${LS_GUARD_KEY_PREFIX}_${id}`;
    }

    _lsClear() {
        try {
            window.localStorage.removeItem(this._lsKey);
        } catch (e) {
            console.warn('VaultGuard: localStorage clear failed', e);
        }
    }

    _lsWrite(salt) {
        try {
            window.localStorage.setItem(
                this._lsKey,
                JSON.stringify({ v: 1, salt })
            );
        } catch (e) {
            console.warn('VaultGuard: localStorage write failed', e);
        }
    }

    _lsRead() {
        try {
            const raw = window.localStorage.getItem(this._lsKey);
            return raw ? JSON.parse(raw) : null;
        } catch {
            return null;
        }
    }

    async writeSentinel(key) {
        const hmac = await this.computeSentinelHmac(key);
        const path = `${this.manifest.dir}/locksidian-guard.json`;
        await this.app.vault.adapter.write(path, JSON.stringify({ v: 1, check: hmac }));
    }

    async verifySentinel(key) {
        const path = `${this.manifest.dir}/locksidian-guard.json`;
        try {
            const raw = await this.app.vault.adapter.read(path);
            const { check } = JSON.parse(raw);
            const expected = await this.computeSentinelHmac(key);
            return check === expected;
        } catch {
            return false; // File missing or malformed = tampered
        }
    }

    async computeSentinelHmac(key) {
        const raw = await crypto.subtle.exportKey('raw', key);
        const hmacKey = await crypto.subtle.importKey(
            'raw', raw,
            { name: 'HMAC', hash: 'SHA-256' },
            false, ['sign']
        );
        const sig = await crypto.subtle.sign(
            'HMAC', hmacKey,
            new TextEncoder().encode('locksidian-integrity-v1')
        );
        return bufferToBase64(sig);
    }

    async sentinelExists() {
        const path = `${this.manifest.dir}/locksidian-guard.json`;
        return await this.app.vault.adapter.exists(path);
    }

    async saveSettings() {
        if (this.isLocked) {
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
        if (this.isLocked) {
            return;
        }

        // Encrypt notes if enabled
        if (this.state.settings.encryptNotes && this.state.encryptionKey) {
            const files = this.app.vault.getMarkdownFiles();
            const progressModal = ProgressModal.create(this.app, 'Encrypting Notes', files.length);

            await this.processAllNotes('encrypt', (processed, failed) => {
                if (progressModal) progressModal.updateProgress(processed, failed);
            });

            if (progressModal) progressModal.complete();
        }

        // Clear sensitive state
        this.state.phase = 'LOCKED';
        this.state.encryptionKey = null;
        clearTimeout(this.idleTimer);

        // Show lock screen
        this.showLockScreen();
    }

    async unlock(password, triggerEl) {
        const wasTampered = this.state.phase === 'TAMPERED';
        let stored = await this.loadData() || {};

        // When data.json was deleted (TAMPERED), recover the salt from localStorage.
        // The salt is mirrored there on every successful unlock and on setPassword().
        if (wasTampered && !stored.salt) {
            const lsGuard = this._lsRead();
            if (lsGuard?.salt) {
                stored = { salt: lsGuard.salt }; // encryptedSettings is gone — handled below
            } else {
                console.error('VaultGuard: No salt in data.json or localStorage — cannot recover');
                return false;
            }
        }

        if (!stored.salt) {
            console.error('VaultGuard: No salt found in stored data');
            return false;
        }

        try {
            // Salt-swap check: if localStorage has a trusted salt, data.json must match it.
            // Skip when we already know data.json is absent (we just sourced salt from LS above).
            if (stored.encryptedSettings) {
                const lsGuard = this._lsRead();
                if (lsGuard?.salt && lsGuard.salt !== stored.salt) {
                    throw new Error('Salt mismatch — data.json does not match trusted localStorage record');
                }
            }

            const saltBuf = new Uint8Array(base64ToBuffer(stored.salt));
            const key = await deriveKey(password, saltBuf);

            let decryptedSettings;

            if (stored.encryptedSettings) {
                // Normal path — decrypt settings, then verify sentinel.
                // Sentinel is always checked here, including when wasTampered, because the
                // sentinel is the independent oracle: if data.json was swapped the derived
                // key will not reproduce the stored HMAC and unlock must be refused.
                decryptedSettings = await decryptData(key, stored.encryptedSettings);
                if (!(await this.verifySentinel(key))) {
                    throw new Error('Sentinel verification failed — file missing or key mismatch');
                }
            } else {
                // TAMPERED + data.json deleted — sentinel is the auth oracle.
                // If the derived key produces the correct HMAC, the password is correct.
                if (!(await this.verifySentinel(key))) {
                    throw new Error('Incorrect password — sentinel HMAC did not match');
                }
                // encryptedSettings is unrecoverable. Detect note encryption from file content
                // so we can decrypt notes before rebuilding data.json with the correct setting.
                let notesEncrypted = false;
                const mdFiles = this.app.vault.getMarkdownFiles();
                for (const f of mdFiles.slice(0, 10)) {
                    const c = await this.app.vault.read(f);
                    if (c.startsWith(MAGIC_HEADER)) { notesEncrypted = true; break; }
                }
                decryptedSettings = {
                    encryptNotes: notesEncrypted,
                    autoLockTime: DEFAULT_SETTINGS.autoLockTime
                };
            }

            // Credentials verified. Assign the key (needed for note decryption below)
            // but keep isLocked=true until the screen is actually gone.
            this.state.encryptionKey = key;
            this.state.settings.encryptNotes = !!decryptedSettings.encryptNotes;
            this.state.settings.autoLockTime = decryptedSettings.autoLockTime ?? DEFAULT_SETTINGS.autoLockTime;

            // Write/refresh sentinel on every successful unlock
            await this.writeSentinel(key);

            // Refresh localStorage mirror on every successful unlock
            this._lsWrite(stored.salt);

            // Decrypt notes BEFORE the tampered recovery block: if data.json was deleted and
            // setPassword is called below, it generates a new key that overwrites state.encryptionKey.
            // Notes must be decrypted with the original key while it is still assigned.
            if (this.state.settings.encryptNotes) {
                const files = this.app.vault.getMarkdownFiles();
                const progressModal = ProgressModal.create(this.app, 'Decrypting Notes', files.length);

                await this.processAllNotes('decrypt', (processed, failed) => {
                    if (progressModal) progressModal.updateProgress(processed, failed);
                });

                if (progressModal) progressModal.complete();
            }

            if (wasTampered) {
                if (!stored.encryptedSettings) {
                    // data.json was deleted — rebuild it from scratch with the verified password.
                    // Notes are already decrypted above; setPassword now saves the correct
                    // encryptNotes state and generates a fresh salt for future use.
                    await this.setPassword(password);
                } else {
                    await this.saveData({ ...stored, tamperDetectedAt: null });
                }
                new obsidian.Notice('⚠ Vault tamper detected and resolved. Settings reset to defaults.', 8000);
            }

            // Remove lock screen, then flip state — lock screen gone and unlocked are atomic
            this.removeLockScreen();
            this.state.phase = 'UNLOCKED';

            // Show success feedback and notify
            this.showSuccessFeedback(triggerEl);
            new obsidian.Notice('Vault unlocked!');

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
        const saltB64 = bufferToBase64(salt); // capture before fill(0) zeros the buffer

        await this.saveData({
            salt: saltB64,
            encryptedSettings,
            visualPrefs: this.state.settings.visual
        });

        try { salt.fill(0); } catch (e) {}

        this.state.phase = 'UNLOCKED';
        await this.writeSentinel(key);
        this._lsWrite(saltB64);
        this.resetIdleTimer();
    }

    async changePassword(currentPassword, newPassword) {
        const stored = await this.loadData();

        if (!stored?.salt) {
            return "Password not set.";
        }

        let oldKey;
        try {
            const saltBuf = new Uint8Array(base64ToBuffer(stored.salt));
            oldKey = await deriveKey(currentPassword, saltBuf);
            await decryptData(oldKey, stored.encryptedSettings);

            // If sentinel is present, it must match the current key before we overwrite it
            if (await this.sentinelExists() && !(await this.verifySentinel(oldKey))) {
                return "Vault integrity check failed. Sentinel does not match current password.";
            }
        } catch (err) {
            return "Current password is incorrect.";
        }

        const encryptNotes = this.state.settings.encryptNotes;

        // Decrypt notes with old key before switching
        if (encryptNotes) {
            const files = this.app.vault.getMarkdownFiles();
            const decryptModal = ProgressModal.create(this.app, 'Decrypting Notes', files.length);
            this.state.encryptionKey = oldKey;
            await this.processAllNotes('decrypt', (processed, failed) => {
                if (decryptModal) decryptModal.updateProgress(processed, failed);
            });
            if (decryptModal) decryptModal.close();
        }

        // Set new password (derives new key, writes new sentinel)
        await this.setPassword(newPassword);

        // Re-encrypt notes with new key
        if (encryptNotes) {
            const files = this.app.vault.getMarkdownFiles();
            const encryptModal = ProgressModal.create(this.app, 'Encrypting Notes', files.length);
            await this.processAllNotes('encrypt', (processed, failed) => {
                if (encryptModal) encryptModal.updateProgress(processed, failed);
            });
            if (encryptModal) encryptModal.close();
        }

        return null;
    }

    // ========================================================================
    // NOTE ENCRYPTION/DECRYPTION
    // ========================================================================

    async processAllNotes(mode, progressCallback) {
        this.state.isProcessing = true;
        try {
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
                    } else {
                        processedCount++;
                    }
                });

                if (progressCallback) {
                    progressCallback(processedCount, failedCount);
                }
            }

            if (failedCount > 0) {
                new obsidian.Notice(
                    `VaultGuard: ${failedCount} file(s) failed to ${mode}. Check console for details.`
                );
            }
        } finally {
            this.state.isProcessing = false;
        }
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
    // WINDOW FRAME DETECTION & CONTROLS
    // ========================================================================

    getFrameStyle() {
        // Detected from body classes set by Obsidian at startup — authoritative,
        // unlike app.vault.config which does not expose this in the plugin API.
        //   is-frameless + is-hidden-frameless → 'hidden'  (default)
        //   is-frameless only                  → 'obsidian' (Obsidian custom bar)
        //   neither                            → 'native'   (OS titlebar)
        const body = document.body;
        if (!body.classList.contains('is-frameless')) return 'native';
        if (body.classList.contains('is-hidden-frameless')) return 'hidden';
        return 'obsidian';
    }

    _platform() {
        try { return process.platform; } catch { return 'unknown'; }
    }

    // Show a themed navbar for hidden and obsidian styles — native lets the OS handle it.
    get needsNavbar() {
        return this.getFrameStyle() !== 'native';
    }

    // On non-macOS with hidden or obsidian frame, our navbar covers Electron's own
    // window controls (web content) — render replacements.
    // macOS: traffic lights are native OS overlays above all web content, always visible.
    get needsWindowControls() {
        return this.needsNavbar && this._platform() !== 'darwin';
    }

    createWindowControls() {
        const bar = document.createElement('div');
        bar.className = 'vg-window-controls';

        const buttons = [
            {
                cls: 'vg-wc-min',
                label: 'Minimize',
                svg: '<svg viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"><line x1="1" y1="5" x2="9" y2="5"/></svg>',
                action: 'minimize',
            },
            {
                cls: 'vg-wc-max',
                label: 'Maximize',
                svg: '<svg viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"><rect x="1" y="1" width="8" height="8"/></svg>',
                action: 'maximize',
            },
            {
                cls: 'vg-wc-close',
                label: 'Close',
                svg: '<svg viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"><line x1="1" y1="1" x2="9" y2="9"/><line x1="9" y1="1" x2="1" y2="9"/></svg>',
                action: 'close',
            },
        ];

        for (const { cls, label, svg, action } of buttons) {
            const btn = bar.createEl('button', {
                cls: `vg-wc-btn ${cls}`,
                attr: { 'aria-label': label },
            });
            btn.innerHTML = svg;
            btn.addEventListener('click', () => this._winAction(action));
        }

        return bar;
    }

    _winAction(action) {
        // Path 1: Electron remote module (Obsidian ≤ 0.x / some 1.x builds)
        try {
            const electron = window.require('electron');
            const win = electron.remote?.getCurrentWindow?.();
            if (win) {
                if (action === 'minimize') { win.minimize(); return; }
                if (action === 'maximize') { win.isMaximized() ? win.unmaximize() : win.maximize(); return; }
                if (action === 'close')    { win.close(); return; }
            }
        } catch {}

        // Path 2: Obsidian command fallback (close only)
        if (action === 'close') {
            try { this.app.commands.executeCommandById('app:quit'); } catch {}
        }
    }

    // ========================================================================
    // LOCK SCREEN UI
    // ========================================================================

    showLockScreenImmediately() {
        if (this.lockScreenEl) {
            console.warn('VaultGuard: Lock screen already showing');
            return;
        }

        // Create a minimal lock screen ASAP to hide vault content.
        // Keep it as a plain dark screen — the full UI (including any tamper
        // warning) is rendered in enhanceLockScreen() once the workspace is ready.
        this.lockScreenEl = document.createElement('div');
        this.lockScreenEl.className = 'vaultguard-screen vaultguard-screen-loading';
        this.lockScreenEl.style.opacity = '1';
        this.lockScreenEl.style.backgroundColor = 'var(--background-primary)';

        document.body.appendChild(this.lockScreenEl);
    }

    _buildLockScreenUI(el) {
        // Background and overlay are position:absolute on the screen root so they
        // extend behind the navbar as well as the main content area.
        el.appendChild(this.createBackgroundElement());
        el.appendChild(this.createOverlayElement());
        if (this.needsNavbar) {
            const navbar = el.createDiv({ cls: 'vaultguard-navbar' });
            if (this.needsWindowControls) navbar.appendChild(this.createWindowControls());
        }
        const mainContentEl = el.createDiv({ cls: 'vaultguard-main-content' });
        mainContentEl.appendChild(this.createContentElement());
        setTimeout(() => {
            const input = this.lockScreenEl?.querySelector('.vaultguard-input');
            if (input) {
                input.focus();
            }
        }, 150);
        this._focusTrapListener = (ev) => {
            if (this.lockScreenEl && !this.lockScreenEl.contains(ev.target)) {
                const input = this.lockScreenEl.querySelector('.vaultguard-input');
                input?.focus();
            }
        };
        document.addEventListener('focusin', this._focusTrapListener, true);
    }

    _buildTamperedUI(el) {
        if (this.needsNavbar) {
            const navbar = el.createDiv({ cls: 'vaultguard-navbar' });
            if (this.needsWindowControls) navbar.appendChild(this.createWindowControls());
        }

        const screen = el.createDiv({ cls: 'vaultguard-tamper-screen' });
        const panel  = screen.createDiv({ cls: 'vaultguard-tamper-panel' });

        // ── Header row: icon + heading ────────────────────────────────────────
        const header = panel.createDiv({ cls: 'vaultguard-tamper-panel-header' });
        header.appendChild(this._createWarningIcon());
        header.createEl('span', { cls: 'vaultguard-tamper-panel-title', text: 'Integrity Warning' });

        // ── Body: explanation ─────────────────────────────────────────────────
        panel.createEl('p', {
            cls: 'vaultguard-tamper-panel-message',
            text: 'Plugin data was modified or could not be verified. ' +
                  'Enter your master password to confirm your identity and restore access.'
        });

        // ── Password input ────────────────────────────────────────────────────
        panel.appendChild(this.createPasswordInputElement());

        // Focus the input once the panel is in the DOM
        setTimeout(() => panel.querySelector('.vaultguard-input')?.focus(), 100);

        // Focus trap — keep keyboard inside the lock screen
        this._focusTrapListener = (ev) => {
            if (this.lockScreenEl && !this.lockScreenEl.contains(ev.target)) {
                this.lockScreenEl.querySelector('.vaultguard-input')?.focus();
            }
        };
        document.addEventListener('focusin', this._focusTrapListener, true);
    }

    enhanceLockScreen() {
        if (!this.lockScreenEl) {
            return;
        }
        this.lockScreenEl.classList.remove('vaultguard-screen-loading');
        this.lockScreenEl.style.backgroundColor = '';
        this.lockScreenEl.innerHTML = '';

        if (this.state.phase === 'TAMPERED') {
            // Do not apply user visual preferences — data.json may be absent/compromised.
            // Render a stripped-down panel: warning + password input only.
            this._buildTamperedUI(this.lockScreenEl);
        } else {
            this.lockScreenEl.style.setProperty('--vg-overlay-opacity', ((this.state.settings.visual.overlayOpacity ?? 30) / 100).toString());
            this._buildLockScreenUI(this.lockScreenEl);
        }
    }

    showLockScreen() {
        if (this.lockScreenEl) {
            console.warn('VaultGuard: Lock screen already showing');
            return;
        }
        this.lockScreenEl = document.createElement('div');
        this.lockScreenEl.className = 'vaultguard-screen';
        document.body.appendChild(this.lockScreenEl);

        if (this.state.phase === 'TAMPERED') {
            this._buildTamperedUI(this.lockScreenEl);
        } else {
            this.lockScreenEl.style.setProperty('--vg-overlay-opacity', ((this.state.settings.visual.overlayOpacity ?? 30) / 100).toString());
            this._buildLockScreenUI(this.lockScreenEl);
        }
    }

    removeLockScreen() {
        if (!this.lockScreenEl) {
            return;
        }

        if (this._focusTrapListener) {
            document.removeEventListener('focusin', this._focusTrapListener, true);
            this._focusTrapListener = null;
        }

        this.lockScreenEl.classList.add('is-leaving');

        clearInterval(this.clockInterval);
        this.clockInterval = null;

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

        const visual      = this.state.settings.visual;
        const widgetPrefs = visual.widgets ?? {};

        // CSS custom properties
        content.style.setProperty('--vaultguard-ui-scale', (visual.uiScale / 100).toString());
        content.style.setProperty('--vaultguard-input-width', `${visual.inputWidth}px`);
        content.style.setProperty('--vaultguard-input-radius', String(visual.inputRadius ?? 100));
        content.style.setProperty('--vaultguard-shake-intensity', `${visual.shakeIntensity ?? 6}px`);
        content.style.setProperty('--vaultguard-font-family',
            visual.fontFamily === 'System Default' ? 'inherit' : visual.fontFamily
        );
        content.style.setProperty('--vaultguard-font-weight', visual.fontWeight);
        content.style.setProperty('--vaultguard-font-style', visual.fontStyle);

        // Build enabled widget list from registry
        const enabled = WIDGET_REGISTRY.filter(w =>
            w.alwaysOn ||
            (widgetPrefs[w.id] !== false && (!w.isEnabled || w.isEnabled(visual)))
        );

        // Tiling grid — master-stack layout
        const grid = document.createElement('div');
        grid.className = 'vg-tile-grid';

        if (enabled.length <= 1) {
            // Single widget (clock off): full-width fallback
            grid.classList.add('vg-tile-single');
            const item = document.createElement('div');
            item.className = 'vg-tile-item';
            item.appendChild(enabled[0].render(this));
            grid.appendChild(item);
        } else {
            // First widget → master pane (left); rest → stack pane (right)
            const [master, ...stack] = enabled;

            const masterEl = document.createElement('div');
            masterEl.className = 'vg-tile-master';
            masterEl.appendChild(master.render(this));
            grid.appendChild(masterEl);

            const stackEl = document.createElement('div');
            stackEl.className = 'vg-tile-stack';
            for (const widget of stack) {
                const item = document.createElement('div');
                item.className = 'vg-tile-item';
                item.appendChild(widget.render(this));
                stackEl.appendChild(item);
            }
            grid.appendChild(stackEl);
        }

        content.appendChild(grid);
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
                const password = input.value;

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

        media.onerror = () => {
            const fallback = this.createFallbackBackground();
            media.parentNode?.replaceChild(fallback, media);
        };

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

    updateClock(clockEl, dateEl) {
        const now = new Date();
        const fmt = this.state.settings.visual.clockFormat || '24h';
        if (fmt === 'off') {
            clockEl.style.display = 'none';
            if (dateEl) dateEl.style.display = 'none';
            return;
        }
        if (fmt === '12h') {
            clockEl.textContent = now.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit', hour12: true });
        } else {
            clockEl.textContent = now.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
        }
        if (dateEl) dateEl.textContent = now.toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' });
    }

    _createWarningIcon() {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('width', '18');
        svg.setAttribute('height', '18');
        svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor');
        svg.setAttribute('stroke-width', '2');
        svg.setAttribute('stroke-linecap', 'round');
        svg.setAttribute('stroke-linejoin', 'round');
        svg.classList.add('vaultguard-warning-icon');
        svg.innerHTML = '<polygon points="10.29 3.86 1.82 18 22.18 18 13.71 3.86 10.29 3.86"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>';
        return svg;
    }

    createFallbackBackground() {
        const el = document.createElement('div');
        el.className = 'vaultguard-background-media';
        el.style.background = 'linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%)';
        return el;
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
        if (this.state.isProcessing) return;

        clearTimeout(this.idleTimer);

        const timeoutMinutes = this.state.settings.autoLockTime;

        if (this.isLocked || !timeoutMinutes || timeoutMinutes <= 0) {
            return;
        }

        this.idleTimer = setTimeout(() => {
            if (!this.isLocked) {
                this.lock();
            }
        }, 60000 * timeoutMinutes);
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
        this.didComplete = false;
    }

    onOpen() {
        const { contentEl } = this;
        contentEl.empty();
        contentEl.addClass('vaultguard-add-bg-modal');

        contentEl.createEl('h2', { text: 'Add Background' });
        contentEl.createEl('p', {
            cls: 'vaultguard-modal-desc',
            text: 'Add a background from a web URL, a solid color, or a local file.'
        });

        let type = 'image';
        let textComponent;

        new obsidian.Setting(contentEl)
            .setName('Source type')
            .addDropdown(dd => dd
                .addOption('image', 'Image URL')
                .addOption('video', 'Video URL')
                .addOption('color', 'Solid Color (Hex)')
                .onChange(value => type = value)
            );

        new obsidian.Setting(contentEl)
            .setName('Source value')
            .addText(text => {
                text.setPlaceholder('Enter URL or #hex code...');
                textComponent = text;
            });

        new obsidian.Setting(contentEl)
            .addButton(btn => btn
                .setButtonText('Add Background')
                .setCta()
                .onClick(() => {
                    this.addBackground(type, textComponent.getValue());
                })
            );

        contentEl.createDiv({ cls: 'vaultguard-modal-divider' })
            .createSpan({ text: 'or upload a local file' });

        new obsidian.Setting(contentEl)
            .setDesc('The file will be copied into the plugin folder.')
            .addButton(btn => btn
                .setButtonText('Choose File…')
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
        this.didComplete = true;
        this.close();
    }

    onClose() {
        this.contentEl.empty();
        if (this.didComplete) {
            this.plugin.app.setting.openTabById(this.plugin.manifest.id);
        }
    }
}

// ============================================================================
// SETTINGS TAB
// ============================================================================

class VaultGuardSettingsTab extends obsidian.PluginSettingTab {
    display() {
        const { containerEl } = this;
        containerEl.empty();
        containerEl.addClass('vaultguard-settings');

        if (this.plugin.state.phase === 'SETUP') {
            this.renderSetInitialPassword(containerEl);
        } else if (this.plugin.isLocked) {
            containerEl.createEl('p', { 
                text: 'Unlock your vault to change settings.' 
            });
        } else {
            this.renderFullSettings(containerEl);
        }
    }

    renderSetInitialPassword(containerEl) {
        containerEl.createEl('p', { 
            text: 'Welcome to Vault Guard! Please set a master password to secure your vault.' 
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
        // ACCOUNT SECTION
        // ====================================================================

        containerEl.createEl('h3', { text: 'Account' });

        const cpCard = containerEl.createDiv({ cls: 'vaultguard-cp-card' });
        cpCard.createEl('div', { cls: 'vaultguard-cp-title', text: 'Change Master Password' });
        cpCard.createEl('div', { cls: 'vaultguard-cp-desc', text: 'Enter your current password, then choose a new one.' });

        const cpForm = cpCard.createDiv({ cls: 'vaultguard-cp-form' });

        const currentPassInput = cpForm.createEl('input', {
            cls: 'vaultguard-cp-input',
            attr: { type: 'password', placeholder: 'Current password', autocomplete: 'current-password' }
        });

        const newPassInput = cpForm.createEl('input', {
            cls: 'vaultguard-cp-input',
            attr: { type: 'password', placeholder: 'New password', autocomplete: 'new-password' }
        });

        this.createPasswordStrengthUI({ infoEl: cpForm }, null, newPassInput);

        const confirmButton = cpForm.createEl('button', {
            cls: 'vaultguard-cp-btn',
            text: 'Change Password'
        });

        confirmButton.addEventListener('click', async () => {
            const currentPass = currentPassInput.value;
            const newPass = newPassInput.value;

            if (!currentPass || !newPass) {
                new obsidian.Notice('Please fill out all fields.');
                return;
            }

            if (zxcvbn(newPass).score < 2) {
                new obsidian.Notice('New password is too weak.');
                return;
            }

            confirmButton.disabled = true;
            const error = await this.plugin.changePassword(currentPass, newPass);
            confirmButton.disabled = false;

            if (error) {
                new obsidian.Notice(error);
            } else {
                new obsidian.Notice('Password changed successfully!');
                currentPassInput.value = '';
                newPassInput.value = '';
            }
        });

        // ====================================================================
        // AUTO-LOCK SECTION
        // ====================================================================

        containerEl.createEl('h3', { text: 'Auto-Lock' });

        new obsidian.Setting(containerEl)
            .setName('Lock after inactivity')
            .setDesc('Vault locks automatically after the selected period. Restarts on any input.')
            .addDropdown(d => d
                .addOption('0', 'Off')
                .addOption('1', '1 minute')
                .addOption('5', '5 minutes')
                .addOption('15', '15 minutes')
                .addOption('30', '30 minutes')
                .addOption('60', '1 hour')
                .setValue(String(this.plugin.state.settings.autoLockTime))
                .onChange(async v => {
                    this.plugin.state.settings.autoLockTime = parseInt(v, 10);
                    await this.plugin.saveSettings();
                    this.plugin.resetIdleTimer();
                })
            );

        // ====================================================================
        // LOCKSCREEN SECTION
        // ====================================================================

        containerEl.createEl('h3', { text: 'Lockscreen' });

        new obsidian.Setting(containerEl)
            .setName('Show date')
            .setDesc('Display the date below the clock.')
            .addToggle(t => t
                .setValue(this.plugin.state.settings.visual.widgets?.showDate !== false)
                .onChange(async v => {
                    this.plugin.state.settings.visual.widgets = {
                        ...(this.plugin.state.settings.visual.widgets ?? {}),
                        showDate: v,
                    };
                    await this.plugin.saveSettings();
                })
            );

        new obsidian.Setting(containerEl)
            .setName('Show username')
            .setDesc('Display the username inside the login card.')
            .addToggle(t => t
                .setValue(this.plugin.state.settings.visual.widgets?.showUsername !== false)
                .onChange(async v => {
                    this.plugin.state.settings.visual.widgets = {
                        ...(this.plugin.state.settings.visual.widgets ?? {}),
                        showUsername: v,
                    };
                    await this.plugin.saveSettings();
                })
            );

        new obsidian.Setting(containerEl)
            .setName('Background darkness')
            .setDesc('How much the background is darkened behind the lockscreen (0 = none, 60 = dark).')
            .addSlider(s => s
                .setLimits(0, 60, 1)
                .setValue(this.plugin.state.settings.visual.overlayOpacity ?? 30)
                .setDynamicTooltip()
                .onChange(async v => {
                    this.plugin.state.settings.visual.overlayOpacity = v;
                    await this.plugin.saveSettings();
                })
            );

        new obsidian.Setting(containerEl)
            .setName('Clock')
            .setDesc('Time display format on the lock screen.')
            .addDropdown(d => d
                .addOption('off', 'Off')
                .addOption('24h', '24h')
                .addOption('12h', '12h')
                .setValue(this.plugin.state.settings.visual.clockFormat)
                .onChange(async v => {
                    this.plugin.state.settings.visual.clockFormat = v;
                    await this.plugin.saveSettings();
                })
            );

        new obsidian.Setting(containerEl)
            .setName('Clock style')
            .setDesc('Digital shows a numeric readout. Analogue shows a minimal watch face.')
            .addDropdown(d => d
                .addOption('digital', 'Digital')
                .addOption('analogue', 'Analogue')
                .setValue(this.plugin.state.settings.visual.clockStyle ?? 'digital')
                .onChange(async v => {
                    this.plugin.state.settings.visual.clockStyle = v;
                    await this.plugin.saveSettings();
                })
            );

        new obsidian.Setting(containerEl)
            .setName('Lockscreen font')
            .setDesc('Applies to all text on the lock screen — clock, date, username.')
            .addDropdown(d => d
                .addOption('System Default', 'System Default')
                .addOption('system-ui, sans-serif', 'System UI')
                .addOption('Inter, system-ui, sans-serif', 'Inter')
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

        const fontStyleSetting = new obsidian.Setting(containerEl)
            .setName('Font style');

        fontStyleSetting.controlEl.createEl('span', {
            cls: 'vaultguard-toggle-label',
            text: 'Bold',
        });

        fontStyleSetting.addToggle(t => t
            .setValue(this.plugin.state.settings.visual.fontWeight === 'bold')
            .onChange(async v => {
                this.plugin.state.settings.visual.fontWeight = v ? 'bold' : '500';
                await this.plugin.saveSettings();
            })
        );

        fontStyleSetting.controlEl.createEl('span', {
            cls: 'vaultguard-toggle-label vaultguard-toggle-label--gap',
            text: 'Italic',
        });

        fontStyleSetting.addToggle(t => t
            .setValue(this.plugin.state.settings.visual.fontStyle === 'italic')
            .onChange(async v => {
                this.plugin.state.settings.visual.fontStyle = v ? 'italic' : 'normal';
                await this.plugin.saveSettings();
            })
        );

        // ====================================================================
        // INPUT CUSTOMISATION SECTION
        // ====================================================================

        containerEl.createEl('h3', { text: 'Input Customisation' });

        new obsidian.Setting(containerEl)
            .setName('UI Scale')
            .setDesc('Scales the clock, username, and password input.')
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
            .setDesc('Width of the password entry bar in pixels.')
            .addSlider(s => s
                .setLimits(280, 440, 10)
                .setValue(this.plugin.state.settings.visual.inputWidth)
                .setDynamicTooltip()
                .onChange(async v => {
                    this.plugin.state.settings.visual.inputWidth = v;
                    await this.plugin.saveSettings();
                })
            );

        new obsidian.Setting(containerEl)
            .setName('Bar rounding')
            .setDesc('Shape of the password input. 0 = square, 100 = pill.')
            .addSlider(s => s
                .setLimits(0, 100, 5)
                .setValue(this.plugin.state.settings.visual.inputRadius)
                .setDynamicTooltip()
                .onChange(async v => {
                    this.plugin.state.settings.visual.inputRadius = v;
                    await this.plugin.saveSettings();
                })
            );

        new obsidian.Setting(containerEl)
            .setName('Shake intensity')
            .setDesc('How much the bar shakes on a wrong password. 0 to disable.')
            .addSlider(s => s
                .setLimits(0, 20, 1)
                .setValue(this.plugin.state.settings.visual.shakeIntensity)
                .setDynamicTooltip()
                .onChange(async v => {
                    this.plugin.state.settings.visual.shakeIntensity = v;
                    await this.plugin.saveSettings();
                })
            );

        // ====================================================================
        // BACKGROUND SECTION
        // ====================================================================

        containerEl.createEl('h3', { text: 'Background' });
        this.renderThumbnailGrid(containerEl);

        // ====================================================================
        // NOTE ENCRYPTION SECTION
        // ====================================================================

        containerEl.createEl('h3', { text: 'Note Encryption' });

        if (!this.plugin.state.settings.encryptNotes) {
            new obsidian.Setting(containerEl)
                .setName('Encrypt notes on disk')
                .setDesc(this.createWarningFragment())
                .addToggle(toggle => toggle
                    .setValue(false)
                    .onChange(async value => {
                        this.plugin.state.settings.encryptNotes = value;
                        await this.plugin.saveSettings();
                        new obsidian.Notice('Encryption will activate on next lock.');
                    })
                );
        } else {
            const dangerZone = containerEl.createDiv({ cls: 'vaultguard-danger-zone' });
            dangerZone.createEl('p', {
                text: 'Note encryption is active. Notes are encrypted on lock and decrypted on unlock. Disabling will immediately decrypt all notes.'
            });
            const disableBtn = dangerZone.createEl('button', { text: 'Disable Note Encryption' });
            disableBtn.addEventListener('click', async () => {
                if (confirm('Disable note encryption? This will decrypt all notes now.')) {
                    this.plugin.state.settings.encryptNotes = false;
                    await this.plugin.processAllNotes('decrypt', null);
                    await this.plugin.saveSettings();
                    new obsidian.Notice('Note encryption disabled. All notes decrypted.');
                    this.display();
                }
            });
        }
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
            } else if (bg.type === 'video') {
                const videoSrc = bg.value === 'local'
                    ? this.app.vault.adapter.getResourcePath(`${this.plugin.manifest.dir}/bg.mp4`)
                    : src;
                const vid = item.createEl('video', { cls: 'thumbnail-image' });
                vid.muted = true;
                vid.preload = 'metadata';
                vid.src = videoSrc;
                vid.addEventListener('loadedmetadata', () => { vid.currentTime = 0.001; });
                item.createDiv({ cls: 'thumbnail-icon thumbnail-video-overlay' }).innerHTML =
                    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="20" rx="2.18" ry="2.18"></rect><line x1="7" y1="2" x2="7" y2="22"></line><line x1="17" y1="2" x2="17" y2="22"></line><line x1="2" y1="12" x2="22" y2="12"></line><line x1="2" y1="7" x2="7" y2="7"></line><line x1="2" y1="17" x2="7" y2="17"></line><line x1="17" y1="17" x2="22" y2="17"></line><line x1="17" y1="7" x2="22" y2="7"></line></svg>`;
            } else if (bg.type === 'color') {
                item.style.backgroundColor = bg.value;
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

                if (zxcvbn(val).score < 2) {
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
            if (val) {
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

export default VaultGuardPlugin;
