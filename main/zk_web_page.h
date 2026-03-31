#ifndef ZK_WEB_PAGE_H
#define ZK_WEB_PAGE_H

// Embedded web interface for Zero-Knowledge Authentication
// Includes: HTML, CSS, JavaScript, and crypto libraries (elliptic.js, CryptoJS)

const char ZK_WEB_PAGE[] = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ESP32 Zero-Knowledge Auth</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' width='24' height='24' viewBox='0 0 24 24' fill='none' stroke='%23333' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M13 2H6.5A2.5 2.5 0 0 0 4 4.5v15'/><path d='M17 2v6'/><path d='M17 4h2'/><path d='M20 15.2V21a1 1 0 0 1-1 1H6.5a1 1 0 0 1 0-5H20'/><circle cx='17' cy='10' r='2'/></svg>">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #6b7c7c 0%, #5a7d5a 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 450px;
            width: 100%;
            padding: 40px;
            animation: slideIn 0.5s ease-out;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        
        .subtitle {
            text-align: center;
            color: #666;
            font-size: 14px;
            margin-bottom: 30px;
        }
        
        .info-box {
            background: #f0f5f3;
            border-left: 4px solid #5a7d5a;
            padding: 15px;
            margin-bottom: 25px;
            border-radius: 5px;
            font-size: 13px;
            color: #555;
        }
        
        .info-box strong {
            color: #4a6d4a;
        }
        
        .form-group {
            margin-bottom: 25px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
            font-size: 14px;
        }
        
        input[type="password"],
        input[type="text"] {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e1e8ed;
            border-radius: 10px;
            font-size: 16px;
            transition: all 0.3s ease;
            outline: none;
        }
        
        input:focus {
            border-color: #5a7d5a;
            box-shadow: 0 0 0 3px rgba(90, 125, 90, 0.1);
        }
        
        /* Prevent browser autofill from injecting inline styles */
        input:-webkit-autofill,
        input:-webkit-autofill:hover,
        input:-webkit-autofill:focus {
            -webkit-box-shadow: 0 0 0 1000px white inset;
            box-shadow: 0 0 0 1000px white inset;
            transition: background-color 5000s ease-in-out 0s;
        }
        
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #6b7c7c 0%, #5a7d5a 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            margin-top: 10px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(90, 125, 90, 0.4);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        #status {
            margin-top: 20px;
            padding: 15px;
            border-radius: 10px;
            font-size: 14px;
            text-align: center;
            display: none;
            animation: fadeIn 0.3s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .status-info {
            background: #e3f2fd;
            color: #1976d2;
            border: 1px solid #90caf9;
        }
        
        .status-success {
            background: #e8f5e9;
            color: #2e7d32;
            border: 1px solid #81c784;
        }
        
        .status-error {
            background: #ffebee;
            color: #c62828;
            border: 1px solid #ef5350;
        }
        
        .loader {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #5a7d5a;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-right: 10px;
            vertical-align: middle;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .device-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 12px;
            color: #666;
        }
        
        .device-info .label {
            font-weight: 600;
            color: #333;
            margin-bottom: 5px;
        }
        
        .device-info .value {
            font-family: 'Courier New', monospace;
            background: white;
            padding: 8px;
            border-radius: 4px;
            word-break: break-all;
            font-size: 11px;
        }
        
        .tech-badge {
            display: inline-block;
            background: #e8f5e9;
            color: #2e7d32;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            margin: 2px;
        }
        
        .success-animation {
            text-align: center;
            padding: 40px 20px;
        }
        
        .checkmark-circle {
            width: 120px;
            height: 120px;
            margin: 0 auto 30px;
            border-radius: 50%;
            background: #e8f5e9;
            position: relative;
            animation: scaleIn 0.5s ease-out;
        }
        
        @keyframes scaleIn {
            0% {
                transform: scale(0);
                opacity: 0;
            }
            50% {
                transform: scale(1.1);
            }
            100% {
                transform: scale(1);
                opacity: 1;
            }
        }
        
        .checkmark {
            width: 60px;
            height: 60px;
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
        }
        
        .checkmark path {
            stroke: #2e7d32;
            stroke-width: 4;
            stroke-linecap: round;
            fill: none;
            stroke-dasharray: 100;
            stroke-dashoffset: 100;
            animation: drawCheck 1s ease-out 1s forwards;
        }
        
        @keyframes drawCheck {
            to {
                stroke-dashoffset: 0;
            }
        }
        
        .status-page {
            display: none;
        }
        
        .status-page.active {
            display: block;
            animation: fadeIn 0.5s ease-in;
        }
        
        .unlock-page {
            display: none;
        }
        
        .unlock-page.active {
            display: block;
        }
        
        .status-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        
        .status-card h3 {
            color: #333;
            margin-bottom: 15px;
            font-size: 18px;
        }
        
        .status-item {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #e1e8ed;
        }
        
        .status-item:last-child {
            border-bottom: none;
        }
        
        .status-label {
            color: #666;
            font-size: 14px;
            flex: 0 0 auto;
        }
        
        .status-value {
            color: #333;
            font-weight: 600;
            font-size: 14px;
            text-align: right;
            flex: 1 1 auto;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .badge-success {
            background: #e8f5e9;
            color: #2e7d32;
        }
        
        .btn-secondary {
            background: #e1e8ed;
            color: #333;
        }
        
        .btn-secondary:hover {
            background: #d1d8dd;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
        }
        
        .setup-box {
            background: #fff3e0;
            border-left: 4px solid #e65100;
            padding: 15px;
            margin-bottom: 25px;
            border-radius: 5px;
            font-size: 13px;
            color: #555;
            display: none;
        }
        
        .setup-box strong {
            color: #e65100;
        }
        
        .warning-box {
            background: #fff3e0;
            border-left: 4px solid #e65100;
            padding: 15px;
            margin-bottom: 25px;
            border-radius: 5px;
            font-size: 13px;
            color: #555;
        }
        
        .warning-box strong {
            color: #e65100;
        }

        .icon-lg {
            vertical-align: middle;
            margin-right: 8px;
        }

        .icon-sm {
            vertical-align: middle;
            margin-right: 2px;
        }

        .success-title {
            color: #2e7d32;
            margin-bottom: 10px;
        }

        .success-subtitle {
            color: #666;
        }

        .mb-10 {
            margin-bottom: 10px;
        }

        .mt-10 {
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container" id="mainContainer">
        <div id="unlockPage" class="unlock-page">
            <h1><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon-lg"><path d="M13 2H6.5A2.5 2.5 0 0 0 4 4.5v15"/><path d="M17 2v6"/><path d="M17 4h2"/><path d="M20 15.2V21a1 1 0 0 1-1 1H6.5a1 1 0 0 1 0-5H20"/><circle cx="17" cy="10" r="2"/></svg>Zero-Knowledge Auth</h1>
            <p class="subtitle" id="unlockSubtitle">ESP32-C6 Secure Unlock</p>
            
            <div class="setup-box" id="setupNotice">
                <strong><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon-sm"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> First-Time Setup:</strong> This device has not been initialized yet.
                Choose a strong password to generate the Tang encryption keys. This password will be required to unlock the device on every boot.
            </div>
            
            <div class="info-box">
                <strong><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon-sm"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg> Privacy First:</strong> Your password is never transmitted. 
                The device only receives an encrypted, derived key over an ECIES tunnel.
            </div>
            
            <form id="unlockForm">
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" placeholder="Enter your password" autocomplete="off">
            </div>
            
            <button type="submit" class="btn" id="unlockBtn">
                <span id="unlockBtnText">Unlock Device</span>
            </button>
            </form>
            
            <div id="status"></div>
        </div>
        
        <div id="statusPage" class="status-page">
            <div class="success-animation">
                <div class="checkmark-circle">
                    <svg class="checkmark" viewBox="0 0 52 52">
                        <path d="M14 27l7.5 7.5L38 18"/>
                    </svg>
                </div>
                <h2 class="success-title">Device Unlocked!</h2>
                <p class="success-subtitle">Authentication successful</p>
            </div>
            
            <div class="status-card">
                <h3>Session Information</h3>
                <div class="status-item">
                    <span class="status-label">Status</span>
                    <span class="badge badge-success">Active</span>
                </div>
                <div class="status-item">
                <span class="status-label">Authentication Method</span>
                <span class="status-value">Password</span>
                </div>
                <div class="status-item">
                <span class="status-label">Key Derivation</span>
                <span class="status-value">PBKDF2-SHA256</span>
                </div>
                <div class="status-item">
                <span class="status-label">Encryption</span>
                <span class="status-value">P-256 + TEE + eFuse HMAC</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Authenticated At</span>
                    <span class="status-value" id="authTime">--</span>
                </div>
                <div class="status-item">
                    <span class="status-label">Device Uptime</span>
                    <span class="status-value" id="uptime">--</span>
                </div>
            </div>
            <button class="btn mb-10" id="changePasswordBtn">
                Change Password
            </button>
            <button class="btn mb-10" id="rotateKeysBtn">
                Rotate Keys
            </button>
            <button class="btn btn-secondary" id="lockBtn">
                Lock Device
            </button>
        </div>
        
        <div id="changePasswordPage" class="status-page">
            <h1>Change Password</h1>
            <p class="subtitle">Update password and rotate Tang keys</p>
            
            <div class="warning-box">
                <strong><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon-sm"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> Key Rotation:</strong> Changing the password will generate new Tang encryption keys. Clients bound to the old keys will need to be re-enrolled.
            </div>
            
            <form id="changePasswordForm">
            <div class="form-group">
                <label for="currentPassword">Current Password</label>
                <input type="password" id="currentPassword" placeholder="Enter current password" autocomplete="off">
            </div>
            
            <div class="form-group">
                <label for="newPassword">New Password</label>
                <input type="password" id="newPassword" placeholder="Enter new password" autocomplete="off">
            </div>
            
            <button type="submit" class="btn" id="changeBtn">
                Change Password
            </button>
            </form>
            
            <div id="changeStatus"></div>
            
            <button class="btn btn-secondary mt-10" id="backFromChangeBtn">
                Back
            </button>
        </div>

        <div id="rotatePage" class="status-page">
            <h1>Rotate Keys</h1>
            <p class="subtitle">Advance to next exchange key generation</p>
            
            <div class="info-box">
                <strong><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon-sm"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg> Key Rotation:</strong> This will generate a new exchange key and drop the oldest one. Existing clients using recent keys will continue to work.
            </div>
            
            <form id="rotateForm">
            <div class="form-group">
                <label for="rotatePassword">Password</label>
                <input type="password" id="rotatePassword" placeholder="Enter your password" autocomplete="off">
            </div>
            
            <button type="submit" class="btn" id="rotateBtn">
                Rotate Keys
            </button>
            </form>
            
            <div id="rotateStatus"></div>
            
            <button class="btn btn-secondary mt-10" id="backFromRotateBtn">
                Back
            </button>
        </div>
    </div>

    <!-- All crypto uses the browser's native Web Crypto API (requires HTTPS) -->
    <script>
// ===============================================================================
// Zero-Knowledge Authentication - Browser-Side Cryptography (Web Crypto API)
// ===============================================================================
// SECURITY FEATURES IMPLEMENTED:
// 1. Password is NEVER transmitted - only PBKDF2-derived hash
// 2. Immediate password field clearing after read
// 3. Secure memory wiping of all sensitive variables (keys, secrets, hashes)
// 4. try-finally blocks ensure cleanup even on errors
// 5. Ephemeral ECDH keypair (generated per-session, discarded after)
// 6. All sensitive data cleared before function returns
//
// ENCRYPTION: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
// - Format: IV (16 bytes) + Ciphertext (N bytes) + HMAC (32 bytes)
// - Provides confidentiality (CBC) + authenticity (HMAC)
// - Random IV for each session
// - HMAC prevents tampering and padding oracle attacks
//
// All crypto operations use the native Web Crypto API (crypto.subtle).
// No external libraries required. HTTPS provides the secure context.
// ===============================================================================

let deviceIdentity = null;

function secureWipe(buf) {
    if (!buf) return;
    if (buf instanceof Uint8Array || buf instanceof ArrayBuffer) {
        const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
        for (let i = 0; i < view.length; i++) view[i] = 0;
    }
}

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Concatenate multiple Uint8Arrays
function concat(...arrays) {
    const total = arrays.reduce((sum, a) => sum + a.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) { result.set(a, offset); offset += a.length; }
    return result;
}

async function loadDeviceIdentity() {
    try {
        const response = await fetch('/api/identity');
        if (!response.ok) throw new Error('Failed to fetch device identity');
        deviceIdentity = await response.json();
        console.log('Device Public Key loaded');
        return true;
    } catch (error) {
        console.error('Error loading device identity:', error);
        showStatus('Failed to load device identity', 'error');
        return false;
    }
}

// Derive AES-256-CBC ciphertext + HMAC-SHA256 blob from plaintext bytes.
// Returns { clientPubHex, blobHex }.
async function buildEciesPayload(plaintextBytes) {
    if (!deviceIdentity) {
        const loaded = await loadDeviceIdentity();
        if (!loaded) throw new Error('Failed to load device identity');
    }

    let sharedSecret = null;

    try {
        // Generate ephemeral ECDH keypair (P-256)
        const clientKeyPair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
        );
        const clientPubRaw = new Uint8Array(
            await crypto.subtle.exportKey('raw', clientKeyPair.publicKey)
        );
        const clientPubHex = bytesToHex(clientPubRaw);

        // Import server's public key and derive shared secret
        const serverPubKey = await crypto.subtle.importKey(
            'raw', hexToBytes(deviceIdentity.pubKey),
            { name: 'ECDH', namedCurve: 'P-256' }, false, []
        );
        sharedSecret = new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'ECDH', public: serverPubKey }, clientKeyPair.privateKey, 256
        ));

        // Derive separate encryption and MAC keys: SHA-256("label" || sharedSecret)
        const encLabel = new TextEncoder().encode('encryption');
        const macLabel = new TextEncoder().encode('authentication');
        const encKey = new Uint8Array(await crypto.subtle.digest('SHA-256', concat(encLabel, sharedSecret)));
        const macKey = new Uint8Array(await crypto.subtle.digest('SHA-256', concat(macLabel, sharedSecret)));

        // Clear shared secret after key derivation
        secureWipe(sharedSecret);
        sharedSecret = null;

        // AES-256-CBC encrypt (Web Crypto adds PKCS7 padding; we trim it since plaintext is block-aligned)
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const aesKey = await crypto.subtle.importKey('raw', encKey, 'AES-CBC', false, ['encrypt']);
        const encryptedFull = new Uint8Array(await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv }, aesKey, plaintextBytes
        ));
        // Strip PKCS7 padding block (server expects raw CBC output, no padding)
        const ciphertext = encryptedFull.slice(0, plaintextBytes.length);

        // HMAC-SHA256 over IV + Ciphertext (Encrypt-then-MAC)
        const dataToAuth = concat(iv, ciphertext);
        const hmacKey = await crypto.subtle.importKey(
            'raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        );
        const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, dataToAuth));

        // Build blob: IV(16) + Ciphertext(N) + HMAC(32)
        const blobHex = bytesToHex(concat(iv, ciphertext, hmac));

        // Wipe key material
        secureWipe(encKey);
        secureWipe(macKey);

        return { clientPubHex, blobHex };
    } finally {
        if (sharedSecret) secureWipe(sharedSecret);
    }
}

async function performSecureUnlock() {
    const passwordInput = document.getElementById('password');
    const password = passwordInput.value;

    if (!password) {
        showStatus('Please enter a password', 'error');
        return;
    }

    const btn = document.getElementById('unlockBtn');
    btn.disabled = true;
    showStatus('Initializing secure connection...', 'info', true);

    let sessionKey = null;

    try {
        if (!deviceIdentity) {
            const loaded = await loadDeviceIdentity();
            if (!loaded) { btn.disabled = false; return; }
        }

        showStatus('Computing zero-knowledge proof...', 'info', true);

        // PBKDF2-HMAC-SHA256 with 600000 iterations (OWASP 2023 minimum for SHA-256)
        const saltBytes = hexToBytes(deviceIdentity.salt);
        const passwordKey = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
        );
        // Clear password from input immediately after reading
        passwordInput.value = '';

        sessionKey = new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: saltBytes, iterations: 600000, hash: 'SHA-256' },
            passwordKey, 256
        ));

        showStatus('Establishing ECIES tunnel...', 'info', true);

        const { clientPubHex, blobHex } = await buildEciesPayload(sessionKey);

        // Wipe session key after encryption
        secureWipe(sessionKey);
        sessionKey = null;

        showStatus('Sending unlock request...', 'info', true);

        const response = await fetch('/api/unlock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ clientPub: clientPubHex, blob: blobHex })
        });

        if (!response.ok) throw new Error('Unlock request failed');

        const result = await response.json();

        if (result.success) {
            showStatus('\u2705 Device unlocked successfully!', 'success');
            setTimeout(() => window.location.reload(), 1500);
        } else {
            showStatus('\u274c Unlock failed: ' + (result.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showStatus('\u274c Error: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        passwordInput.value = '';
        if (sessionKey) secureWipe(sessionKey);
    }
}

function showStatus(message, type, showLoader = false) {
    const status = document.getElementById('status');
    status.className = 'status-' + type;
    status.style.display = 'block';
    if (showLoader) {
        status.innerHTML = '<div class="loader"></div>' + message;
    } else {
        status.innerHTML = message;
    }
}

async function lockDevice() {
    await fetch('/api/lock', { method: 'POST' });
    window.location.reload();
}

function formatUptime(milliseconds) {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h ${minutes % 60}m`;
    if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
}

function showChangeStatus(message, type, showLoader = false) {
    const status = document.getElementById('changeStatus');
    status.className = 'status-' + type;
    status.style.display = 'block';
    if (showLoader) {
        status.innerHTML = '<div class="loader"></div>' + message;
    } else {
        status.innerHTML = message;
    }
}

function showChangePasswordPage() {
    document.getElementById('statusPage').classList.remove('active');
    document.getElementById('changePasswordPage').classList.add('active');
    loadDeviceIdentity();
}

function backToStatus() {
    document.getElementById('changePasswordPage').classList.remove('active');
    document.getElementById('currentPassword').value = '';
    document.getElementById('newPassword').value = '';
    document.getElementById('changeStatus').style.display = 'none';
    document.getElementById('statusPage').classList.add('active');
}

function showRotatePage() {
    document.getElementById('statusPage').classList.remove('active');
    document.getElementById('rotatePage').classList.add('active');
    loadDeviceIdentity();
}

function backToStatusFromRotate() {
    document.getElementById('rotatePage').classList.remove('active');
    document.getElementById('rotatePassword').value = '';
    document.getElementById('rotateStatus').style.display = 'none';
    document.getElementById('statusPage').classList.add('active');
}

function showRotateStatus(message, type, showLoader = false) {
    const status = document.getElementById('rotateStatus');
    status.className = 'status-' + type;
    status.style.display = 'block';
    if (showLoader) {
        status.innerHTML = '<div class="loader"></div>' + message;
    } else {
        status.innerHTML = message;
    }
}

async function performRotate() {
    const pwInput = document.getElementById('rotatePassword');
    const pw = pwInput.value;

    if (!pw) {
        showRotateStatus('Please enter your password', 'error');
        return;
    }

    const btn = document.getElementById('rotateBtn');
    btn.disabled = true;
    showRotateStatus('Initializing...', 'info', true);

    let keyHash = null;

    try {
        if (!deviceIdentity) {
            const loaded = await loadDeviceIdentity();
            if (!loaded) { btn.disabled = false; return; }
        }

        showRotateStatus('Deriving key...', 'info', true);

        const saltBytes = hexToBytes(deviceIdentity.salt);
        const passwordKey = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']
        );
        pwInput.value = '';

        keyHash = new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: saltBytes, iterations: 600000, hash: 'SHA-256' },
            passwordKey, 256
        ));

        showRotateStatus('Encrypting...', 'info', true);
        const { clientPubHex, blobHex } = await buildEciesPayload(keyHash);

        showRotateStatus('Sending request...', 'info', true);
        const response = await fetch('/api/rotate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ clientPub: clientPubHex, blob: blobHex })
        });

        const result = await response.json();

        if (result.success) {
            showRotateStatus('Keys rotated successfully! New generation: ' + result.gen, 'success');
            setTimeout(() => backToStatusFromRotate(), 2000);
        } else {
            showRotateStatus('Failed: ' + (result.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showRotateStatus('Error: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        pwInput.value = '';
        if (keyHash) secureWipe(keyHash);
    }
}

async function performPasswordChange() {
    const currentPwInput = document.getElementById('currentPassword');
    const newPwInput = document.getElementById('newPassword');
    const currentPw = currentPwInput.value;
    const newPw = newPwInput.value;

    if (!currentPw || !newPw) {
        showChangeStatus('Please fill in both fields', 'error');
        return;
    }

    const btn = document.getElementById('changeBtn');
    btn.disabled = true;
    showChangeStatus('Initializing...', 'info', true);

    let oldKeyHash = null;
    let newKeyHash = null;

    try {
        if (!deviceIdentity) {
            const loaded = await loadDeviceIdentity();
            if (!loaded) { btn.disabled = false; return; }
        }

        showChangeStatus('Deriving keys...', 'info', true);

        const saltBytes = hexToBytes(deviceIdentity.salt);

        const oldPwKey = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(currentPw), 'PBKDF2', false, ['deriveBits']
        );
        currentPwInput.value = '';

        oldKeyHash = new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: saltBytes, iterations: 600000, hash: 'SHA-256' },
            oldPwKey, 256
        ));

        const newPwKey = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(newPw), 'PBKDF2', false, ['deriveBits']
        );
        newPwInput.value = '';

        newKeyHash = new Uint8Array(await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: saltBytes, iterations: 600000, hash: 'SHA-256' },
            newPwKey, 256
        ));

        // Concatenate: old_hash(32) + new_hash(32) = 64 bytes
        const combined = concat(oldKeyHash, newKeyHash);

        showChangeStatus('Encrypting...', 'info', true);
        const { clientPubHex, blobHex } = await buildEciesPayload(combined);

        secureWipe(combined);

        showChangeStatus('Sending request...', 'info', true);
        const response = await fetch('/api/change-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ clientPub: clientPubHex, blob: blobHex })
        });

        const result = await response.json();

        if (result.success) {
            showChangeStatus('Password changed successfully! Keys have been rotated.', 'success');
            setTimeout(() => backToStatus(), 2000);
        } else {
            showChangeStatus('Failed: ' + (result.error || 'Unknown error'), 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showChangeStatus('Error: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        currentPwInput.value = '';
        newPwInput.value = '';
        if (oldKeyHash) secureWipe(oldKeyHash);
        if (newKeyHash) secureWipe(newKeyHash);
    }
}

// On load: ask server which view to show
window.addEventListener('load', async () => {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        if (data.unlocked) {
            document.getElementById('authTime').textContent = new Date().toLocaleString();
            if (data.uptime !== undefined) {
                document.getElementById('uptime').textContent = formatUptime(data.uptime);
            }
            document.getElementById('statusPage').classList.add('active');
        } else {
            if (data.configured === false) {
                document.getElementById('unlockSubtitle').textContent = 'First-Time Device Setup';
                document.getElementById('setupNotice').style.display = 'block';
                document.getElementById('unlockBtnText').textContent = 'Initialize Device';
                document.getElementById('password').placeholder = 'Choose a password';
            }
            document.getElementById('unlockPage').classList.add('active');
            loadDeviceIdentity();
        }
    } catch (e) {
        document.getElementById('unlockPage').classList.add('active');
        loadDeviceIdentity();
    }
});

// Allow Enter key to submit
document.getElementById('password').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') performSecureUnlock();
});

document.getElementById('currentPassword').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') document.getElementById('newPassword').focus();
});

document.getElementById('newPassword').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') performPasswordChange();
});

document.getElementById('rotatePassword').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') performRotate();
});

window.addEventListener('beforeunload', () => {
    const passwordInput = document.getElementById('password');
    if (passwordInput) passwordInput.value = '';
});

window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
        const passwordInput = document.getElementById('password');
        if (passwordInput) passwordInput.value = '';
    }
});

document.getElementById('unlockForm').addEventListener('submit', (e) => { e.preventDefault(); performSecureUnlock(); });
document.getElementById('changePasswordBtn').addEventListener('click', showChangePasswordPage);
document.getElementById('rotateKeysBtn').addEventListener('click', showRotatePage);
document.getElementById('lockBtn').addEventListener('click', lockDevice);
document.getElementById('changePasswordForm').addEventListener('submit', (e) => { e.preventDefault(); performPasswordChange(); });
document.getElementById('backFromChangeBtn').addEventListener('click', backToStatus);
document.getElementById('rotateForm').addEventListener('submit', (e) => { e.preventDefault(); performRotate(); });
document.getElementById('backFromRotateBtn').addEventListener('click', backToStatusFromRotate);
    </script>
</body>
</html>
)rawliteral";

#endif // ZK_WEB_PAGE_H
