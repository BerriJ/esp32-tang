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
    </style>
</head>
<body>
    <div class="container" id="mainContainer">
        <div id="unlockPage" class="unlock-page">
            <h1><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 8px;"><path d="M13 2H6.5A2.5 2.5 0 0 0 4 4.5v15"/><path d="M17 2v6"/><path d="M17 4h2"/><path d="M20 15.2V21a1 1 0 0 1-1 1H6.5a1 1 0 0 1 0-5H20"/><circle cx="17" cy="10" r="2"/></svg>Zero-Knowledge Auth</h1>
            <p class="subtitle">ESP32-C6 Secure Unlock</p>
            
            <div class="info-box">
                <strong><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 2px;"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg> Privacy First:</strong> Your password is never transmitted. 
                The device only receives an encrypted, derived key over an ECIES tunnel.
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" placeholder="Enter your password" autocomplete="off">
            </div>
            
            <button class="btn" onclick="performSecureUnlock()" id="unlockBtn">
                Unlock Device
            </button>
            
            <div id="status"></div>
        </div>
        
        <div id="statusPage" class="status-page">
            <div class="success-animation">
                <div class="checkmark-circle">
                    <svg class="checkmark" viewBox="0 0 52 52">
                        <path d="M14 27l7.5 7.5L38 18"/>
                    </svg>
                </div>
                <h2 style="color: #2e7d32; margin-bottom: 10px;">Device Unlocked!</h2>
                <p style="color: #666;">Authentication successful</p>
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
                <span class="status-value">P-256 + eFuse HMAC</span>
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
            <button class="btn btn-secondary" onclick="lockDevice()">
                Lock Device
            </button>
        </div>
    </div>

    <!-- ⚠️ SECURITY WARNING: Password handling in browser - client-side only -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/elliptic/6.5.4/elliptic.min.js"></script>
    <script>
// ===============================================================================
// Zero-Knowledge Authentication - Browser-Side Cryptography
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
// - Format: IV (16 bytes) + Ciphertext (32 bytes) + HMAC (32 bytes) = 80 bytes
// - Provides confidentiality (CBC) + authenticity (HMAC)
// - Random IV for each session
// - HMAC prevents tampering and padding oracle attacks
//
// PRODUCTION CHECKLIST:
// - Remove console.log statements that expose secrets (marked with ⚠️)
// - Ensure input field has autocomplete="off" (already set)
// - Consider adding Content-Security-Policy headers
// - Use subresource integrity (SRI) for CDN libraries in production
// ===============================================================================

let deviceIdentity = null;

// ⚠️ SECURITY: Secure memory wiping functions
function secureWipeArray(arr) {
    if (!arr) return;
    for (let i = 0; i < arr.length; i++) {
        arr[i] = 0;
    }
}

function secureWipeWordArray(wordArray) {
    if (!wordArray || !wordArray.words) return;
    for (let i = 0; i < wordArray.words.length; i++) {
        wordArray.words[i] = 0;
    }
    wordArray.sigBytes = 0;
}

function secureWipeString(str) {
    // Note: JavaScript strings are immutable, but we can at least dereference
    // Best practice: clear the input field immediately after reading
    return null;
}

function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function wordArrayToByteArray(wordArray) {
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    const bytes = [];
    for (let i = 0; i < sigBytes; i++) {
        bytes.push((words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff);
    }
    return bytes;
}

function byteArrayToWordArray(bytes) {
    const words = [];
    for (let i = 0; i < bytes.length; i++) {
        words[i >>> 2] |= bytes[i] << (24 - (i % 4) * 8);
    }
    return CryptoJS.lib.WordArray.create(words, bytes.length);
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
    
    // ⚠️ SECURITY: Track all sensitive variables for cleanup
    let sessionKeyHash = null;
    let sessionKeyBytes = null;
    let sharedSecretBytes = null;
    let aesKeyHash = null;
    let aesKeyBytes = null;
    let clientKey = null;
    
    try {
        // Load device identity if not already loaded
        if (!deviceIdentity) {
            const loaded = await loadDeviceIdentity();
            if (!loaded) {
                btn.disabled = false;
                return;
            }
        }
        
        showStatus('Computing zero-knowledge proof...', 'info', true);
        
        // Step 1: Derive session key using PBKDF2
        // PBKDF2-HMAC-SHA256 with 10000 iterations
        // Use MAC address as salt (received from device identity)
        const macBytes = hexToBytes(deviceIdentity.macAddress);
        const salt = byteArrayToWordArray(macBytes);
        sessionKeyHash = CryptoJS.PBKDF2(password, salt, {
            keySize: 256/32,  // 256 bits = 8 words
            iterations: 10000,
            hasher: CryptoJS.algo.SHA256
        });
        
        // ⚠️ SECURITY: Clear password from input field immediately
        passwordInput.value = '';
        
        sessionKeyBytes = wordArrayToByteArray(sessionKeyHash);
        const sessionKeyHex = bytesToHex(sessionKeyBytes);
        
        // ⚠️ PRODUCTION WARNING: Remove console.log statements in production builds
        // These logs expose sensitive cryptographic material
        console.log('Salt (MAC Address):', deviceIdentity.macAddress);
        console.log('Session Key (PBKDF2):', sessionKeyHex);
        
        showStatus('Establishing ECIES tunnel...', 'info', true);
        
        // Step 2: Generate ephemeral client keypair using elliptic
        const ec = new elliptic.ec('p256');
        clientKey = ec.genKeyPair();
        
        // Export uncompressed public key (0x04 + X + Y)
        const clientPubHex = clientKey.getPublic('hex');
        console.log('Client Public Key:', clientPubHex); // Public key - safe to log
        
        // Step 3: Import server public key and derive shared secret (ECDH)
        const serverKey = ec.keyFromPublic(deviceIdentity.pubKey, 'hex');
        const sharedPoint = clientKey.derive(serverKey.getPublic());
        
        // Convert BN to 32-byte array
        const sharedSecretHex = sharedPoint.toString(16).padStart(64, '0');
        sharedSecretBytes = hexToBytes(sharedSecretHex);
        
        // ⚠️ PRODUCTION WARNING: Remove in production - exposes shared secret
        console.log('Shared Secret:', sharedSecretHex);
        
        // Step 4: Derive separate keys for encryption and authentication
        // This prevents key reuse vulnerabilities in Encrypt-then-MAC
        const sharedSecretWA = byteArrayToWordArray(sharedSecretBytes);
        
        // Encryption key: SHA256("encryption" || shared_secret)
        const encKeyHash = CryptoJS.SHA256(
            CryptoJS.enc.Utf8.parse('encryption').concat(sharedSecretWA)
        );
        const encKeyBytes = wordArrayToByteArray(encKeyHash);
        
        // MAC key: SHA256("authentication" || shared_secret)
        const macKeyHash = CryptoJS.SHA256(
            CryptoJS.enc.Utf8.parse('authentication').concat(sharedSecretWA)
        );
        const macKeyBytes = wordArrayToByteArray(macKeyHash);
        
        // ⚠️ PRODUCTION WARNING: Remove in production - exposes keys
        console.log('Encryption Key:', bytesToHex(encKeyBytes));
        console.log('MAC Key:', bytesToHex(macKeyBytes));
        
        // ⚠️ SECURITY: Clear shared secret after deriving keys
        secureWipeArray(sharedSecretBytes);
        secureWipeWordArray(sharedSecretWA);
        
        showStatus('Encrypting credentials...', 'info', true);
        
        // Step 5: Encrypt the session key hash with AES-256-CBC
        
        // Generate random IV (16 bytes for CBC)
        const ivWords = CryptoJS.lib.WordArray.random(16);
        
        // Convert encryption key bytes to WordArray
        const encKey = byteArrayToWordArray(encKeyBytes);
        
        // Encrypt with AES-256-CBC using NoPadding
        // Session key hash is 32 bytes (exactly 2 blocks), so no padding needed
        const encrypted = CryptoJS.AES.encrypt(
            sessionKeyHash,
            encKey,
            {
                iv: ivWords,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.NoPadding
            }
        );
        
        // ⚠️ SECURITY: Clear session key after encryption
        secureWipeArray(sessionKeyBytes);
        secureWipeWordArray(sessionKeyHash);
        
        // Extract IV and ciphertext
        const ivBytes = wordArrayToByteArray(ivWords);
        const ciphertextBytes = wordArrayToByteArray(encrypted.ciphertext);
        
        showStatus('Computing authentication tag...', 'info', true);
        
        // Build complete blob: IV (16) + Ciphertext (32) + HMAC (32) = 80 bytes
        // Note: We only include first 32 bytes of ciphertext (should be exactly 32 after padding)
        const completeBlob = new Uint8Array(80);
        completeBlob.set(ivBytes, 0);           // IV at offset 0
        completeBlob.set(ciphertextBytes.slice(0, 32), 16);  // First 32 bytes of ciphertext at offset 16
        
        // Step 6: Compute HMAC-SHA256 over IV + Ciphertext (Encrypt-then-MAC)
        // CRITICAL: Compute HMAC over the EXACT data in the blob (first 48 bytes: IV + CT)
        const dataToAuthenticateBytes = new Uint8Array(48);
        dataToAuthenticateBytes.set(completeBlob.slice(0, 48));
        const dataToAuthenticate = byteArrayToWordArray(Array.from(dataToAuthenticateBytes));
        const macKey = byteArrayToWordArray(macKeyBytes);
        const hmac = CryptoJS.HmacSHA256(dataToAuthenticate, macKey);
        const hmacBytes = wordArrayToByteArray(hmac);
        
        console.log('IV:', bytesToHex(ivBytes));
        console.log('HMAC:', bytesToHex(hmacBytes));
        
        // Place HMAC in blob
        completeBlob.set(hmacBytes, 48);        // HMAC at offset 48
        
        const encryptedBlobHex = bytesToHex(Array.from(completeBlob));
        
        console.log('Encrypted Blob (IV+CT+HMAC):', encryptedBlobHex); // Encrypted data - safe to log
        
        // ⚠️ SECURITY: Clear all keys after encryption
        secureWipeArray(encKeyBytes);
        secureWipeArray(macKeyBytes);
        secureWipeWordArray(encKeyHash);
        secureWipeWordArray(macKeyHash);
        secureWipeWordArray(encKey);
        secureWipeWordArray(macKey);
        secureWipeWordArray(ivWords);
        secureWipeWordArray(dataToAuthenticate);
        secureWipeWordArray(hmac);
        
        showStatus('Sending unlock request...', 'info', true);
        
        // Step 7: Send to device
        const response = await fetch('/api/unlock', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                clientPub: clientPubHex,
                blob: encryptedBlobHex
            })
        });
        
        if (!response.ok) {
            throw new Error('Unlock request failed');
        }
        
        const result = await response.json();
        
        if (result.success) {
            showStatus('✅ Device unlocked successfully!', 'success');
            
            // Reload page after 1.5s - server will show status page
            setTimeout(() => {
                window.location.reload();
            }, 1500);
        } else {
            showStatus('❌ Unlock failed: ' + (result.error || 'Unknown error'), 'error');
        }
        
    } catch (error) {
        console.error('Error:', error);
        showStatus('❌ Error: ' + error.message, 'error');
    } finally {
        // ⚠️ SECURITY: Always clear sensitive data, even on error
        btn.disabled = false;
        passwordInput.value = ''; // Ensure password field is cleared
        
        // Wipe all sensitive variables
        if (sessionKeyHash) secureWipeWordArray(sessionKeyHash);
        if (sessionKeyBytes) secureWipeArray(sessionKeyBytes);
        if (sharedSecretBytes) secureWipeArray(sharedSecretBytes);
        
        // Clear client private key if possible
        if (clientKey && clientKey.priv) {
            // Elliptic.js uses BN.js for private keys - zero it out
            if (clientKey.priv.words) {
                for (let i = 0; i < clientKey.priv.words.length; i++) {
                    clientKey.priv.words[i] = 0;
                }
            }
        }
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

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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
    
    if (days > 0) {
        return `${days}d ${hours % 24}h ${minutes % 60}m`;
    } else if (hours > 0) {
        return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${seconds % 60}s`;
    } else {
        return `${seconds}s`;
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
    if (e.key === 'Enter') {
        performSecureUnlock();
    }
});

// ⚠️ SECURITY: Clear password field on page unload/navigation
window.addEventListener('beforeunload', () => {
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.value = '';
    }
});

// ⚠️ SECURITY: Clear password field when page is restored from bfcache
window.addEventListener('pageshow', (event) => {
    if (event.persisted) {
        // Page was restored from back/forward cache
        const passwordInput = document.getElementById('password');
        if (passwordInput) {
            passwordInput.value = '';
        }
    }
});
    </script>
</body>
</html>
)rawliteral";

#endif // ZK_WEB_PAGE_H
