#ifndef PROVISION_WEB_PAGE_H
#define PROVISION_WEB_PAGE_H

// Embedded web interface for device provisioning

const char PROVISION_WEB_PAGE[] = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ESP32 Provisioning</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
            max-width: 500px;
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
        
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #666;
            font-size: 14px;
        }
        
        .warning-box {
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .warning-box h3 {
            color: #856404;
            margin-bottom: 10px;
            font-size: 18px;
        }
        
        .warning-box ul {
            margin-left: 20px;
            color: #856404;
        }
        
        .warning-box li {
            margin-bottom: 5px;
        }
        
        .info-box {
            background: #e7f3ff;
            border: 2px solid #2196F3;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
        }
        
        .info-box h3 {
            color: #1976D2;
            margin-bottom: 10px;
            font-size: 18px;
        }
        
        .info-box p {
            color: #1565C0;
            line-height: 1.6;
        }
        
        .provision-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 15px;
        }
        
        .provision-btn:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        
        .provision-btn:active:not(:disabled) {
            transform: translateY(0);
        }
        
        .provision-btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        
        .status-message {
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 15px;
            display: none;
            animation: fadeIn 0.3s ease-out;
        }
        
        @keyframes fadeIn {
            from {
                opacity: 0;
            }
            to {
                opacity: 1;
            }
        }
        
        .status-message.success {
            background: #d4edda;
            border: 2px solid #28a745;
            color: #155724;
            display: block;
        }
        
        .status-message.error {
            background: #f8d7da;
            border: 2px solid #dc3545;
            color: #721c24;
            display: block;
        }
        
        .status-message.info {
            background: #d1ecf1;
            border: 2px solid #17a2b8;
            color: #0c5460;
            display: block;
        }
        
        .skip-link {
            text-align: center;
            margin-top: 20px;
        }
        
        .skip-link a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
        }
        
        .skip-link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔧 Device Provisioning Required</h1>
            <p>Your device needs to be provisioned before first use</p>
        </div>
        
        <div class="warning-box">
            <h3>⚠️ Provisioning Needed</h3>
            <ul id="provisionReasons">
                <li>Loading status...</li>
            </ul>
        </div>
        
        <div class="info-box">
            <h3>ℹ️ What This Does</h3>
            <p>
                This will provision your device security hardware:
            </p>
            <ul style="margin-top: 10px; margin-left: 20px; color: #1565C0;">
                <li><strong>ATECC608B:</strong> Write secure configuration (SlotConfig, KeyConfig, ChipOptions) and lock the config zone</li>
                <li><strong>ESP32-C6:</strong> Write hardcoded HMAC key to EFUSE BLOCK_KEY5 with purpose <code>EFUSE_KEY_PURPOSE_HMAC_UP</code></li>
            </ul>
            <p style="margin-top: 10px; font-weight: bold;">
                ⚠️ Warning: These are one-time operations and cannot be undone!
            </p>
        </div>
        
        <div id="statusMessage" class="status-message"></div>
        Device
        <button id="provisionBtn" class="provision-btn" onclick="provisionDevice()">
            Provision EFUSE KEY5
        </button>
        
        <div class="skip-link">
            <a href="/">Skip and continue anyway</a>
        </div>
    </div>
    
    <script>
        // Fetch and display current provisioning status on page load
        async function loadProvisionStatus() {
            const reasonsList = document.getElementById('provisionReasons');
            
            try {
                const response = await fetch('/api/provision/status');
                const status = await response.json();
                
                // Clear loading message
                reasonsList.innerHTML = '';
                
                // Build list of actual conditions
                
                if (status.config_unlocked) {
                    const li = document.createElement('li');
                    li.textContent = 'ATECC608B Config Zone is unlocked';
                    reasonsList.appendChild(li);
                }
                
                if (status.data_unlocked) {
                    const li = document.createElement('li');
                    li.textContent = 'ATECC608B Data Zone is unlocked';
                    reasonsList.appendChild(li);
                }
                
                if (status.key5_unused) {
                    const li = document.createElement('li');
                    li.textContent = 'ESP32-C6 EFUSE BLOCK_KEY5 is not configured';
                    reasonsList.appendChild(li);
                }
                
                // If somehow no conditions are true, show message
                if (!status.needs_provisioning) {
                    reasonsList.innerHTML = '<li>No provisioning needed (you may skip)</li>';
                }
            } catch (error) {
                reasonsList.innerHTML = '<li>Error loading status: ' + error.message + '</li>';
            }
        }
        
        async function provisionDevice() {
            const btn = document.getElementById('provisionBtn');
            const statusMsg = document.getElementById('statusMessage');
            
            // Disable button
            btn.disabled = true;
            btn.textContent = 'Provisioning...';
            
            // Show info messageProvisioning device security hardware
            statusMsg.className = 'status-message info';
            statusMsg.textContent = 'Writing HMAC key to EFUSE BLOCK_KEY5...';
            
            try {
                const response = await fetch('/api/provision', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                const result = await response.json();
                
                if (response.ok && result.success) {
                    statusMsg.className = 'status-message success';
                    statusMsg.textContent = '✓ ' + result.message;
                    btn.textContent = 'Provisioning Complete!';
                    
                    // Redirect to home after 2 seconds
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 2000);
                } else {
                    statusMsg.className = 'status-message error';
                    statusMsg.textContent = '✗ Error: ' + (result.message || 'Unknown error');
                    btn.disabled = false;
                    btn.textContent = 'Retry Provisioning';
                }
            } catch (error) {
                statusMsg.className = 'status-message error';
                statusMsg.textContent = '✗ Connection error: ' + error.message;
                btn.disabled = false;
                btn.textContent = 'Retry Provisioning';
            }
        }
        
        // Load status when page loads
        window.addEventListener('DOMContentLoaded', loadProvisionStatus);
    </script>
</body>
</html>
)rawliteral";

#endif // PROVISION_WEB_PAGE_H
