#ifndef WIFI_PROV_PAGE_H
#define WIFI_PROV_PAGE_H

const char WIFI_PROV_PAGE[] = R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ESP-Tang Setup</title>
    <link rel="icon" href="data:,">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
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
        }
        h1 { text-align: center; color: #333; margin-bottom: 10px; font-size: 28px; }
        .subtitle { text-align: center; color: #666; font-size: 14px; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 6px; font-weight: 600; color: #333; font-size: 14px; }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s;
            background: #fafafa;
        }
        input:focus { outline: none; border-color: #5a7d5a; background: white; }
        .hint { font-size: 12px; color: #888; margin-top: 4px; }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #5a7d5a, #4a6d4a);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 10px;
            transition: opacity 0.3s;
        }
        button:hover { opacity: 0.9; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        .status {
            text-align: center;
            margin-top: 16px;
            padding: 12px;
            border-radius: 10px;
            font-size: 14px;
            display: none;
        }
        .status.error { display: block; background: #fee; color: #c00; border: 1px solid #fcc; }
        .status.success { display: block; background: #efe; color: #060; border: 1px solid #cec; }
    </style>
</head>
<body>
    <div class="container">
        <h1>ESP-Tang Setup</h1>
        <p class="subtitle">Configure WiFi and device hostname</p>
        <form id="f">
            <div class="form-group">
                <label for="ssid">WiFi Network (SSID)</label>
                <input type="text" id="ssid" required maxlength="32" autocomplete="off">
            </div>
            <div class="form-group">
                <label for="password">WiFi Password</label>
                <input type="password" id="password" maxlength="64">
            </div>
            <div class="form-group">
                <label for="hostname">Device Hostname</label>
                <input type="text" id="hostname" maxlength="63" value="esp-tang"
                       pattern="[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?"
                       title="Letters, numbers and hyphens only">
                <div class="hint">Used for network discovery (e.g. https://<span id="hostname-preview">esp-tang</span>.local)</div>
            </div>
            <button type="submit" id="btn">Save &amp; Connect</button>
        </form>
        <div id="status" class="status"></div>
    </div>
    <script>
    document.getElementById('hostname').addEventListener('input', function() {
        document.getElementById('hostname-preview').textContent = this.value.trim() || 'esp-tang';
    });
    document.getElementById('f').addEventListener('submit', async function(e) {
        e.preventDefault();
        var btn = document.getElementById('btn');
        var st = document.getElementById('status');
        btn.disabled = true;
        btn.textContent = 'Saving...';
        st.className = 'status';
        st.style.display = 'none';
        var ssid = document.getElementById('ssid').value.trim();
        var password = document.getElementById('password').value;
        var hostname = document.getElementById('hostname').value.trim() || 'esp-tang';
        if (!ssid) {
            st.textContent = 'SSID is required';
            st.className = 'status error';
            btn.disabled = false;
            btn.textContent = 'Save & Connect';
            return;
        }
        try {
            var resp = await fetch('/api/configure', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ssid: ssid, password: password, hostname: hostname})
            });
            var data = await resp.json();
            if (data.success) {
                st.textContent = 'Configuration saved! Rebooting...';
                st.className = 'status success';
            } else {
                st.textContent = data.message || 'Failed to save';
                st.className = 'status error';
                btn.disabled = false;
                btn.textContent = 'Save & Connect';
            }
        } catch (err) {
            st.textContent = 'Connection error';
            st.className = 'status error';
            btn.disabled = false;
            btn.textContent = 'Save & Connect';
        }
    });
    </script>
</body>
</html>
)rawliteral";

#endif // WIFI_PROV_PAGE_H
