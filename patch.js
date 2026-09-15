    const fingerprintBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', signingKeyBytes));
    const base64String = btoa(String.fromCharCode(...fingerprintBytes)).replace(/=+$/, '');
    const fingerprintText = 'SHA256:' + base64String;
    
    const width = 17, height = 9;
    const grid = Array(width * height).fill(0);
    let fx = 8, fy = 4;
    for (let i = 0; i < fingerprintBytes.length; i++) {
        let b = fingerprintBytes[i];
        for (let shift = 0; shift < 8; shift += 2) {
            const dir = (b >> shift) & 3;
            if ((dir & 1) === 0) fx = Math.max(0, fx - 1); else fx = Math.min(width - 1, fx + 1);
            if ((dir & 2) === 0) fy = Math.max(0, fy - 1); else fy = Math.min(height - 1, fy + 1);
            grid[fy * width + fx]++;
        }
    }
    const chars = " .o+=*BOX@%&#/^";
    let art = "+---[ECDSA 256]---+\\n";
    for (let row = 0; row < height; row++) {
        art += "|";
        for (let col = 0; col < width; col++) {
            if (col === fx && row === fy) art += "E";
            else if (col === 8 && row === 4) art += "S";
            else art += chars[Math.min(grid[row * width + col], chars.length - 1)];
        }
        art += "|\\n";
    }
    art += "+----[SHA256]-----+";
    
    const notices = document.querySelectorAll('.security-notice');
    notices.forEach(notice => {
        const svgIcon = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon-sm"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
        if (isFirstTrust) {
            notice.innerHTML = `<strong>${svgIcon} First Trust:</strong> Server identity pinned. Fingerprint:<br><div class="randomart-container"><span class="fingerprint-val fingerprint-block">${fingerprintText}</span><br><pre class="randomart">${art}</pre></div>This key is now saved in your browser (localStorage).`;
        } else {
            notice.innerHTML = `<strong>${svgIcon} Identity Verified:</strong> Device identity matched pinned key. Fingerprint:<br><div class="randomart-container"><span class="fingerprint-val fingerprint-block">${fingerprintText}</span><br><pre class="randomart">${art}</pre></div>`;
        }
        notice.style.display = 'block';
    });
}
