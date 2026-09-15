function generateRandomArt(fingerprintBytes) {
    const width = 17;
    const height = 9;
    const grid = Array(width * height).fill(0);
    
    let x = 8;
    let y = 4;
    
    for (let i = 0; i < fingerprintBytes.length; i++) {
        let b = fingerprintBytes[i];
        for (let shift = 0; shift < 8; shift += 2) {
            const dir = (b >> shift) & 3;
            if ((dir & 1) === 0) x = Math.max(0, x - 1); else x = Math.min(width - 1, x + 1);
            if ((dir & 2) === 0) y = Math.max(0, y - 1); else y = Math.min(height - 1, y + 1);
            grid[y * width + x]++;
        }
    }
    
    const chars = " .o+=*BOX@%&#/^";
    let art = "+---[ECDSA 256]---+\n";
    for (let row = 0; row < height; row++) {
        art += "|";
        for (let col = 0; col < width; col++) {
            if (col === 8 && row === 4) art += "S";
            else if (col === x && row === y) art += "E";
            else {
                const val = grid[row * width + col];
                art += chars[Math.min(val, chars.length - 1)];
            }
        }
        art += "|\n";
    }
    art += "+----[SHA256]-----+";
    return art;
}
const crypto = require('crypto');
const hash = crypto.createHash('sha256').update('test_fingerprint_generation_for_ssh_random_art').digest();
console.log(generateRandomArt(hash));
