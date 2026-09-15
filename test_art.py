import hashlib
def generateRandomArt(fingerprintBytes):
    width = 17
    height = 9
    grid = [0] * (width * height)
    x = 8
    y = 4
    for b in fingerprintBytes:
        for shift in range(0, 8, 2):
            dir = (b >> shift) & 3
            if (dir & 1) == 0: x = max(0, x - 1)
            else: x = min(width - 1, x + 1)
            if (dir & 2) == 0: y = max(0, y - 1)
            else: y = min(height - 1, y + 1)
            grid[y * width + x] += 1
            
    chars = " .o+=*BOX@%&#/^"
    art = "+---[ECDSA 256]---+\n"
    for row in range(height):
        art += "|"
        for col in range(width):
            if col == 8 and row == 4: art += "S"
            else:
                if col == x and row == y: art += "E"
                else:
                    val = grid[row * width + col]
                    art += chars[min(val, len(chars) - 1)]
        art += "|\n"
    art += "+----[SHA256]-----+"
    return art

h = hashlib.sha256(b"test_fingerprint_generation_for_ssh_random_art").digest()
print(generateRandomArt(h))
