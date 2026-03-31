#!/usr/bin/env python3
"""Compute SHA-256 CSP hashes for inline <style> and <script> blocks in zk_web_page.h.

Run after changing any inline JS or CSS, then update the CSP header in
main/zk_handlers.h with the printed hashes.
"""

import hashlib, base64, re, sys

SRC = "main/zk_web_page.h"

with open(SRC, "r") as f:
    html = f.read()

def extract_block(tag):
    pattern = rf"<{tag}>(.*?)</{tag}>"
    m = re.search(pattern, html, re.DOTALL)
    if not m:
        sys.exit(f"No <{tag}> block found")
    return m.group(1)

def csp_hash(content):
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "sha256-" + base64.b64encode(digest).decode()

style_hash = csp_hash(extract_block("style"))
script_hash = csp_hash(extract_block("script"))

print(f"Style:  '{style_hash}'")
print(f"Script: '{script_hash}'")
print()
print("Update the CSP header in main/zk_handlers.h with these values:")
print(f"  style-src  '{style_hash}'")
print(f"  script-src '{script_hash}'")
