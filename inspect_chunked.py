#!/usr/bin/env python3
import requests
import binascii

HOST = "52.76.96.108"
PORT = 3012
URL = f"http://{HOST}:{PORT}/"

SESSION = requests.Session()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "identity",
    "Connection": "keep-alive",
    "X-Custom-Header": "flag",
}

def fetch(url, extra_headers=None, stream=False):
    h = dict(HEADERS)
    if extra_headers:
        h.update(extra_headers)
    return SESSION.get(url, headers=h, stream=stream, timeout=30, allow_redirects=False)

def dump_headers(resp):
    print("=== STATUS ===")
    print(resp.status_code, resp.reason)
    print("\n=== RESPONSE HEADERS ===")
    for k, v in resp.headers.items():
        print(f"{k}: {v}")
    print("\n=== SET-COOKIES ===")
    for c in resp.cookies:
        print(f"{c.name}={c.value}; domain={c.domain}; path={c.path}")

def dump_body(resp):
    raw = resp.raw.read(decode_content=False) if resp.raw is not None else b""
    print("\n=== RAW BYTES (len=%d) ===" % len(raw))
    print(raw)
    print("\n=== HEX (first 512 bytes) ===")
    print(binascii.hexlify(raw[:512]).decode("ascii", "replace"))
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception as e:
        text = f"<decode error: {e}>"
    print("\n=== TEXT BODY ===")
    print(text)

def main():
    print(f"[+] Target: {URL}\n")
    try:
        r = fetch(URL)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return
    dump_headers(r)
    dump_body(r)

    print("\n[+] Retrying with raw socket to inspect chunk framing ...")
    import socket
    try:
        s = socket.create_connection((HOST, PORT), timeout=10)
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            f"User-Agent: {HEADERS['User-Agent']}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        s.sendall(req)
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        s.close()
        print("=== RAW SOCKET RESPONSE (len=%d) ===" % len(buf))
        print(buf.decode("latin-1", errors="replace"))
    except Exception as e:
        print(f"[!] raw socket failed: {e}")

if __name__ == "__main__":
    main()
