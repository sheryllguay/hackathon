#!/usr/bin/env python3
import requests
import sys

TARGET = "http://52.76.96.108:3012"
FLAG_PREFIX = "UCSI26{"
TIMEOUT = 15

PATHS = [
    "/egg", "/EGG", "/Egg", "/flag", "/api", "/robots.txt",
    "/.git", "/.git/HEAD", "/admin", "/secret", "/index.php",
    "/index.html", "/hint", "/source", "/src", "/login",
    "/static", "/status", "/health", "/debug", "/config",
    "/egg/", "/flag.txt", "/answer", "/egg.html", "/egg.txt",
]

HEADER_SETS = [
    {},
    {"User-Agent": "EGG"},
    {"User-Agent": "egg"},
    {"X-Egg": "true"},
    {"Egg": "true"},
    {"Egg": "EGG"},
    {"Accept": "application/json"},
    {"Accept": "text/plain"},
    {"Accept": "*/*"},
    {"X-Flag": "true"},
    {"X-Debug": "true"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"Referer": "http://52.76.96.108:3012/egg"},
    {"User-Agent": "EGG", "X-Egg": "true"},
    {"User-Agent": "EGG", "Accept": "application/json"},
]

SESSION = requests.Session()


def report(label, resp):
    raw = b""
    try:
        raw = resp.raw.read(decode_content=False)
    except Exception:
        pass
    text = resp.text if resp.text else ""
    clen = len(raw) if raw else len(resp.content)
    has_flag = FLAG_PREFIX in text or FLAG_PREFIX in resp.text
    interesting = clen > 0 or has_flag
    marker = " <<< FLAG" if has_flag else (" <<< BODY" if clen > 0 else "")
    print(f"[{label}] {resp.status_code} len={clen}{marker}")
    if interesting:
        print("  HEADERS:")
        for k, v in resp.headers.items():
            print(f"    {k}: {v}")
        print("  BODY (raw, first 1000):")
        print("    " + (raw[:1000].decode("latin-1", "replace") if raw else text[:1000]))
        if has_flag:
            idx = text.find(FLAG_PREFIX)
            end = text.find("}", idx) + 1
            print(f"  >>> EXTRACTED: {text[idx:end]}")
    return interesting


def fuzz_paths():
    print("=" * 60)
    print("[1] PATH FUZZING")
    print("=" * 60)
    hits = 0
    for path in PATHS:
        url = TARGET + path
        for hdr in HEADER_SETS[:3]:
            try:
                r = SESSION.get(url, headers=hdr, timeout=TIMEOUT, allow_redirects=False)
                if report(f"GET {path} | hdrs={list(hdr.keys()) or 'none'}", r):
                    hits += 1
            except requests.RequestException as e:
                print(f"[GET {path}] ERR {e}")
    print(f"\n[paths] {hits} interesting response(s)\n")


def fuzz_headers():
    print("=" * 60)
    print("[2] HEADER FUZZING on / and /egg")
    print("=" * 60)
    hits = 0
    for path in ["/", "/egg"]:
        for hdr in HEADER_SETS:
            label = f"GET {path} | " + (",".join(f"{k}={v}" for k, v in hdr.items()) or "default")
            try:
                r = SESSION.get(TARGET + path, headers=hdr, timeout=TIMEOUT, allow_redirects=False)
                if report(label, r):
                    hits += 1
            except requests.RequestException as e:
                print(f"[{label}] ERR {e}")
    print(f"\n[headers] {hits} interesting response(s)\n")


def fuzz_methods():
    print("=" * 60)
    print("[3] METHOD FUZZING on / and /egg")
    print("=" * 60)
    for path in ["/", "/egg", "/flag"]:
        for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]:
            try:
                r = SESSION.request(method, TARGET + path, timeout=TIMEOUT, allow_redirects=False)
                report(f"{method} {path}", r)
            except requests.RequestException as e:
                print(f"[{method} {path}] ERR {e}")


def raw_socket_check():
    print("=" * 60)
    print("[4] RAW SOCKET - check for hidden chunked body")
    print("=" * 60)
    import socket
    for path in ["/", "/egg", "/flag", "/EGG"]:
        try:
            s = socket.create_connection(("52.76.96.108", 3012), timeout=15)
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: 52.76.96.108:3012\r\n"
                f"User-Agent: EGG\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            s.sendall(req)
            buf = b""
            s.settimeout(10)
            try:
                while True:
                    c = s.recv(4096)
                    if not c:
                        break
                    buf += c
            except socket.timeout:
                pass
            s.close()
            text = buf.decode("latin-1", "replace")
            has_flag = FLAG_PREFIX in text
            body_len = len(buf) - (buf.find(b"\r\n\r\n") + 4 if b"\r\n\r\n" in buf else 0)
            print(f"[raw {path}] total={len(buf)} body={body_len} flag={has_flag}")
            if has_flag or body_len > 2:
                print("  RAW:")
                print("  " + text)
        except Exception as e:
            print(f"[raw {path}] ERR {e}")


if __name__ == "__main__":
    print(f"Target: {TARGET} | Flag prefix: {FLAG_PREFIX}\n")
    fuzz_paths()
    fuzz_headers()
    fuzz_methods()
    raw_socket_check()
    print("\nDone.")
