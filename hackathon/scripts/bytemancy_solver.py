#!/usr/bin/env python3
"""Auto-solver for picoCTF 'bytemancy' series.

The server repeatedly asks: "Send me the HEX BYTE 0xHH N times, side-by-side,
no space." Many requested bytes are non-printable, so they cannot be typed in a
terminal -- they must be sent as raw bytes over a socket.

Usage:
    python bytemancy_solver.py <host> <port>
"""
import re
import socket
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass


def recv_until(sock, marker: bytes, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])

    sock = socket.create_connection((host, port), timeout=10)
    buf = b""
    rounds = 0
    while True:
        buf += recv_until(sock, b"==> ")
        print(buf.decode("utf-8", "replace"))
        if b"picoCTF{" in buf or b"flag{" in buf.lower():
            break

        m = re.search(rb"0x([0-9A-Fa-f]{2})", buf)
        n = re.search(rb"(\d+)\s+times", buf)
        if not m or not n:
            print("[-] could not parse request")
            break
        bval = int(m.group(1), 16)
        count = int(n.group(1))
        # append newline: the server reads with fgets/scanf-style input
        payload = bytes([bval]) * count + b"\n"
        print(f"[*] round {rounds}: send 0x{m.group(1).decode()} x{count} -> {payload!r}")
        sock.sendall(payload)
        rounds += 1
        buf = b""

    sock.close()


if __name__ == "__main__":
    main()
