from pwn import *
import struct, sys
context.log_level='error'
HOST='52.76.96.108'; PORT=9005

def log(*a):
    print(*a, file=sys.stderr, flush=True)

def create(p, idx, size, data, t=3):
    p.sendlineafter(b'> ', b'1', timeout=t); log('c1')
    p.sendlineafter(b'index: ', str(idx).encode(), timeout=t); log('c2')
    p.sendlineafter(b'size: ', str(size).encode(), timeout=t); log('c3')
    p.sendlineafter(b'data: ', data, timeout=t); log('c4')
    p.recvuntil(b'> ', timeout=t); log('c5')

p=remote(HOST,PORT); log('conn')
p.recvuntil(b'> '); log('banner')
create(p,0,0x80,b'A'*0x80)
print("done create0 OK")
