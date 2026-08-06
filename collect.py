import socket, time

HOST="52.76.96.108"; PORT=9004
def hexd(b): return ' '.join(f'{x:02x}' for x in b)
hello=bytes([0x52,0x45,0x4C,0x59,0x01,0x00,0x00,0xA6])
collected=[]
for i in range(10):
    try:
        s=socket.socket(); s.settimeout(6); s.connect((HOST,PORT))
        s.sendall(hello); time.sleep(0.4)
        r=s.recv(4096); s.close()
        if len(r)>=16 and r[0:4]==b"RELY":
            op=r[4]; ln=(r[5]<<8)|r[6]; chk=r[7]; pay=r[8:8+ln]
            collected.append((chk,pay))
    except Exception as e:
        pass

for chk,pay in collected:
    print(f"chk=0x{chk:02x} pay={hexd(pay)}")

print(f"\ncollected {len(collected)} frames")

# Now validate payload functions across these SAME-header frames
def f_wsum_end(p):
    L=len(p); return sum(p[i]*(L-i) for i in range(L))&0xFF
def f_fletcher_b(p):
    a=0;b=0
    for x in p: a=(a+x)&0xFF; b=(b+a)&0xFF
    return b

val_wse = set((chk - f_wsum_end(pay))&0xFF for chk,pay in collected)
val_fl  = set((chk - f_fletcher_b(pay))&0xFF for chk,pay in collected)
print("wsum_end constant across HELLO-resp frames:", val_wse)
print("fletcher_b constant across HELLO-resp frames:", val_fl)