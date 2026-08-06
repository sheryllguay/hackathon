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
    s.sendall(b"1\n"); time.sleep(0.08); recv_all(s,0.15,2)
    s.sendall(str(idx).encode()+b"\n"); time.sleep(0.08); recv_all(s,0.15,2)
    s.sendall(str(size).encode()+b"\n"); time.sleep(0.08); recv_all(s,0.15,2)
    s.sendall(data); time.sleep(0.08); return recv_all(s,0.15,2)

def edit(idx, data):
    s.sendall(b"2\n"); time.sleep(0.08); recv_all(s,0.15,2)
    s.sendall(str(idx).encode()+b"\n"); time.sleep(0.08); recv_all(s,0.15,2)
    s.sendall(data); time.sleep(0.08); return recv_all(s,0.15,2)

def read(idx):
    s.sendall(b"4\n"); time.sleep(0.08); recv_all(s,0.15,2)
    s.sendall(str(idx).encode()+b"\n"); time.sleep(0.08); return recv_all(s,0.15,2)

def delete(idx):
    s.sendall(b"3\n"); time.sleep(0.08); recv_all(s,0.15,2)
    s.sendall(str(idx).encode()+b"\n"); time.sleep(0.08); return recv_all(s,0.15,2)

def help():
    s.sendall(b"5\n"); time.sleep(0.08); return recv_all(s)

s=socket.socket(); s.settimeout(0.4); s.connect((host,port)); time.sleep(0.3)
print(s.recv(8192).decode(errors='replace'))
print("HELP:", help())

print("test size limit 0x1000")
print(create(0,0x1000,b"A"*0x100))  # will read 0x1000 bytes though
s.close()
