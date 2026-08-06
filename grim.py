import socket, time

def recv_all(s, timeout=0.5, count=8):
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

def run(actions, host='52.76.96.108', port=9005):
    s=socket.socket(); s.settimeout(0.5); s.connect((host,port))
    time.sleep(0.3)
    print(s.recv(8192).decode(errors='replace'))
    for a in actions:
        s.sendall(a)
        time.sleep(0.15)
        r=recv_all(s)
        print(f"--- sent {a!r} -> got:")
        print(r.decode(errors='replace'))
    s.close()

actions=[
 b"1\n",
 b"HELLO\n",
 b"4\n",
 b"0\n",
 b"0\n",
 b"5\n",
 b"0\n",
]
run(actions)
