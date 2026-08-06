import socket, time, binascii, sys

host = "52.76.96.108"
port = 9004
N = 12

HELLO = bytes([0x52,0x45,0x4C,0x59, 0x01, 0x00,0x00, 0xA6])

def recv_frame(sock, timeout=5):
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < 8:
        c = sock.recv(8 - len(buf))
        if not c: break
        buf += c
    if len(buf) < 8: return None
    op = buf[4]; length = int.from_bytes(buf[5:7],"big"); cksum = buf[7]
    payload = b""
    while len(payload) < length:
        c = sock.recv(length - len(payload))
        if not c: break
        payload += c
    return buf+payload, cksum, op, payload

samples = []  # (data_bytes, cksum)
ack_payloads = []
for i in range(N):
    try:
        s = socket.create_connection((host,port), timeout=8)
        s.sendall(HELLO)
        time.sleep(0.3)
        r = recv_frame(s, 4)
        if r is None:
            print(i, "no frame")
            s.close(); continue
        data, cksum, op, payload = r
        print(i, "cksum=%#04x op=%#04x len=%d" % (cksum, op, len(payload)),
              "hdr+payload:", binascii.hexlify(data).decode())
        samples.append((data, cksum))
        if op == 0x81:
            ack_payloads.append(payload)
        s.close()
    except Exception as e:
        print(i, "err", e)
    time.sleep(0.1)

# save
import json
with open("relay_samples.json","w") as f:
    json.dump([{"d":d.hex(),"c":c} for d,c in samples], f)
print("saved", len(samples), "samples")