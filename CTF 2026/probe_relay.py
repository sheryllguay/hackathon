import socket, sys, time, binascii

host = sys.argv[1] if len(sys.argv) > 1 else "52.76.96.108"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 9004

HELLO = bytes([0x52,0x45,0x4C,0x59, 0x01, 0x00,0x00, 0xA6])

def recv_frame(sock, timeout=5):
    sock.settimeout(timeout)
    buf = b""
    # read header
    while len(buf) < 8:
        c = sock.recv(8 - len(buf))
        if not c:
            break
        buf += c
    if len(buf) < 8:
        return buf
    magic = buf[0:4]
    op = buf[4]
    length = int.from_bytes(buf[5:7], "big")
    cksum = buf[7]
    payload = b""
    while len(payload) < length:
        c = sock.recv(length - len(payload))
        if not c:
            break
        payload += c
    return buf, magic, op, length, cksum, payload

s = socket.create_connection((host, port), timeout=8)
print("-> HELLO")
print(binascii.hexlify(HELLO).decode(), len(HELLO))
s.sendall(HELLO)
time.sleep(0.5)
res = recv_frame(s, 5)
if isinstance(res, tuple):
    buf, magic, op, length, cksum, payload = res
    print(f"<- reply: magic={magic!r} op={op:#04x} len={length} cksum={cksum:#04x}")
    print("raw:", binascii.hexlify(buf).decode())
    print("payload hex:", binascii.hexlify(payload).decode())
    print("payload ascii:", repr(payload))
else:
    print("<- short reply:", binascii.hexlify(res).decode())

# try reading more
s.settimeout(2)
try:
    extra = s.recv(4096)
    print("extra:", binascii.hexlify(extra).decode())
except Exception as e:
    print("no extra:", e)
s.close()