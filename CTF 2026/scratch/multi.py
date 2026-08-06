"""
Test various combinations of dialects in one negotiate.
"""
import sys
sys.path.insert(0, "scratch")
import smb_probe3
import binascii
import socket
import struct

TARGET = "10.181.33.90"
PORT = 445

def hexdump(b, n=128):
    h = binascii.hexlify(b[:n]).decode("ascii")
    return " ".join(h[i:i+2] for i in range(0, len(h), 2))

def recv_all(s, timeout=2, max_bytes=65536):
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) >= max_bytes:
                break
    except socket.timeout:
        pass
    return data

def test(label, dialects):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((TARGET, PORT))
        pkt = smb_probe3.smb2_negotiate(dialects)
        s.sendall(pkt)
        data = recv_all(s, timeout=3)
        if data:
            body = data[4:]
            status = struct.unpack("<I", body[8:12])[0]
            print(f"{label}: {len(data)} bytes, status=0x{status:08x}")
        else:
            print(f"{label}: no data")
    except Exception as e:
        print(f"{label}: ERR {e}")
    finally:
        s.close()

test("[0x0311, 0x0302, 0x0300, 0x0210, 0x0202]", [0x0311, 0x0302, 0x0300, 0x0210, 0x0202])
test("[0x0302, 0x0210, 0x0202]", [0x0302, 0x0210, 0x0202])
test("[0x0302, 0x0300, 0x0210, 0x0202]", [0x0302, 0x0300, 0x0210, 0x0202])
test("[0x0311, 0x0302]", [0x0311, 0x0302])
test("[0x0302]", [0x0302])
test("[0x0311]", [0x0311])
