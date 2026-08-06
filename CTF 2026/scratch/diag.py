"""
Test with same bytes as multi.py.
"""
import sys
sys.path.insert(0, "scratch")
import smb_probe3
import socket
import struct
import binascii

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

# exactly like multi.py
def test_multi_style():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((TARGET, PORT))
        pkt = smb_probe3.smb2_negotiate([0x0311, 0x0302, 0x0300, 0x0210, 0x0202])
        print(f"Packet len: {len(pkt)}, hex: {hexdump(pkt, 32)}")
        s.sendall(pkt)
        data = recv_all(s, timeout=3)
        print(f"Response: {len(data)} bytes")
    except Exception as e:
        print(f"ERR: {e}")
    finally:
        s.close()

test_multi_style()
