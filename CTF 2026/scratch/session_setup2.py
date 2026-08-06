"""
Minimal chain test - same as multi.py but does session setup.
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

def recv_all(s, timeout=3, max_bytes=65536):
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

def build_session_setup_ntlmssp():
    nt = b"NTLMSSP\x00"
    msg_type = 1
    flags = 0x00088237
    domain = b""
    workstation = b""
    payload_off = 32
    body = nt + struct.pack("<I", msg_type) + struct.pack("<I", flags)
    body += struct.pack("<HHI", len(domain), len(domain), payload_off)
    body += struct.pack("<HHI", len(workstation), len(workstation), payload_off + len(domain))

    smb_setup = struct.pack("<H", 25) + struct.pack("<BB", 0, 0) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<H", 88) + struct.pack("<H", len(body)) + struct.pack("<Q", 0)
    smb_setup += body

    smb2_header = b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<H", 0) + struct.pack("<I", 0) + struct.pack("<H", 1) + struct.pack("<H", 1) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 2) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 0) + b"\x00" * 16

    msg = smb2_header + smb_setup
    return struct.pack(">I", len(msg)) + msg

# Step 1: negotiate
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((TARGET, PORT))
s.sendall(smb_probe3.smb2_negotiate([0x0302]))  # use only 0x0302 (which works)
data = recv_all(s, timeout=3)
print(f"negotiate: {len(data)} bytes, hex: {hexdump(data, 32)}")
if data:
    body = data[4:]
    status = struct.unpack("<I", body[8:12])[0]
    print(f"  status: 0x{status:08x}")

# Step 2: session setup
print("Sending session setup...")
s.sendall(build_session_setup_ntlmssp())
data = recv_all(s, timeout=5)
print(f"session setup: {len(data)} bytes")
if data:
    print(f"  hex: {hexdump(data, 256)}")
s.close()
