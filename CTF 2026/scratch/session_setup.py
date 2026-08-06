"""
Quick test - send negotiate and then send session setup.
"""
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

# Use 5 dialects (same as multi.py that worked)
def build_negotiate():
    dialects = [0x0311, 0x0302, 0x0300, 0x0210, 0x0202]
    negotiate = struct.pack("<H", 36) + struct.pack("<H", len(dialects)) + struct.pack("<H", 0x01) + struct.pack("<H", 0) + struct.pack("<I", 0) + b"\x00" * 16 + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 0)
    for d in dialects:
        negotiate += struct.pack("<H", d)
    h = b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<H", 0) + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 1) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 1) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 0) + b"\x00" * 16
    msg = h + negotiate
    return struct.pack(">I", len(msg)) + msg

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

def main():
    print("--- chain test ---")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((TARGET, PORT))
        print("  connected")
        s.sendall(build_negotiate())
        print("  negotiate sent")
        data = recv_all(s, timeout=3)
        print(f"  negotiate response: {len(data)} bytes")
        if len(data) > 4:
            body = data[4:]
            status = struct.unpack("<I", body[8:12])[0]
            print(f"  status: 0x{status:08x}")
            if status == 0:
                print("  sending session setup...")
                s.sendall(build_session_setup_ntlmssp())
                print("  session setup sent")
                data = recv_all(s, timeout=5)
                print(f"  session setup response: {len(data)} bytes")
                if data:
                    print(f"  hex: {hexdump(data, 256)}")
    except Exception as e:
        print(f"ERR: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    main()
