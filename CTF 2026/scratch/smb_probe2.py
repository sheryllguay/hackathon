"""
SMB probe v2 - more careful, tries various patterns.
Also tries NetShareEnum / RPC bindings and a banner grab.
"""
import socket
import struct
import sys
import binascii
import time

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

def try_smb1_negotiate():
    print(f"--- SMB1 Negotiate on {TARGET}:{PORT} ---")
    dialect = b"\x02NT LM 0.12\x00"
    bcc = len(dialect)
    smb_header = b"\xffSMB" + b"\x72" + b"\x00\x00\x00\x00" + b"\x18" + b"\xc0\x00" + b"\x00\x00" + b"\x00"*8 + b"\x00\x00" + b"\x00\x00" + b"\xff\xff" + b"\x00\x00" + b"\x00\x00"
    assert len(smb_header) == 32
    smb_body = b"\x00" + struct.pack("<H", bcc) + dialect
    smb_msg = smb_header + smb_body
    pkt = struct.pack(">I", len(smb_msg)) + smb_msg
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((TARGET, PORT))
        s.sendall(pkt)
        data = recv_all(s, timeout=3)
        print(f"  Received {len(data)} bytes")
        print(f"  hex: {hexdump(data, 96)}")
    except Exception as e:
        print(f"  ERR: {e}")
    finally:
        s.close()

def try_smb2_negotiate():
    print(f"--- SMB2 Negotiate on {TARGET}:{PORT} ---")
    # Build negotiate with capabilities = 0
    dialects = [0x0311, 0x0302, 0x0300, 0x0210, 0x0202]
    negotiate = struct.pack("<H", 36)
    negotiate += struct.pack("<H", len(dialects))
    negotiate += struct.pack("<H", 0x03)  # security mode: signing enabled + required? try required
    negotiate += struct.pack("<H", 0)
    negotiate += struct.pack("<I", 0)
    negotiate += b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    negotiate += struct.pack("<I", 0)
    negotiate += struct.pack("<H", 0)
    negotiate += struct.pack("<H", 0)
    for d in dialects:
        negotiate += struct.pack("<H", d)

    smb2_header = b"\xfeSMB"
    smb2_header += struct.pack("<H", 64)
    smb2_header += struct.pack("<H", 0)
    smb2_header += struct.pack("<I", 0)
    smb2_header += struct.pack("<H", 0)  # cmd = 0
    smb2_header += struct.pack("<H", 1)
    smb2_header += struct.pack("<I", 0)
    smb2_header += struct.pack("<I", 0)
    smb2_header += struct.pack("<Q", 1)
    smb2_header += struct.pack("<I", 0)
    smb2_header += struct.pack("<I", 0)
    smb2_header += struct.pack("<Q", 0)
    smb2_header += b"\x00" * 16

    smb_msg = smb2_header + negotiate
    pkt = struct.pack(">I", len(smb_msg)) + smb_msg

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((TARGET, PORT))
        s.sendall(pkt)
        data = recv_all(s, timeout=3)
        print(f"  Received {len(data)} bytes")
        print(f"  hex: {hexdump(data, 256)}")
        if len(data) > 4 and data[4:8] == b" SMB" or (len(data) > 4 and data[4:8] == b"\xfeSMB"):
            # parse the response
            body = data[4:]
            h = body
            status = struct.unpack("<I", h[8:12])[0]
            cmd = struct.unpack("<H", h[12:14])[0]
            print(f"  status: 0x{status:08x}, command: 0x{cmd:04x}")
            if cmd == 0 and (status >> 30) == 0x2:  # success? no, 0xc000000d is invalid param
                pass
            if len(body) >= 64 + 2:
                nbody = body[64:]
                struct_size = struct.unpack("<H", nbody[0:2])[0]
                if struct_size == 65:
                    sec_mode = struct.unpack("<H", nbody[2:4])[0]
                    dialect = struct.unpack("<H", nbody[4:6])[0]
                    server_guid = nbody[8:24]
                    capabilities = struct.unpack("<I", nbody[24:28])[0]
                    max_trans_size = struct.unpack("<I", nbody[28:32])[0]
                    max_read_size = struct.unpack("<I", nbody[32:36])[0]
                    max_write_size = struct.unpack("<I", nbody[36:40])[0]
                    sys_time = struct.unpack("<Q", nbody[40:48])[0]
                    server_start = struct.unpack("<Q", nbody[48:56])[0]
                    sec_buf_off = struct.unpack("<H", nbody[56:58])[0]
                    sec_buf_len = struct.unpack("<H", nbody[58:60])[0]
                    print(f"  negotiate: sec_mode=0x{sec_mode:04x}, dialect=0x{dialect:04x}")
                    print(f"  capabilities=0x{capabilities:08x}, max_trans={max_trans_size}, max_read={max_read_size}, max_write={max_write_size}")
                    print(f"  sys_time=0x{sys_time:x}, server_start=0x{server_start:x}")
                    print(f"  sec_buf_off={sec_buf_off}, sec_buf_len={sec_buf_len}")
                    dialect_names = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1", 0x02FF: "SMB2 wildcard"}
                    print(f"  dialect_name={dialect_names.get(dialect, 'unknown')}")
                    if sec_buf_off and sec_buf_len:
                        buf = body[64 + sec_buf_off: 64 + sec_buf_off + sec_buf_len]
                        txt = buf.decode("utf-16-le", errors="replace")
                        print(f"  server_name={txt!r}")
                else:
                    print(f"  error response (struct_size={struct_size})")
    except Exception as e:
        print(f"  ERR: {e}")
    finally:
        s.close()

def try_banner_grab():
    print(f"--- TCP connect + banner grab {TARGET}:{PORT} ---")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((TARGET, PORT))
        try:
            data = s.recv(1024)
            print(f"  pre-send banner ({len(data)} bytes): {data!r}")
        except socket.timeout:
            print(f"  no pre-send banner (silent connect)")
    except Exception as e:
        print(f"  ERR: {e}")
    finally:
        s.close()

def main():
    try_banner_grab()
    print()
    try_smb1_negotiate()
    print()
    try_smb2_negotiate()

if __name__ == "__main__":
    main()
