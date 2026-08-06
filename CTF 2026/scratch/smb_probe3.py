"""
SMB probe v3 - try multiple variations to see what the server accepts.
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

def attempt(label, pkt):
    print(f"--- {label} ---")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect((TARGET, PORT))
        s.sendall(pkt)
        data = recv_all(s, timeout=2)
        print(f"  Got {len(data)} bytes")
        if data:
            print(f"  hex: {hexdump(data, 256)}")
            if len(data) > 4 and data[4:8] == b"\xfeSMB":
                h = data[4:]
                status = struct.unpack("<I", h[8:12])[0]
                cmd = struct.unpack("<H", h[12:14])[0]
                print(f"  SMB2 status=0x{status:08x} cmd=0x{cmd:04x}")
                if len(h) >= 66 and status == 0:
                    nbody = h[64:]
                    ss = struct.unpack("<H", nbody[0:2])[0]
                    if ss == 65:
                        sec_mode = struct.unpack("<H", nbody[2:4])[0]
                        dialect = struct.unpack("<H", nbody[4:6])[0]
                        sec_buf_off = struct.unpack("<H", nbody[56:58])[0]
                        sec_buf_len = struct.unpack("<H", nbody[58:60])[0]
                        dialect_names = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1"}
                        print(f"  NEGOTIATE: sec_mode=0x{sec_mode:04x}, dialect=0x{dialect:04x} ({dialect_names.get(dialect,'?')})")
                        if sec_buf_off and sec_buf_len:
                            buf = h[64 + sec_buf_off: 64 + sec_buf_off + sec_buf_len]
                            try:
                                txt = buf.decode("utf-16-le", errors="replace")
                                print(f"  server_name={txt!r}")
                            except Exception as e:
                                print(f"  decode err: {e}")
            elif len(data) > 4 and data[4:8] == b"\xffSMB":
                h = data[4:]
                cmd = h[4]
                print(f"  SMB1 cmd=0x{cmd:02x}")
    except Exception as e:
        print(f"  ERR: {e}")
    finally:
        s.close()
    print()

def smb2_negotiate(dialects, sec_mode=0x01, msg_id=0):
    negotiate = struct.pack("<H", 36) + struct.pack("<H", len(dialects)) + struct.pack("<H", sec_mode) + struct.pack("<H", 0) + struct.pack("<I", 0) + b"\x00" * 16 + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 0)
    for d in dialects:
        negotiate += struct.pack("<H", d)
    h = b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<H", 0) + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 1) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", msg_id) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 0) + b"\x00" * 16
    msg = h + negotiate
    return struct.pack(">I", len(msg)) + msg

def smb1_negotiate():
    dialect = b"\x02NT LM 0.12\x00"
    bcc = len(dialect)
    h = b"\xffSMB" + b"\x72" + b"\x00\x00\x00\x00" + b"\x18" + b"\xc0\x00" + b"\x00\x00" + b"\x00" * 8 + b"\x00\x00" + b"\x00\x00" + b"\xff\xff" + b"\x00\x00" + b"\x00\x00"
    body = b"\x00" + struct.pack("<H", bcc) + dialect
    msg = h + body
    return struct.pack(">I", len(msg)) + msg

attempt("SMB2 negotiate 3.1.1 only, sec_mode=0x01", smb2_negotiate([0x0311]))
attempt("SMB2 negotiate 3.1.1 only, sec_mode=0x02", smb2_negotiate([0x0311], sec_mode=0x02))
attempt("SMB2 negotiate 3.0.2 only", smb2_negotiate([0x0302]))
attempt("SMB2 negotiate 3.0 only", smb2_negotiate([0x0300]))
attempt("SMB2 negotiate 2.1 only", smb2_negotiate([0x0210]))
attempt("SMB2 negotiate 2.0.2 only", smb2_negotiate([0x0202]))
attempt("SMB1 negotiate", smb1_negotiate())
