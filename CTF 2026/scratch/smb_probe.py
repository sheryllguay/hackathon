"""
SMB probe - read-only - no authentication, no exploit.
Tries SMB1 negotiate, SMB2 negotiate, and NetShareEnum via null session.
Captures any banners and any OS info returned.
"""
import socket
import struct
import sys
import binascii
import time

TARGET = "10.181.33.90"
PORT = 445

def hexdump(b, n=64):
    h = binascii.hexlify(b[:n]).decode("ascii")
    return " ".join(h[i:i+2] for i in range(0, len(h), 2))

def parse_smb1_negotiate_response(pkt):
    """
    Parse a minimal SMB1 negotiate response. Returns dict.
    """
    out = {}
    if len(pkt) < 4:
        return out
    # NetBIOS header: 4 bytes
    # 0x00 0x00 ... = session message
    smb = pkt[4:]
    if len(smb) < 32:
        return out
    # SMB1 header: 0xFF 'SMB' (4) cmd(1) err(4) flags(1) flags2(2) pid(2) tid(2) uid(2) mid(2)
    if smb[0:4] != b"\xffSMB":
        return {"_note": "not SMB1", "_smb": hexdump(smb, 32)}
    cmd = smb[4]
    out["smb_command"] = hex(cmd)
    if cmd == 0x72:  # negotiate
        # word count, then words
        if len(smb) < 39:
            return out
        wcount = smb[36]
        # then 17 words (each 2 bytes)
        # 0 = UCHAR wcount; then 17 WORDs: DialectIndex, SecurityMode, MaxMpxCount, MaxNumberVcs, MaxBufferSize, MaxRawSize, SessionKey, Capabilities, SystemTime (8), ServerTimeZone (2), EncryptionKeyLength
        idx = 37
        dialect_index = struct.unpack("<H", smb[idx:idx+2])[0]; idx += 2
        sec_mode = struct.unpack("<B", smb[idx:idx+1])[0]; idx += 1
        # skip padding to align
        # After sec_mode (1 byte) there's 1 byte reserved
        # Then MaxMpxCount (2) MaxNumberVcs (2) MaxBufferSize (4) MaxRawSize (4) SessionKey (2) Capabilities (4) SystemTime (8) ServerTimeZone (2) EncryptionKeyLength (1)
        # word count was 17 so total bytes = 1 + 17*2 = 35 then bcc
        # Actually SMB1 negotiate is 17 words after wcount byte
        # The structure: 1 byte wcount, 17 words (34 bytes) = 35 bytes
        # Let me just continue from idx
        out["dialect_index"] = dialect_index
        out["security_mode"] = sec_mode
        # rest is complex - skip to bcc
        idx = 36 + 1 + 17*2  # = 71
        bcc = struct.unpack("<H", smb[idx:idx+2])[0]
        out["bcc"] = bcc
        # Bytes: EncryptionKey (variable), Unicode strings (server, domain) preceded by 1 byte type + null-terminated Unicode
        idx += 2
        # EncryptionKey
        if len(smb) > idx:
            eklen = smb[idx]; idx += 1
            idx += eklen
        # Now the string area - first byte is 0 (skip), then 1 byte type, then 2*N+2 null-terminated Unicode string
        # Actually structure: 1 byte (case-sensitive byte) + ServerName, then 1 byte + DomainName
        # bytes after encryption key:
        # 2 bytes: ByteCount
        # ... ugh let me just dump remaining
        rest = smb[idx:]
        out["_rest_bytes"] = binascii.hexlify(rest).decode("ascii")
        out["_rest_len"] = len(rest)
    return out

def try_smb1_negotiate():
    print(f"--- SMB1 Negotiate on {TARGET}:{PORT} ---")
    # Build an SMB1 negotiate request.
    # We'll request just NT LM 0.12 (dialect 0) which is the simplest
    # NetBIOS session message: 0x00 0x00 0x00 <len>
    # SMB header (without NetBIOS): 0xFF 'S' 'M' 'B' cmd=0x72 (negotiate) err=0 flags=0 ... tid=0
    # Then word count = 0
    # Then byte count = length of dialects
    # Dialects: 2 bytes each, format = 0x02 + ASCII\0
    # We'll send: \x02NT LM 0.12\x00

    dialect = b"\x02NT LM 0.12\x00"
    dialects = dialect
    bcc = len(dialects)

    smb_header = b"\xffSMB" \
        + b"\x72" \
        + b"\x00\x00\x00\x00" \
        + b"\x18" \
        + b"\xc0\x00" \
        + b"\x00\x00" \
        + b"\x00\x00" \
        + b"\x00\x00" \
        + b"\x00\x00" \
        + b"\x00\x00\x00\x00" \
        + b"\xff\xff" \
        + b"\x00\x00\x00\x00"
    # Wait SMB1 header is 32 bytes. Let me rebuild.
    # Protocol (4) + Command (1) + Error (4) + Flags (1) + Flags2 (2) + PIDHigh (2) + Signature (8) + Reserved (2) + TID (2) + PIDLow (2) + UID (2) + MID (2) = 32
    smb_header = b"\xffSMB"        # 4
    smb_header += b"\x72"          # command
    smb_header += b"\x00\x00\x00\x00"  # status
    smb_header += b"\x18"          # flags: case-sensitive
    smb_header += b"\xc0\x00"      # flags2
    smb_header += b"\x00\x00"      # pid high
    smb_header += b"\x00" * 8      # signature
    smb_header += b"\x00\x00"      # reserved
    smb_header += b"\x00\x00"      # tid
    smb_header += b"\xff\xff"      # pid low
    smb_header += b"\x00\x00"      # uid
    smb_header += b"\x00\x00"      # mid
    assert len(smb_header) == 32, f"hdr len={len(smb_header)}"

    smb_body = b"\x00"            # word count = 0
    smb_body += struct.pack("<H", bcc)
    smb_body += dialects

    smb_msg = smb_header + smb_body
    netbios_prefix = struct.pack(">I", len(smb_msg))
    pkt = netbios_prefix + smb_msg

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((TARGET, PORT))
    s.sendall(pkt)
    data = s.recv(4096)
    s.close()
    print(f"Received {len(data)} bytes")
    print(f"  hex: {hexdump(data, 96)}")
    parsed = parse_smb1_negotiate_response(data)
    print(f"  parsed: {parsed}")
    return data, parsed

def try_smb2_negotiate():
    print(f"--- SMB2 Negotiate on {TARGET}:{PORT} ---")
    # SMB2 header: 16-byte header
    # Then negotiate request
    # Negotiate request:
    #   StructureSize (2) = 36
    #   DialectCount (2)
    #   SecurityMode (2)
    #   Reserved (2)
    #   Capabilities (4)
    #   ClientGuid (16)
    #   NegotiateContextOffset (4)
    #   NegotiateContextCount (2)
    #   Reserved2 (2)
    # Then dialects: 2 bytes each
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]  # 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1
    negotiate = struct.pack("<H", 36)  # StructureSize
    negotiate += struct.pack("<H", len(dialects))
    negotiate += struct.pack("<H", 0x01)  # security mode: signing enabled
    negotiate += struct.pack("<H", 0)
    negotiate += struct.pack("<I", 0)     # capabilities
    negotiate += b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    negotiate += struct.pack("<I", 0)     # negotiate context offset
    negotiate += struct.pack("<H", 0)     # negotiate context count
    negotiate += struct.pack("<H", 0)     # reserved
    for d in dialects:
        negotiate += struct.pack("<H", d)

    # SMB2 header
    smb2_header = b"\xfeSMB"        # protocol id
    smb2_header += struct.pack("<H", 64)  # header size
    smb2_header += struct.pack("<H", 0)   # credit charge
    smb2_header += struct.pack("<I", 0)   # status
    smb2_header += struct.pack("<H", 0)   # command = 0 = negotiate
    smb2_header += struct.pack("<H", 1)   # credits requested
    smb2_header += struct.pack("<I", 0)   # flags
    smb2_header += struct.pack("<I", 0)   # next command offset
    smb2_header += struct.pack("<Q", 0)   # message id
    smb2_header += struct.pack("<I", 0)   # reserved
    smb2_header += struct.pack("<I", 0)   # tree id
    smb2_header += struct.pack("<Q", 0)   # session id
    smb2_header += b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"  # signature
    assert len(smb2_header) == 64

    smb_msg = smb2_header + negotiate
    netbios_prefix = struct.pack(">I", len(smb_msg))
    pkt = netbios_prefix + smb_msg

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((TARGET, PORT))
    s.sendall(pkt)
    data = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 8192:
                break
    except socket.timeout:
        pass
    s.close()
    print(f"Received {len(data)} bytes")
    print(f"  hex: {hexdump(data, 256)}")
    if data.startswith(b"\xfeSMB"):
        # parse the response
        # header is 64 bytes
        h = data[4:]
        status = struct.unpack("<I", h[8:12])[0]
        cmd = struct.unpack("<H", h[12:14])[0]
        print(f"  status: 0x{status:08x}, command: 0x{cmd:04x}")
        if cmd == 0 and len(data) >= 68:
            # negotiate response
            nbody = data[64:]
            struct_size = struct.unpack("<H", nbody[0:2])[0]
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
            print(f"  negotiate: struct={struct_size}, sec_mode=0x{sec_mode:04x}, dialect=0x{dialect:04x}")
            print(f"  capabilities=0x{capabilities:08x}, max_trans=0x{max_trans_size:x}")
            print(f"  max_read=0x{max_read_size:x}, max_write=0x{max_write_size:x}")
            print(f"  server_guid={server_guid.hex()}")
            print(f"  sys_time=0x{sys_time:x}, server_start=0x{server_start:x}")
            print(f"  sec_buf_off={sec_buf_off}, sec_buf_len={sec_buf_len}")
            # Check dialect: 0x0202 = 2.0.2, 0x0210 = 2.1, 0x0300 = 3.0, 0x0302 = 3.0.2, 0x0311 = 3.1.1
            dialect_names = {0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0", 0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1", 0x02FF: "SMB2 wildcard"}
            print(f"  dialect_name={dialect_names.get(dialect, 'unknown')}")
            # Print the security buffer which contains the server name
            if sec_buf_off and sec_buf_len:
                buf = data[64 + sec_buf_off: 64 + sec_buf_off + sec_buf_len]
                # bytes are UTF-16LE
                try:
                    txt = buf.decode("utf-16-le", errors="replace")
                    print(f"  server_name={txt!r}")
                except Exception as e:
                    print(f"  server_name decode err: {e}")
    return data

def main():
    try:
        d, p = try_smb1_negotiate()
    except Exception as e:
        print(f"SMB1 err: {e}")
    print()
    try:
        d = try_smb2_negotiate()
    except Exception as e:
        print(f"SMB2 err: {e}")

if __name__ == "__main__":
    main()
