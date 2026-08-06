"""
SMB2 chain - send negotiate and then session setup on same connection.
"""
import socket
import struct
import binascii
import sys

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

def build_negotiate():
    dialects = [0x0311, 0x0302, 0x0300, 0x0210, 0x0202]
    negotiate = struct.pack("<H", 36) + struct.pack("<H", len(dialects)) + struct.pack("<H", 0x01) + struct.pack("<H", 0) + struct.pack("<I", 0) + b"\x00" * 16 + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 0)
    for d in dialects:
        negotiate += struct.pack("<H", d)
    h = b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<H", 0) + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 1) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 1) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 0) + b"\x00" * 16
    msg = h + negotiate
    return struct.pack(">I", len(msg)) + msg

def build_session_setup_ntlmssp_negotiate():
    # NTLMSSP_NEGOTIATE
    nt = b"NTLMSSP\x00"
    msg_type = 1
    flags = 0x00088237  # NTLM, OEM, UNICODE, EXTENDED_SESSIONSECURITY, etc.
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

def parse_session_setup_response(body):
    h = body
    status = struct.unpack("<I", h[8:12])[0]
    cmd = struct.unpack("<H", h[12:14])[0]
    print(f"  SMB2 status=0x{status:08x} cmd=0x{cmd:04x}")
    if len(body) < 64 + 9:
        return
    ss = struct.unpack("<H", body[64:66])[0]
    sess_flags = struct.unpack("<H", body[66:68])[0]
    sec_off = struct.unpack("<H", body[68:70])[0]
    sec_len = struct.unpack("<H", body[70:72])[0]
    print(f"  structure_size={ss}, session_flags=0x{sess_flags:04x}, sec_off={sec_off}, sec_len={sec_len}")
    if sec_len > 0:
        buf = body[64+sec_off:64+sec_off+sec_len]
        print(f"  sec_buf ({sec_len} bytes): {hexdump(buf, 256)}")
        if buf[:8] == b"NTLMSSP\x00":
            msg_type = struct.unpack("<I", buf[8:12])[0]
            print(f"  NTLMSSP msg type: {msg_type}")
            if msg_type == 2:  # CHALLENGE
                # In CHALLENGE msg:
                #   signature (8)
                #   msg type (4) = 2
                #   domain_name (8: len, max, off)
                #   flags (4)
                #   challenge (8)
                #   reserved (8)
                #   address list (8)
                #   target info (8: len, max, off)
                # Total fixed = 8 + 4 + 8 + 4 + 8 + 8 + 8 + 8 = 56
                # Version field in NTLMSSP CHALLENGE is 8 bytes at offset 48-55 if NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY flag (0x00080000) was set
                # AV pairs don't contain OS version (that's a separate "Version" field)
                # Wait, actually NTLMSSP challenge can have a "Version" field at offset 48 if NTLMSSP_NEGOTIATE_VERSION (0x02000000) was set
                # Then target info follows
                domain_len, domain_max, domain_off = struct.unpack("<HHI", buf[12:20])
                flags = struct.unpack("<I", buf[20:24])[0]
                challenge = buf[24:32]
                addr_len, addr_max, addr_off = struct.unpack("<HHI", buf[40:48])
                target_info_len, target_info_max, target_info_off = struct.unpack("<HHI", buf[48:56])
                print(f"  NTLMSSP flags: 0x{flags:08x}")
                print(f"    NTLMSSP_NEGOTIATE_VERSION: {bool(flags & 0x02000000)}")
                print(f"    NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: {bool(flags & 0x00080000)}")
                # If VERSION present, the version field is at offset 48-55 (8 bytes)
                # Wait - actually in NTLMSSP_CHALLENGE_MESSAGE, the structure is:
                #   NTLMSSP Signature (8 bytes)
                #   MessageType (4 bytes)
                #   TargetName (8 bytes: Length, MaxLength, Offset)
                #   NegotiateFlags (4 bytes)
                #   ServerChallenge (8 bytes)
                #   Reserved (8 bytes)
                #   TargetInfo (8 bytes: Length, MaxLength, Offset)
                #   Version (8 bytes, optional, only if NTLMSSP_NEGOTIATE_VERSION is set)
                # Then data: TargetName, then ServerChallenge (already inline), then TargetInfo
                # Actually, the Version field is BEFORE TargetInfo in some references but AFTER in others. Let me check MS spec.
                # MS-NLMP 2.2.1.2: VERSION is at offset 48 (8 bytes: MajorVersion, MinorVersion, BuildNumber (2), Reserved (3), RevisionNumber (1))
                # And TargetInfo comes right after Version. But wait, TargetInfo is also 8 bytes (length, max, offset).
                # Hmm let me look at this more carefully.
                # Actually, I see two structures:
                #   - NTLMSSP_CHALLENGE (Type 2): has TargetName, Flags, ServerChallenge, Reserved, TargetInfo, Version
                #   - NTLMSSP_AUTHENTICATE (Type 3): has more fields
                # The version is in the CHALLENGE at offset 48-55 if NTLMSSP_NEGOTIATE_VERSION was set
                if flags & 0x02000000:
                    # Version field is at offset 48
                    v = buf[48:56]
                    if len(v) >= 8:
                        major = v[0]
                        minor = v[1]
                        build = struct.unpack("<H", v[2:4])[0]
                        # v[4:7] = reserved
                        revision = v[7]
                        print(f"  OS VERSION: Windows {major}.{minor} (build {build}, revision {revision})")
                # Then parse AV pairs from target info
                if target_info_len > 0 and target_info_off > 0:
                    ti = buf[target_info_off:target_info_off+target_info_len]
                    print(f"  Target info ({len(ti)} bytes): {hexdump(ti, 256)}")
                    i = 0
                    avs = {}
                    while i + 4 <= len(ti):
                        av_type = struct.unpack("<H", ti[i:i+2])[0]
                        av_len = struct.unpack("<H", ti[i+2:i+4])[0]
                        i += 4
                        if av_type == 0:
                            break
                        if i + av_len > len(ti):
                            break
                        av_data = ti[i:i+av_len]
                        i += av_len
                        avs[av_type] = av_data
                    av_names = {
                        1: "NbComputerName", 2: "NbDomainName", 3: "DnsComputerName",
                        4: "DnsDomainName", 5: "DnsTreeName", 6: "Flags", 7: "Timestamp"
                    }
                    for k, v in avs.items():
                        try:
                            txt = v.decode("utf-16-le", errors="replace")
                        except:
                            txt = v.hex()
                        print(f"    AV {k} ({av_names.get(k,'?')}): {txt!r}")

def main():
    print("--- SMB2 chain probe ---")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((TARGET, PORT))
        # Negotiate
        print("  Sending negotiate...")
        s.sendall(build_negotiate())
        data = recv_all(s, timeout=3)
        print(f"  Negotiate response: {len(data)} bytes")
        if len(data) < 4:
            print("  No response - quitting")
            return
        # parse status
        body = data[4:]
        status = struct.unpack("<I", body[8:12])[0]
        print(f"  Status: 0x{status:08x}")
        if status != 0:
            print("  Negotiate failed - quitting")
            return
        # Session setup
        print("  Sending session setup...")
        s.sendall(build_session_setup_ntlmssp_negotiate())
        data = recv_all(s, timeout=5)
        print(f"  SessionSetup response: {len(data)} bytes")
        if len(data) > 4:
            print(f"  hex: {hexdump(data, 512)}")
            parse_session_setup_response(data[4:])
        # try to get more
        d2 = recv_all(s, timeout=2)
        if d2:
            print(f"  extra: {len(d2)} bytes")
            print(f"  hex: {hexdump(d2, 256)}")
    except Exception as e:
        print(f"ERR: {e}")
    finally:
        try:
            s.close()
        except:
            pass

if __name__ == "__main__":
    main()
