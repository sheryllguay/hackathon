"""
SMB2 NTLMSSP probe - sends SessionSetup with NTLMSSP_NEGOTIATE to elicit
NTLMSSP_CHALLENGE from the server. The CHALLENGE contains the OS version
string (8 bytes: version, build, revision).
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

def build_smb2_negotiate():
    dialects = [0x0302]  # use 3.0.2 which we know works
    negotiate = struct.pack("<H", 36) + struct.pack("<H", len(dialects)) + struct.pack("<H", 0x01) + struct.pack("<H", 0) + struct.pack("<I", 0) + b"\x00" * 16 + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 0)
    for d in dialects:
        negotiate += struct.pack("<H", d)
    h = b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<H", 0) + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 1) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 1) + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 0) + b"\x00" * 16
    msg = h + negotiate
    return struct.pack(">I", len(msg)) + msg

def build_smb2_session_setup_ntlmssp_negotiate(msg_id=2, session_id=0):
    # NTLMSSP_NEGOTIATE message
    # NTLMSSP signature: 'N' 'T' 'L' 'M' 'S' 'S' 'P' 0x00
    # MessageType: 0x00000001 (1)
    # NegotiateFlags: 4 bytes
    # DomainNameFields: 8 bytes (len, maxlen, offset)
    # WorkstationFields: 8 bytes
    # ... + data
    nt = b"NTLMSSP\x00"
    msg_type = 1
    flags = 0x00088207  # common flags: NTLM, OEM, UNICODE, EXTENDED_SESSIONSECURITY, etc.
    domain = b""
    workstation = b""
    payload_off = 32  # size of NTLMSSP_NEGOTIATE without data
    # build fields
    body = nt + struct.pack("<I", msg_type) + struct.pack("<I", flags)
    body += struct.pack("<HHI", len(domain), len(domain), payload_off)
    body += struct.pack("<HHI", len(workstation), len(workstation), payload_off + len(domain))
    # no data

    # SMB2 SessionSetup request
    # StructureSize (2) = 25
    # Flags (1) = 0
    # SecurityMode (1) = 0
    # Capabilities (4) = 0
    # Channel (4) = 0
    # SecurityBufferOffset (2) = 88 (right after header+24)
    # SecurityBufferLength (2) = len(body)
    # Then PreviousSessionId (8) = 0
    # Then buffer

    smb_setup = struct.pack("<H", 25)
    smb_setup += struct.pack("<B", 0)
    smb_setup += struct.pack("<B", 0)
    smb_setup += struct.pack("<I", 0)
    smb_setup += struct.pack("<I", 0)
    smb_setup += struct.pack("<H", 88)  # offset
    smb_setup += struct.pack("<H", len(body))
    smb_setup += struct.pack("<Q", 0)  # previous session id
    smb_setup += body

    smb2_header = b"\xfeSMB"
    smb2_header += struct.pack("<H", 64)  # header size
    smb2_header += struct.pack("<H", 0)  # credit charge
    smb2_header += struct.pack("<I", 0)  # status
    smb2_header += struct.pack("<H", 1)  # command = 1 = SESSION_SETUP
    smb2_header += struct.pack("<H", 1)  # credits requested
    smb2_header += struct.pack("<I", 0)  # flags
    smb2_header += struct.pack("<I", 0)  # next command
    smb2_header += struct.pack("<Q", msg_id)  # message id
    smb2_header += struct.pack("<I", 0)  # reserved
    smb2_header += struct.pack("<I", 0)  # tree id
    smb2_header += struct.pack("<Q", session_id)  # session id
    smb2_header += b"\x00" * 16  # signature

    msg = smb2_header + smb_setup
    return struct.pack(">I", len(msg)) + msg

def parse_session_setup_response(body):
    # body starts with SMB2 header (64 bytes)
    h = body
    status = struct.unpack("<I", h[8:12])[0]
    cmd = struct.unpack("<H", h[12:14])[0]
    print(f"  SMB2 status=0x{status:08x} cmd=0x{cmd:04x}")
    if status != 0 and (status & 0xC0000000) != 0xC0000000:
        # not a status
        return
    # SessionSetup response: structure size 9, session_flags 2, security_buffer_offset 2, security_buffer_length 2
    if len(body) >= 64 + 9:
        ss = struct.unpack("<H", body[64:66])[0]
        sess_flags = struct.unpack("<H", body[66:68])[0]
        sec_off = struct.unpack("<H", body[68:70])[0]
        sec_len = struct.unpack("<H", body[70:72])[0]
        print(f"  structure_size={ss}, session_flags=0x{sess_flags:04x}, sec_off={sec_off}, sec_len={sec_len}")
        if sec_len > 0:
            buf = body[64+sec_off:64+sec_off+sec_len]
            print(f"  sec_buf ({sec_len} bytes): {hexdump(buf, 200)}")
            # parse NTLMSSP_CHALLENGE
            if buf[:8] == b"NTLMSSP\x00":
                msg_type = struct.unpack("<I", buf[8:12])[0]
                print(f"  NTLMSSP message type: {msg_type}")
                if msg_type == 2:  # CHALLENGE
                    # CHALLENGE: signature 8, msgtype 4 (offset 8), domain 8, flags 4 (offset 20), challenge 8 (offset 24), reserved 8, addrlist 8, security blob
                    # Actually: msg type (4), domain_name_fields (8), flags (4), challenge (8), reserved (8), address_list (8), then data
                    domain_len, domain_max, domain_off = struct.unpack("<HHI", buf[12:20])
                    flags = struct.unpack("<I", buf[20:24])[0]
                    challenge = buf[24:32]
                    reserved = buf[32:40]
                    addr_len, addr_max, addr_off = struct.unpack("<HHI", buf[40:48])
                    target_info_len, target_info_max, target_info_off = struct.unpack("<HHI", buf[48:56])
                    print(f"  NTLMSSP flags: 0x{flags:08x}")
                    # Now target info (AV pairs) follows
                    if target_info_len > 0:
                        # After msg type and fixed fields, the target info data is at offset 56 in the NTLMSSP, but its actual data is at target_info_off relative to the NTLMSSP start
                        ti = buf[target_info_off:target_info_off+target_info_len]
                        print(f"  Target info ({len(ti)} bytes): {hexdump(ti, 256)}")
                        # AV pairs: type (2) + length (2) + data
                        i = 0
                        avs = {}
                        while i + 4 <= len(ti):
                            av_type = struct.unpack("<H", ti[i:i+2])[0]
                            av_len = struct.unpack("<H", ti[i+2:i+4])[0]
                            i += 4
                            if av_type == 0:  # MsvAvEOL
                                break
                            if i + av_len > len(ti):
                                break
                            av_data = ti[i:i+av_len]
                            i += av_len
                            avs[av_type] = av_data
                        # AV type 7 = MsvAvTimestamp
                        # AV type 0 = MsvAvEOL
                        # AV type 1 = MsvAvNbComputerName
                        # AV type 2 = MsvAvNbDomainName
                        # AV type 3 = MsvAvDnsComputerName
                        # AV type 4 = MsvAvDnsDomainName
                        # AV type 5 = MsvAvDnsTreeName (forest)
                        # AV type 6 = MsvAvFlags
                        # AV type 7 = MsvAvTimestamp
                        # AV type 8 = MsvAvSingleHost
                        # AV type 9 = MsvAvTargetName
                        # AV type 10 = MsvAvChannelBindings
                        av_names = {
                            1: "NbComputerName", 2: "NbDomainName", 3: "DnsComputerName",
                            4: "DnsDomainName", 5: "DnsTreeName", 6: "Flags", 7: "Timestamp",
                            8: "SingleHost", 9: "TargetName", 10: "ChannelBindings"
                        }
                        for k, v in avs.items():
                            try:
                                txt = v.decode("utf-16-le", errors="replace")
                            except:
                                txt = v.hex()
                            print(f"    AV {k} ({av_names.get(k,'?')}): {txt!r}")
                    # Domain name:
                    if domain_len > 0:
                        dom = buf[domain_off:domain_off+domain_len]
                        print(f"  Domain (NTLMSSP): {dom.decode('utf-16-le', errors='replace')!r}")
                elif msg_type == 3:  # AUTH
                    print("  (got NTLMSSP_AUTH from server? unexpected)")

def main():
    print("--- SMB2 NTLMSSP NEGOTIATE probe ---")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((TARGET, PORT))
        s.sendall(build_smb2_negotiate())
        data = recv_all(s, timeout=3)
        print(f"  Negotiate response: {len(data)} bytes")
        if len(data) > 0:
            print(f"  hex: {hexdump(data, 256)}")
        if len(data) < 4:
            return
        # don't close; reuse for session setup
        print("  Sending session setup...")
        s.sendall(build_smb2_session_setup_ntlmssp_negotiate(msg_id=2, session_id=0))
        data = recv_all(s, timeout=5)
        print(f"  SessionSetup response: {len(data)} bytes")
        if len(data) > 4:
            print(f"  hex: {hexdump(data, 512)}")
            parse_session_setup_response(data[4:])
        # maybe more
        data2 = recv_all(s, timeout=2)
        if data2:
            print(f"  more data: {len(data2)} bytes")
            print(f"  hex: {hexdump(data2, 512)}")
            parse_session_setup_response(data2[4:])
    except Exception as e:
        print(f"ERR: {e}")
    finally:
        try:
            s.close()
        except:
            pass

if __name__ == "__main__":
    main()
