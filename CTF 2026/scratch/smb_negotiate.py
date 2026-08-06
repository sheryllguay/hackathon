import socket, struct, sys

HOST = '10.181.33.90'
PORT = 445

# SMB2 negotiate request (minimum viable)
# NetBIOS session header: 4 bytes (type 0x00 + length)
# SMB2 header: ProtocolId (4) + HeaderLength (2) + CreditCharge (2) + ...
# We craft a simple SMB2 negotiate that asks for dialect 0x0311 (SMB 3.1.1) etc.
def build_smb2_negotiate():
    # SMB2 negotiate body
    # StructureSize (2) = 36, DialectCount (2) = 3, SecurityMode (2) = 0, Reserved (2) = 0, Capabilities (4) = 0
    dialects = struct.pack('<HHH', 0x0311, 0x0310, 0x0302)  # 3.1.1, 3.1.0, 3.0.2
    negotiate_body = struct.pack('<HHHHI', 36, 3, 0, 0, 0) + dialects
    # SMB2 header (64 bytes)
    smb2_header = b'\xfeSMB'  # 0xFE534D42
    smb2_header += struct.pack('<H', 64)        # HeaderLength
    smb2_header += struct.pack('<H', 0)         # CreditCharge
    smb2_header += struct.pack('<I', 0)         # Status (success in negotiate)
    smb2_header += struct.pack('<H', 0)         # Command (0=negotiate)
    smb2_header += struct.pack('<H', 1)         # Credits requested
    smb2_header += struct.pack('<I', 0)         # Flags
    smb2_header += struct.pack('<I', 0)         # NextCommand
    smb2_header += struct.pack('<Q', 0xFFFFFFFFFFFFFFFF)  # MessageId
    smb2_header += struct.pack('<I', 0)         # Reserved
    smb2_header += struct.pack('<I', 0)         # TreeId
    smb2_header += struct.pack('<Q', 0xFFFFFFFFFFFFFFFF)  # SessionId
    smb2_header += b'\x00' * 16                 # Signature (none for negotiate)
    smb2 = smb2_header + negotiate_body
    # NetBIOS session header
    nb_header = b'\x00' + struct.pack('>I', len(smb2))[1:]  # 1 byte type + 3 byte length big-endian
    return nb_header + smb2

s = socket.socket()
s.settimeout(6)
s.connect((HOST, PORT))
s.sendall(build_smb2_negotiate())
data = s.recv(8192)
print('Raw response (hex, first 256 bytes):')
print(data[:256].hex())
print()
print('Response length:', len(data))
# Parse SMB2 header
if data[4:8] == b'\xfeSMB':
    print('Server speaks SMB2/3')
    # After netbios header (4 bytes), then SMB2 header at offset 4
    smb2_start = 4
    status = struct.unpack('<I', data[smb2_start+8:smb2_start+12])[0]
    print(f'Status: 0x{status:08x}')
    # Negotiate response: dialect revision is at offset 4 (after structure size 2 + security mode 2)
    # Actually, after SMB2 header, the negotiate response body starts:
    # StructureSize(2) = 65, SecurityMode(2), DialectRevision(2), NegotiateContextCount(2)...
    body_start = smb2_start + 64
    if len(data) >= body_start + 4:
        struct_size = struct.unpack('<H', data[body_start:body_start+2])[0]
        sec_mode = struct.unpack('<H', data[body_start+2:body_start+4])[0]
        dialect = struct.unpack('<H', data[body_start+4:body_start+6])[0]
        print(f'StructureSize: {struct_size}')
        print(f'SecurityMode: 0x{sec_mode:04x} (signing enabled={bool(sec_mode & 2)})')
        print(f'DialectRevision: 0x{dialect:04x}')
    # ServerGuid
    guid_start = body_start + 8
    if len(data) >= guid_start + 16:
        guid = data[guid_start:guid_start+16]
        print('ServerGuid:', '-'.join([guid[0:4].hex(), guid[4:6].hex(), guid[6:8].hex(), guid[8:10].hex(), guid[10:16].hex()]))
    # Capabilities, MaxTransSize, MaxReadSize, MaxWriteSize
    if len(data) >= guid_start + 32:
        cap = struct.unpack('<I', data[guid_start+16:guid_start+20])[0]
        print(f'Capabilities: 0x{cap:08x}')
    if len(data) >= guid_start + 40:
        max_tx = struct.unpack('<I', data[guid_start+20:guid_start+24])[0]
        max_rd = struct.unpack('<I', data[guid_start+24:guid_start+28])[0]
        max_wr = struct.unpack('<I', data[guid_start+28:guid_start+32])[0]
        print(f'MaxTrans/Read/Write: {max_tx}/{max_rd}/{max_wr}')
    # SystemTime, ServerStartTime
    if len(data) >= guid_start + 72:
        import datetime
        st = data[guid_start+32:guid_start+40]
        sst = data[guid_start+40:guid_start+48]
        def parse_filetime(b):
            if len(b) != 8: return None
            val = struct.unpack('<Q', b)[0]
            if val == 0: return None
            # FILETIME is 100ns since 1601
            epoch_diff = 11644473600
            ts = (val / 10000000) - epoch_diff
            try:
                return datetime.datetime.utcfromtimestamp(ts)
            except: return None
        print('SystemTime:', parse_filetime(st))
        print('ServerStartTime:', parse_filetime(sst))
    # NegotiateContextOffset, NegotiateContextCount
    # Then there's the signing key
    # Then SMB2 negotiate contexts...
    # ServerName is at the end of the fixed negotiate response
    if len(data) >= body_start + struct_size:
        # ServerName is at offset 0x48 from body start
        sn_off = body_start + 0x48
        if len(data) >= sn_off + 4:
            name_len = struct.unpack('<H', data[sn_off:sn_off+2])[0]
            # Actually, the field after server_start_time is: NegotiateContextCount(2) + ServerName(16 bytes) + NegotiateContextOffset(2) ?
            # Hmm, let me re-check the structure
            pass
    # Just print anything that looks like a server name (UTF-16LE)
    import re
    matches = re.findall(b'(?:[\x20-\x7e]\x00){4,}', data)
    if matches:
        print('Possible server names (UTF-16LE):')
        for m in matches[:5]:
            print('  ', m.decode('utf-16le', errors='replace'))
s.close()
