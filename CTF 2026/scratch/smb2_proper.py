import socket, struct, re

HOST = '10.181.33.90'
PORT = 445

# Proper SMB2 negotiate (with compound dialects, signing enabled)
# SMB2 NEGOTIATE request body structure (rev 2):
#   StructureSize: 36
#   DialectCount: N
#   SecurityMode: 0x0001 (signing enabled)
#   Reserved: 0
#   Capabilities: 0
#   ClientGuid: 16 bytes
#   NegotiateContextOffset: 0
#   NegotiateContextCount: 0
#   Reserved2: 0
#   Dialects: 2 bytes each

dialects = [0x0311, 0x0310, 0x0302, 0x0300, 0x0210]
body = struct.pack('<H', 36)
body += struct.pack('<H', len(dialects))
body += struct.pack('<H', 0x0001)  # security mode: signing enabled
body += struct.pack('<H', 0)       # reserved
body += struct.pack('<I', 0)       # capabilities
body += b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00'  # client GUID
body += struct.pack('<I', 0)       # negotiate context offset
body += struct.pack('<H', 0)       # negotiate context count
body += struct.pack('<H', 0)       # reserved2
for d in dialects:
    body += struct.pack('<H', d)

# SMB2 header (64 bytes)
smb2 = b'\xfeSMB'
smb2 += struct.pack('<H', 64)  # HeaderLength
smb2 += struct.pack('<H', 0)   # CreditCharge
smb2 += struct.pack('<I', 0)   # Status
smb2 += struct.pack('<H', 0)   # Command: NEGOTIATE
smb2 += struct.pack('<H', 1)   # CreditsRequested
smb2 += struct.pack('<I', 0)   # Flags
smb2 += struct.pack('<I', 0)   # NextCommand
smb2 += struct.pack('<Q', 1)   # MessageId
smb2 += struct.pack('<I', 0)   # Reserved
smb2 += struct.pack('<I', 0)   # TreeId
smb2 += struct.pack('<Q', 0)   # SessionId
smb2 += b'\x00' * 16           # Signature
smb2 += body

# NetBIOS session header
nb = b'\x00' + struct.pack('>I', len(smb2))[1:]
pkt = nb + smb2

print('Sending SMB2 negotiate ({} dialects), packet len={}'.format(len(dialects), len(pkt)))
s = socket.socket()
s.settimeout(6)
s.connect((HOST, PORT))
s.sendall(pkt)
try:
    data = s.recv(8192)
    print('Response len:', len(data))
    if len(data) < 4:
        print('Too short:', data.hex())
    else:
        # NetBIOS header is 4 bytes; SMB2 starts at offset 4
        smb2_start = 4
        if data[smb2_start:smb2_start + 4] == b'\xfeSMB':
            status = struct.unpack('<I', data[smb2_start + 8:smb2_start + 12])[0]
            cmd = struct.unpack('<H', data[smb2_start + 12:smb2_start + 14])[0]
            print(f'Status: 0x{status:08x}, Cmd: {cmd} (0=negotiate)')

            # SMB2 NEGOTIATE response
            body_off = smb2_start + 64
            struct_size = struct.unpack('<H', data[body_off:body_off + 2])[0]
            sec_mode = struct.unpack('<H', data[body_off + 2:body_off + 4])[0]
            dialect = struct.unpack('<H', data[body_off + 4:body_off + 6])[0]
            ctx_count = struct.unpack('<H', data[body_off + 6:body_off + 8])[0]
            guid = data[body_off + 8:body_off + 24]
            caps = struct.unpack('<I', data[body_off + 24:body_off + 28])[0]
            max_tx = struct.unpack('<I', data[body_off + 28:body_off + 32])[0]
            max_rd = struct.unpack('<I', data[body_off + 32:body_off + 36])[0]
            max_wr = struct.unpack('<I', data[body_off + 36:body_off + 40])[0]

            print(f'StructureSize: {struct_size}')
            print(f'SecurityMode: 0x{sec_mode:04x}  (signing_enabled={bool(sec_mode & 1)}, signing_required={bool(sec_mode & 2)})')
            print(f'DialectRevision: 0x{dialect:04x}')
            print(f'ServerGuid: {guid.hex()}')
            print(f'Capabilities: 0x{caps:08x}')
            print(f'MaxTransSize/Read/Write: {max_tx}/{max_rd}/{max_wr}')

            # SystemTime, ServerStartTime (8 bytes each)
            sys_t = data[body_off + 40:body_off + 48]
            start_t = data[body_off + 48:body_off + 56]
            import datetime

            def ft(b):
                if len(b) != 8: return None
                v = struct.unpack('<Q', b)[0]
                if v == 0: return None
                ts = (v / 10000000) - 11644473600
                try: return datetime.datetime.utcfromtimestamp(ts)
                except: return None

            print(f'SystemTime: {ft(sys_t)}')
            print(f'ServerStartTime: {ft(start_t)}')

            # ServerName (offset 0x70 = 112, but offset in struct is 56)
            sn_off = body_off + 56
            if len(data) >= sn_off + 2:
                # ServerName is an SMB_STRING: 2-byte offset (or length), then 16 bytes
                # Actually it is preceded by an SMB_STRING structure with name at 8-byte align
                # Let's just find any UTF-16 strings in the response
                strs = re.findall(b'(?:[\x20-\x7e]\x00){4,}', data)
                if strs:
                    print('UTF-16 strings:')
                    for s2 in strs[:5]:
                        print(' ', s2.decode('utf-16le', errors='replace'))
        else:
            print('Not SMB2, raw first 64 hex:', data[:64].hex())
            # Maybe it's SMB1
            if data[4:8] == b'\xffSMB':
                print('Server speaks SMB1 only!')
                # Parse native OS string from SMB1 negotiate response
                # The format: \xffSMB then various fields, including native OS and native LAN manager
                # search the body for printable UTF-16 strings
                strs = re.findall(b'(?:[\x20-\x7e]\x00){4,}', data)
                if strs:
                    print('Native OS strings:')
                    for s2 in strs[:10]:
                        print(' ', s2.decode('utf-16le', errors='replace'))
except Exception as e:
    print('ERR:', type(e).__name__, e)
s.close()
