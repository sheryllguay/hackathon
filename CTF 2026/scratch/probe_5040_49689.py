import socket, struct

HOST = '10.181.33.90'

# 5040 deep probe
print('=== Port 5040 deep probe ===')
s = socket.socket()
s.settimeout(6)
s.connect((HOST, 5040))
# Try sending a DCE/RPC bind (8-byte aligned)
# Build a proper DCE/RPC bind to nsrp (NSI Service Interface)
bind_uuid_nsi = b'\xa8\x05\x7b\xd0\x10\xe1\x9e\x19\x08\x00\x2b\x10\x48\x60\x02\x00'  # nsi (likely)
bind_uuid_svc = b'\x6c\x96\x4f\x18\x2a\x06\x47\x4d\xa1\xf9\x6a\x5b\x22\x00\x00\x00'  # placeholder
bind = b'\x05\x00'  # version 5, minor 0
bind += b'\x0b\x00'  # PTYPE_BIND (11)
bind += b'\x10\x00'  # PFC_FIRST | PFC_LAST (0x10)
bind += b'\x10\x00\x00\x00'  # data representation
bind += b'\x58\x00'  # frag length 88
bind += b'\x00\x00'  # auth length
bind += b'\x01\x00\x00\x00'  # call id
bind += b'\x48\x00'  # max xmit frag
bind += b'\x48\x00'  # max recv frag
bind += b'\x00\x00\x00\x00'  # assoc group
bind += b'\x01\x00'  # ctx items (1)
bind += b'\x00\x00'  # padding
bind += b'\x00\x00'  # context id (0)
bind += b'\x01\x00'  # num trans items (1)
bind += b'\x00\x00\x00\x00'  # padding
# abstract syntax: nsi (0b3698b8-79c4-4a83-9b9c-1a5b3c1a85c1)
bind += b'\xb8\x98\x36\x0b\xc4\x79\x83\x4a\x9b\x9c\x1a\x5b\x3c\x1a\x85\xc1'
bind += b'\x02\x00\x00\x00'  # version
# transfer syntax: NDR 1.0
bind += b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60'
bind += b'\x02\x00\x00\x00'
s.sendall(bind)
try:
    r = s.recv(4096)
    if r:
        print('  DCE/RPC bind resp hex:', r[:128].hex())
        # Parse
        if len(r) >= 24:
            ver = r[:2].hex()
            ptype = r[2]
            print(f'    version={ver} ptype={ptype} (11=bind, 12=bind_ack, 13=bind_nak, 16=alter_context_resp)')
        if r[2] == 13:
            print('    BIND_NAK (rejection)')
        elif r[2] == 12:
            print('    BIND_ACK')
    else:
        print('  bind resp: empty')
except Exception as e:
    print('  bind ERR:', e)
s.close()

print()
# 49689 - it sent us data first. Let me reconnect and parse what it sent
print('=== Port 49689 - parse initial binary data ===')
s = socket.socket()
s.settimeout(6)
s.connect((HOST, 49689))
try:
    data = s.recv(8192)
    print(f'  Got {len(data)} bytes (hex):')
    print('  ', data[:256].hex())
    # First 4 bytes: NTSTATUS or transaction signature?
    if len(data) >= 4:
        sig = struct.unpack('<I', data[:4])[0]
        print(f'  first 4 bytes as uint32 LE: 0x{sig:08x}')
    # Check if this is a DCE/RPC bind_nak or something else
    if len(data) >= 16:
        print(f'  bytes 4-16: {data[4:16].hex()}')
    # Hex dump with ASCII
    for i in range(0, min(len(data), 256), 32):
        chunk = data[i:i+32]
        hexpart = ' '.join(f'{b:02x}' for b in chunk)
        ascpart = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'    {i:04x}: {hexpart:<96s} {ascpart}')
except Exception as e:
    print('  ERR:', e)
s.close()
print()
# Now try sending a real DCE/RPC bind
print('=== Port 49689 - try DCE/RPC bind to common services ===')
# Common service UUIDs to try (just one at a time)
services = [
    ('NSI', b'\xb8\x98\x36\x0b\xc4\x79\x83\x4a\x9b\x9c\x1a\x5b\x3c\x1a\x85\xc1'),
    ('lsarpc', b'\xc8\x4f\x32\x1b\x78\x16\x8a\x46\x98\x07\x2b\x1b\x31\x09\x13\x1d'),
    ('samr', b'\x78\x16\x57\xe0\xfe\x4f\x44\x2e\x47\x3e\xa4\x0c\x42\x6d\x10\xa0'),
    ('winreg', b'\x33\x8d\x14\xe1\x84\x1c\xd3\xc4\xff\x3d\xc2\x2f\x4c\xa0\x8a\x7a'),
    ('spoolss', b'\x12\x94\xa9\x36\x12\x84\x1f\x4a\xb1\x9b\xc5\x9b\xd5\x06\x46\x09'),
    ('SVCCTL', b'\x36\x92\x79\x2e\x5b\x37\xb5\x4f\x9c\x9b\x4d\x6f\x6c\x2c\x6a\x64'),
    ('BITS', b'\x6d\x3c\x98\x4e\x5f\x18\x36\x42\x97\x44\x3c\x1c\x6e\x2e\x9a\x59'),
    ('ITaskScheduler', b'\x86\xd8\xf4\x8a\x4d\x33\xc7\x49\x9a\x53\x42\x94\x75\x49\xf5\x6e'),
]
ndr = b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00'

for name, uuid in services:
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((HOST, 49689))
        # drain
        try:
            s.recv(4096)
        except Exception:
            pass
        bind = b'\x05\x00\x0b\x00\x10\x00\x10\x00\x00\x00\x58\x00\x00\x00\x01\x00\x00\x00'
        bind += b'\x48\x00\x48\x00\x00\x00\x00\x00\x01\x00\x00\x00'
        bind += uuid + b'\x02\x00\x00\x00' + ndr
        s.sendall(bind)
        try:
            r = s.recv(4096)
            if not r:
                print(f'  {name}: empty response')
            elif r[2] == 13:  # bind_nak
                print(f'  {name}: BIND_NAK (provider rejection)')
            elif r[2] == 12:  # bind_ack
                print(f'  {name}: BIND_ACK!')
            elif r[2] == 16:  # alter_context_resp
                print(f'  {name}: alter_context_resp')
            else:
                print(f'  {name}: ptype={r[2]} (first 32 hex={r[:32].hex()})')
        except Exception as e:
            print(f'  {name}: recv ERR {e}')
        s.close()
    except Exception as e:
        print(f'  {name}: ERR {e}')
