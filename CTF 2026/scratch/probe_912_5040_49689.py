import socket, struct

HOST = '10.181.33.90'

# Probe 912 with HELP
for port in [902, 912]:
    print('=== Port', port, 'plain probes ===')
    s = socket.socket()
    s.settimeout(5)
    s.connect((HOST, port))
    try:
        b = s.recv(2048)
        print('  banner:', repr(b))
    except Exception as e:
        print('  banner ERR:', e)
    s.sendall(b'HELP\r\n')
    try:
        r = s.recv(2048)
        print('  HELP resp:', repr(r))
    except Exception as e:
        print('  HELP ERR:', e)
    s.close()
    print()

# Probe 5040 with HTTP
print('=== Port 5040 HTTP probe ===')
s = socket.socket()
s.settimeout(5)
s.connect((HOST, 5040))
s.sendall(b'GET / HTTP/1.0\r\nHost: 10.181.33.90\r\nUser-Agent: probe\r\n\r\n')
try:
    r = s.recv(4096)
    print('  HTTP resp:', r[:1024])
except Exception as e:
    print('  HTTP ERR:', e)
s.close()
print()

# Probe 49689 with HTTP
print('=== Port 49689 HTTP probe ===')
s = socket.socket()
s.settimeout(5)
s.connect((HOST, 49689))
s.sendall(b'GET / HTTP/1.0\r\nHost: 10.181.33.90\r\nUser-Agent: probe\r\n\r\n')
try:
    r = s.recv(4096)
    print('  HTTP resp:', r[:1024])
except Exception as e:
    print('  HTTP ERR:', e)
s.close()
print()

# Probe 5040 - wait for banner first
print('=== Port 5040 - wait for initial banner ===')
s = socket.socket()
s.settimeout(8)
s.connect((HOST, 5040))
try:
    b = s.recv(4096)
    print('  initial recv:', repr(b))
except Exception as e:
    print('  initial ERR:', e)

# Try DCE/RPC bind to 5040
bind = b'\x05\x00'  # RPC version 5, minor 0
bind += b'\x0b\x00'  # bind
bind += b'\x10\x00'  # flags
bind += b'\x10\x00\x00\x00'  # data rep
bind += b'\x48\x00'  # frag length
bind += b'\x00\x00'  # auth length
bind += b'\x00\x00\x00\x00'  # call id
bind += b'\x48\x00'  # max xmit frag
bind += b'\x48\x00'  # max recv frag
bind += b'\x00\x00\x00\x00'  # assoc group
bind += b'\x04\x00'  # ctx items
bind += b'\x00\x00'  # padding
bind += b'\x00\x00\x01\x00'  # context id 1
bind += b'\x02\x00'  # abstract syntax
bind += b'\x00\x00\x00\x00'
bind += b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00'
bind += b'\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00'
print('  sending DCE/RPC bind to 5040...')
try:
    s.sendall(bind)
    r = s.recv(4096)
    print('  bind resp hex:', r[:128].hex() if r else 'empty')
except Exception as e:
    print('  bind ERR:', e)
s.close()
print()

# Probe 49689 - wait for banner
print('=== Port 49689 - wait for initial banner ===')
s = socket.socket()
s.settimeout(8)
s.connect((HOST, 49689))
try:
    b = s.recv(4096)
    print('  initial recv:', repr(b))
except Exception as e:
    print('  initial ERR:', e)
print('  sending DCE/RPC bind to 49689...')
try:
    s.sendall(bind)
    r = s.recv(4096)
    print('  bind resp hex:', r[:128].hex() if r else 'empty')
except Exception as e:
    print('  bind ERR:', e)
s.close()
print()

# Also probe 135
print('=== Port 135 - DCE/RPC bind (e.g., lsarpc UUID) ===')
s = socket.socket()
s.settimeout(5)
s.connect((HOST, 135))
print('  sending DCE/RPC bind (lsarpc)...')
try:
    s.sendall(bind)
    r = s.recv(4096)
    print('  bind resp hex:', r[:128].hex() if r else 'empty')
except Exception as e:
    print('  bind ERR:', e)
s.close()
