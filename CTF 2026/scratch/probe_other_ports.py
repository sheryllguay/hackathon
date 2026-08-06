"""
Banner grab + HTTP probe for ports 902, 912, 5040, 49689, 135, 139.
"""
import socket
import binascii

TARGET = "10.181.33.90"

def hexdump(b, n=128):
    h = binascii.hexlify(b[:n]).decode("ascii")
    return " ".join(h[i:i+2] for i in range(0, len(h), 2))

def try_tcp(port, probes, timeout=3):
    print(f"--- {TARGET}:{port} ---")
    for probe in probes:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((TARGET, port))
            if probe is not None:
                s.sendall(probe)
            s.settimeout(timeout)
            try:
                data = s.recv(4096)
            except socket.timeout:
                data = b""
            probe_str = repr(probe) if probe else '(no probe)'
            print(f"  probe={probe_str}: {len(data)} bytes")
            if data:
                print(f"    text: {data.decode('latin-1', errors='replace')!r}")
                print(f"    hex: {hexdump(data, 200)}")
        except Exception as e:
            probe_str = repr(probe) if probe else '(no probe)'
            print(f"  probe={probe_str}: ERR {e}")
        finally:
            try:
                s.close()
            except:
                pass

# 912: VMware auth daemon, plaintext version
try_tcp(912, [
    None,  # wait for banner
    b"\r\n",  # empty line
    b"HELP\r\n",
    b"USER admin\r\n",
    b"PASS password\r\n",
])

# 5040: often Windows service notification
try_tcp(5040, [
    None,
    b"\r\n",
    b"GET / HTTP/1.1\r\nHost: " + TARGET.encode() + b"\r\n\r\n",
    b"\x00\x00\x00\x00",
])

# 49689: high RPC ephemeral
try_tcp(49689, [
    None,
    b"\r\n",
    b"GET / HTTP/1.1\r\nHost: " + TARGET.encode() + b"\r\n\r\n",
    b"\x00\x00\x00\x00",
])

# 135: RPC
try_tcp(135, [
    None,
    b"\x05\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00",  # RPC bind
    b"\r\n",
])

# 139: NetBIOS session
try_tcp(139, [
    None,
    b"\x81\x00\x00\x44\x20\x43\x4b\x46\x44\x45\x4e\x45\x43\x46\x44\x45\x46\x46\x43\x46\x47\x45\x46\x46\x43\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x00\x20\x45\x4e\x44\x4f\x46\x4e\x45\x44\x45\x46\x4e\x45\x4e\x45\x4e\x45\x43\x4e\x45\x44\x45\x44\x45\x46\x00",
    b"\x00\x00\x00\x00",
])
