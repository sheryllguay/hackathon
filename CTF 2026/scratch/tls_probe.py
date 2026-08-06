"""
Raw TLS ClientHello probe to see what server responds.
"""
import socket
import struct
import binascii

TARGET = "10.181.33.90"
PORT = 902

def hexdump(b, n=200):
    h = binascii.hexlify(b[:n]).decode("ascii")
    return " ".join(h[i:i+2] for i in range(0, len(h), 2))

def try_tls(version_major, version_minor):
    """Send a minimal TLS ClientHello with the given version and see what the server returns."""
    print(f"--- TLS probe with version 0x{version_major:02x}{version_minor:02x} ---")
    # Build ClientHello
    # ClientHello:
    #   client_version (2)
    #   random (32)
    #   session_id_length (1)
    #   session_id (0)
    #   cipher_suites_length (2)
    #   cipher_suites (e.g., TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F)
    #   compression_methods_length (1)
    #   compression_methods (1)
    client_hello = struct.pack(">H", version_major * 256 + version_minor)  # version
    client_hello += b"\x00" * 32  # random
    client_hello += b"\x00"  # session id length 0
    client_hello += struct.pack(">H", 2)  # cipher suites length
    client_hello += struct.pack(">H", 0x002F)  # TLS_RSA_WITH_AES_128_CBC_SHA
    client_hello += b"\x01\x00"  # compression length 1, null compression
    # Handshake header
    handshake = b"\x01" + struct.pack(">I", len(client_hello))[1:] + client_hello
    # TLS record
    record = struct.pack(">BHH", 0x16, version_major * 256 + version_minor, len(handshake)) + handshake
    print(f"  Sending {len(record)} bytes record: {hexdump(record, 32)}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((TARGET, PORT))
        s.sendall(record)
        s.settimeout(5)
        data = s.recv(4096)
        print(f"  Got {len(data)} bytes: {hexdump(data, 200)}")
        if data:
            # Parse TLS record
            if len(data) >= 5:
                rec_type = data[0]
                rec_version = struct.unpack(">H", data[1:3])[0]
                rec_len = struct.unpack(">H", data[3:5])[0]
                print(f"  Record: type=0x{rec_type:02x} version=0x{rec_version:04x} length={rec_len}")
                if rec_type == 0x15:
                    # Alert
                    if len(data) >= 7:
                        alert_level = data[5]
                        alert_desc = data[6]
                        print(f"  TLS Alert: level={alert_level} description={alert_desc}")
                        # Common descriptions
                        descs = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
                                 22: "record_overflow", 30: "decompression_failure", 40: "handshake_failure",
                                 42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
                                 45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter",
                                 48: "unknown_ca", 49: "access_denied", 50: "decode_error", 51: "decrypt_error",
                                 70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
                                 86: "inappropriate_fallback", 90: "user_cancelled", 91: "no_renegotiation",
                                 112: "unsupported_extension"}
                        print(f"    description: {descs.get(alert_desc, '?')}")
    except Exception as e:
        print(f"  ERR: {e}")
    finally:
        s.close()

# Try various TLS/SSL versions
try_tls(3, 0)  # SSL 3.0
try_tls(3, 1)  # TLS 1.0
try_tls(3, 2)  # TLS 1.1
try_tls(3, 3)  # TLS 1.2
try_tls(3, 4)  # TLS 1.3

# Also try just a non-TLS connection to see if the server gives a banner even on 902
print()
print("--- TCP banner on 902 ---")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect((TARGET, 902))
    data = s.recv(2048)
    print(f"  {len(data)} bytes: {data!r}")
except Exception as e:
    print(f"  ERR: {e}")
finally:
    s.close()
