import socket, struct, sys, time

HOST = "52.76.96.108"
PORT = 9004

def hexd(b):
    return ' '.join(f'{x:02x}' for x in b)

def crc8(data, poly=0x07, init=0x00):
    crc = init
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ poly) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc

def crc8_smbus(data):
    return crc8(data, poly=0x07, init=0x00)

def try_checksums(hdr):
    # hdr is bytes without checksum
    results = {}
    results['xor'] = 0
    for b in hdr: results['xor'] ^= b
    s = sum(hdr) & 0xFF
    results['sum'] = s
    results['negsum'] = (-s) & 0xFF
    results['notsum'] = (~s) & 0xFF
    results['crc8'] = crc8(hdr, 0x07, 0x00)
    results['crc8_0x31'] = crc8(hdr, 0x31, 0x00)
    results['crc8_0x9B'] = crc8(hdr, 0x9B, 0x00)
    results['crc8_initFF'] = crc8(hdr, 0x07, 0xFF)
    results['xor_xorA5'] = results['xor'] ^ 0xA5
    return results

hdr = bytes([0x52,0x45,0x4C,0x59,0x01,0x00,0x00])
print("checksum candidates for HELLO header:", try_checksums(hdr))
print("target = 0xA6")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(6)
s.connect((HOST, PORT))

hello = bytes([0x52,0x45,0x4C,0x59,0x01,0x00,0x00,0xA6])
print("-> sending HELLO:", hexd(hello))
s.sendall(hello)
time.sleep(0.5)
resp = s.recv(4096)
print(f"<- server replied ({len(resp)} bytes):")
print(hexd(resp))
print("---")
# parse frame
if len(resp) >= 8 and resp[0:4] == b"RELY":
    op = resp[4]
    ln = (resp[5] << 8) | resp[6]
    chk = resp[7]
    payload = resp[8:8+ln] if len(resp) >= 8+ln else resp[8:]
    print(f"opcode=0x{op:02x} length={ln} checksum=0x{chk:02x}")
    print("payload:", payload)
    # test checksum on server frame
    shdr = resp[:7]
    print("server frame checksum candidates:", try_checksums(shdr))
s.close()