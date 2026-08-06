import socket, struct, sys, time

HOST = "52.76.96.108"
PORT = 9004

def crc8(data, poly, init, refin=False, refout=False, xorout=0x00):
    def reflect(x, n):
        r = 0
        for i in range(n):
            if x & (1<<i):
                r |= 1 << (n-1-i)
        return r
    crc = init
    for b in data:
        if refin: b = reflect(b, 8)
        crc ^= b
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ poly) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    if refout: crc = reflect(crc, 8)
    return crc ^ xorout

VARIANTS = [
    ("CRC-8",          0x07, 0x00, False, False, 0x00),
    ("CRC-8/CDMA2000", 0x9B, 0xFF, False, False, 0x00),
    ("CRC-8/DARC",     0x39, 0x00, True,  True,  0x00),
    ("CRC-8/DVB-S2",   0xD5, 0x00, False, False, 0x00),
    ("CRC-8/EBU",      0x1D, 0xFF, True,  True,  0x00),
    ("CRC-8/I-CODE",   0x1D, 0xFD, False, False, 0x00),
    ("CRC-8/ITU",      0x07, 0x00, False, False, 0x55),
    ("CRC-8/MAXIM",    0x31, 0x00, True,  True,  0x00),
    ("CRC-8/MAXIM-DOW",0x31, 0x00, True,  True,  0x00),
    ("CRC-8/ROHC",     0x07, 0xFF, True,  True,  0x00),
    ("CRC-8/WCDMA",    0x9B, 0x00, True,  True,  0x00),
    ("CRC-8/AES-3K",   0x1D, 0xFF, False, False, 0x00),
]

def hdr_lenes(hdr, payload=b""):
    full = hdr + payload
    res = {}
    res['xor'] = 0
    for b in full: res['xor'] ^= b
    s = sum(full) & 0xFF
    res['sum'] = s
    res['negsum'] = (-s) & 0xFF
    res['notsum'] = (~s) & 0xFF
    res['xor_A5'] = res['xor'] ^ 0xA5
    res['xor_FF'] = res['xor'] ^ 0xFF
    for name, poly, init, refin, refout, xorout in VARIANTS:
        res[name] = crc8(full, poly, init, refin, refout, xorout)
    return res

hello_hdr = bytes([0x52,0x45,0x4C,0x59,0x01,0x00,0x00])
print("=== HELLO header only (target=0xA6) ===")
for k,v in hdr_lenes(hello_hdr).items():
    if v == 0xA6: print("MATCH (hdr-only):", k, hex(v))

print("=== HELLO header+payload(empty) ===")
for k,v in hdr_lenes(hello_hdr, b"").items():
    if v == 0xA6: print("MATCH:", k, hex(v))

# Now check server reply frame
srv = bytes([0x52,0x45,0x4C,0x59,0x81,0x00,0x08,0x1e,0x61,0x7c,0x57,0x37,0x39,0x25,0x57,0xe9])
srv_hdr = bytes([0x52,0x45,0x4C,0x59,0x81,0x00,0x08])
srv_pay = bytes([0x61,0x7c,0x57,0x37,0x39,0x25,0x57,0xe9])
print("\n=== server frame checksum=0x1e ===")
print("checking over header only:")
for k,v in hdr_lenes(srv_hdr).items():
    if v == 0x1e: print("MATCH (hdr-only):", k, hex(v))
print("checking over header+payload:")
for k,v in hdr_lenes(srv_hdr, srv_pay).items():
    if v == 0x1e: print("MATCH (full):", k, hex(v))