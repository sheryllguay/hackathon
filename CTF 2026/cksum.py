target = 0xA6

def reflect(x, n=8):
    r = 0
    for i in range(n):
        r |= ((x >> i) & 1) << (n - 1 - i)
    return r

def crc8(data, poly, init=0, xorout=0, refin=False, refout=False):
    c = init
    for b in data:
        b = reflect(b) if refin else b
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ poly) & 0xFF if (c & 0x80) else (c << 1) & 0xFF
    c = reflect(c) if refout else c
    return c ^ xorout

datas = {
    'full': bytes([0x52,0x45,0x4C,0x59,0x01,0x00,0x00]),
    'no-magic': bytes([0x01,0x00,0x00]),
    'opcode-only': bytes([0x01]),
    'rev': bytes([0x00,0x00,0x01,0x59,0x4C,0x45,0x52]),
}

# Fletcher-8 / adler-ish variants also try
def sum_mix(d):
    # various: sum with init
    s = 0
    for b in d:
        s = (s + b) & 0xFF
    return s

# target known = a6
# search crc8
found = []
polys = [0x07,0x1D,0x31,0x39,0x4D,0x9B,0xD5,0xA6]
for dname, d in datas.items():
    for p in polys:
        for i in range(256):
            for x in range(256):
                for refin in (False, True):
                    for refout in (False, True):
                        if crc8(d, p, i, x, refin, refout) == target:
                            found.append((dname, hex(p), hex(i), hex(x), refin, refout))
print('count', len(found))
for f in found[:40]:
    print(f)