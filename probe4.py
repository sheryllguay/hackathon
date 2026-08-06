import itertools

# Known frames: (header_bytes_before_checksum, payload, checksum)
frames = [
    # Client HELLO accepted
    (bytes([0x52,0x45,0x4C,0x59,0x01,0x00,0x00]), b"", 0xA6),
    # Server bad-checksum error
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x0C]), b"bad-checksum", 0x72),
    # Server unknown-opcode errors
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), b"unknown-opcode:0x03", 0x89),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), b"unknown-opcode:0x04", 0x8a),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), b"unknown-opcode:0x7f", 0xca),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), b"unknown-opcode:0xff", 0x28),
]

def crc8_variant(data, poly, init, refin, refout, xorout):
    def reflect(x, n):
        r=0
        for i in range(n):
            if x&(1<<i): r|=1<<(n-1-i)
        return r
    crc=init
    for b in data:
        if refin: b=reflect(b,8)
        crc^=b
        for _ in range(8):
            if crc&0x80: crc=((crc<<1)^poly)&0xFF
            else: crc=(crc<<1)&0xFF
    if refout: crc=reflect(crc,8)
    return crc^xorout

POLYS = [0x07,0x1D,0x31,0x39,0x9B,0xD5,0xCD]

def variants(data):
    res={}
    x=0
    for b in data: x^=b
    res['xor']=x
    s=sum(data)&0xFF
    res['sum']=s
    res['negsum']=(-s)&0xFF
    res['notsum']=(~s)&0xFF
    res['sum_xor1']=(s^1)
    for poly in POLYS:
        for init in [0x00,0xFF,0xFD,0xFE]:
            for refin in [False,True]:
                for refout in [False,True]:
                    for xorout in [0x00,0x55,0xFF]:
                        v=crc8_variant(data,poly,init,refin,refout,xorout)
                        res[f'p{poly:02x}i{init:02x}{int(refin)}{int(refout)}x{xorout:02x}']=v
    return res

# Test both "header only" and "header+payload" scopes
for scope in ["hdr","full"]:
    print(f"\n=== searching scope={scope} ===")
    candidates = None
    for hdr,pay,chk in frames:
        data = hdr if scope=="hdr" else hdr+pay
        vals = variants(data)
        matches = set(k for k,v in vals.items() if v==chk)
        if candidates is None:
            candidates = matches
        else:
            candidates &= matches
        print(f"  chk=0x{chk:02x} matches: {sorted(matches)[:5]}{'...' if len(matches)>5 else ''}")
    print("COMMON algorithms:", sorted(candidates))