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

# standard named CRC-8 variants (poly,init,xorout,refin,refout)
named = {
 'CRC-8':            (0x07,0x00,0x00,False,False),
 'CRC-8/CDMA2000':   (0x9B,0xFF,0x00,False,False),
 'CRC-8/DARC':       (0x39,0x00,0x00,True,True),
 'CRC-8/DVB-S2':     (0xD5,0x00,0x00,True,True),
 'CRC-8/EBU':        (0x1D,0xFF,0x00,False,False),
 'CRC-8/I-CODE':     (0x1D,0xFD,0x00,False,False),
 'CRC-8/ITU':        (0x07,0x00,0x55,False,False),
 'CRC-8/MAXIM':      (0x31,0x00,0x00,True,True),  # equals Dallas/Maxim-Dow
 'CRC-8/ROHC':       (0x07,0xFF,0x00,True,True),
 'CRC-8/WCDMA':      (0x9B,0x00,0x00,False,False),
 'CRC-8/OpenAIR':    (0x4D,0x00,0x00,False,False),
}

# candidate data subsets of the header
subsets = {
 'magic+op+len': bytes([0x52,0x45,0x4C,0x59,0x01,0x00,0x00]),
 'op+len':        bytes([0x01,0x00,0x00]),
 'magic':         bytes([0x52,0x45,0x4C,0x59]),
 'op':            bytes([0x01]),
 'magic+op':      bytes([0x52,0x45,0x4C,0x59,0x01]),
 'len+op':        bytes([0x00,0x00,0x01]),
 'op+len(little)':bytes([0x01,0x00,0x00]),
}
for sname, d in subsets.items():
    print(sname, d.hex())
    for cname, params in named.items():
        r = crc8(d, *params)
        if r == target:
            print('  MATCH', cname, hex(r))
        else:
            print('   ', cname, hex(r))