import json

samples = json.load(open("relay_samples.json"))
# also add the known HELLO frame (header only, no payload)
HELLO = bytes.fromhex("52454c59010000")
HELLO_CK = 0xA6

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

named = {
 'CRC-8':            (0x07,0x00,0x00,False,False),
 'CRC-8/CDMA2000':   (0x9B,0xFF,0x00,False,False),
 'CRC-8/DARC':       (0x39,0x00,0x00,True,True),
 'CRC-8/DVB-S2':     (0xD5,0x00,0x00,True,True),
 'CRC-8/EBU':        (0x1D,0xFF,0x00,False,False),
 'CRC-8/I-CODE':     (0x1D,0xFD,0x00,False,False),
 'CRC-8/ITU':        (0x07,0x00,0x55,False,False),
 'CRC-8/MAXIM':      (0x31,0x00,0x00,True,True),
 'CRC-8/ROHC':       (0x07,0xFF,0x00,True,True),
 'CRC-8/WCDMA':      (0x9B,0x00,0x00,False,False),
 'CRC-8/OpenAIR':    (0x4D,0x00,0x00,False,False),
}

# possible data spans
dataset_choices = []
for s in samples:
    full = bytes.fromhex(s['d'])          # 16 bytes: header(8 w/o cksum) + payload(8)
    header = full[0:7]                    # magic+op+len
    payload = full[8:8+8]
    dataset_choices.append((s['c'], {
        'header+payload': header+payload,
        'header': header,
        'payload': payload,
        'payload+header': payload+header,
        'op+len+payload': bytes([0x81,0x00,0x08])+payload,
        'magic+payload+op+len': bytes([0x52,0x45,0x4C,0x59])+payload+bytes([0x81,0x00,0x08]),
    }))
# add HELLO
dataset_choices.append((HELLO_CK, {
    'header+payload': HELLO,
    'header': HELLO,
    'payload': b'',
    'payload+header': HELLO,
    'op+len+payload': bytes([0x01,0x00,0x00]),
    'magic+payload+op+len': HELLO,
}))

for cname, params in named.items():
    print(f"=== {cname} {params}")
    for span in ['header+payload','header','payload','payload+header','op+len+payload','magic+payload+op+len']:
        ok = True
        for ck, dsets in dataset_choices:
            d = dsets[span]
            r = crc8(d, *params)
            if r != ck:
                ok = False
                break
        if ok:
            print(f"   MATCH span={span}")