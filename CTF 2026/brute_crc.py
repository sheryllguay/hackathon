import json, itertools

samples = json.load(open("relay_samples.json"))
HELLO = bytes.fromhex("52454c59010000")
HELLO_CK = 0xA6

cases = []
for s in samples:
    full = bytes.fromhex(s['d'])
    header = full[0:7]
    payload = full[8:16]
    cases.append((s['c'], header, payload))
cases.append((HELLO_CK, HELLO, b''))

# Build candidate data builders over (header, payload)
builders = {
    'header+payload': lambda h,p: h+p,
    'header':          lambda h,p: h,
    'payload':         lambda h,p: p,
    'payload+header':  lambda h,p: p+h,
}

def reflect(x, n=8):
    r=0
    for i in range(n):
        r |= ((x>>i)&1)<<(n-1-i)
    return r

def crc8(data, poly, init, xorout, refin, refout):
    c=init
    for b in data:
        b = reflect(b) if refin else b
        c ^= b
        for _ in range(8):
            c = ((c<<1)^poly)&0xFF if (c&0x80) else (c<<1)&0xFF
    c = reflect(c) if refout else c
    return c ^ xorout

# Brute force all poly, init, xorout, refin, refout over various spans
spans_to_try = list(builders.keys())
print("Bruting CRC-8 params over spans:", spans_to_try)
found=[]
polys = list(range(256))
for poly in polys:
  for init in range(256):
    # early skip if needed; do full
    for xorout in range(256):
      for refin in (False,True):
        for refout in (False,True):
          for span in spans_to_try:
            ok=True
            for ck,h,p in cases:
              d=builders[span](h,p)
              if crc8(d,poly,init,xorout,refin,refout)!=ck:
                ok=False; break
            if ok:
              found.append((span,poly,init,xorout,refin,refout))
print("total found:", len(found))
for f in found[:50]:
    print(f)