P1 = bytes.fromhex("756e6b6e6f776e2d6f70636f64653a30783033")  # 0x03
P2 = bytes.fromhex("756e6b6e6f776e2d6f70636f64653a30783034")  # 0x04
P3 = bytes.fromhex("756e6b6e6f776e2d6f70636f64653a30783766")  # 0x7f
P4 = bytes.fromhex("756e6b6e6f776e2d6f70636f64653a30786666")  # 0xff
CHK = [0x89,0x8a,0xca,0x28]
PAYS = [P1,P2,P3,P4]

def crc8(data, poly, init, refin, refout, xorout):
    def reflect(x,n):
        r=0
        for i in range(n):
            if x&(1<<i): r|=1<<(n-1-i)
        return r
    crc=init
    for b in data:
        if refin: b=reflect(b,8)
        crc^=b
        for _ in range(8):
            crc = ((crc<<1)^poly)&0xFF if crc&0x80 else (crc<<1)&0xFF
    if refout: crc=reflect(crc,8)
    return crc^xorout

def f_sum(p): return sum(p)&0xFF
def f_wsum_end(p):
    L=len(p); return sum(p[i]*(L-i) for i in range(L))&0xFF
def f_wsum_start(p):
    L=len(p); return sum(p[i]*(i+1) for i in range(L))&0xFF
def f_xor(p):
    x=0
    for b in p: x^=b
    return x
def f_djb2(p):
    h=5381
    for b in p: h=((h*33)+b)&0xFFFFFFFF
    return h&0xFF
def f_sdbm(p):
    h=0
    for b in p: h=(b + (h<<6)+(h<<16)-h)&0xFFFFFFFF
    return h&0xFF
def f_ror_add(p):
    h=0
    for b in p:
        h = ((h>>1)|((h&1)<<7))&0xFF
        h = (h+b)&0xFF
    return h
def f_rol_add(p):
    h=0
    for b in p:
        h = ((h<<1)|((h>>7)&1))&0xFF
        h = (h+b)&0xFF
    return h
def f_mul_add(p, m):
    h=0
    for b in p: h=(h*m+b)&0xFF
    return h
def f_fletcher8(p):
    a=0;b=0
    for x in p:
        a=(a+x)&0xFF
        b=(b+a)&0xFF
    return b  # or a+b

def f_running_wsum(p):
    # cumulative: s += (index+1)*byte ? 
    L=len(p); return sum((i+1)*p[i] for i in range(L))&0xFF  # same as wsum_start

cands = {
    'sum': f_sum,
    'wsum_end': f_wsum_end,
    'wsum_start': f_wsum_start,
    'xor': f_xor,
    'djb2': f_djb2,
    'sdbm': f_sdbm,
    'ror_add': f_ror_add,
    'rol_add': f_rol_add,
    'fletcher_b': f_fletcher8,
}
for m in [2,3,5,31,33,37,131]:
    cands[f'mul{m}+add'] = (lambda p,mm=m: f_mul_add(p,mm))

# crc variants
POLYS=[0x07,0x1D,0x31,0x39,0x9B,0xD5,0xCD]
for poly in POLYS:
    for init in [0x00,0xFF]:
        for refin in [False,True]:
            for refout in [False,True]:
                for xorout in [0x00,0xFF,0x55]:
                    name=f'crc8_{poly:02x}_{init:02x}{int(refin)}{int(refout)}{xorout:02x}'
                    cands[name] = (lambda p, P=poly,I=init,Ri=refin,Ro=refout,X=xorout: crc8(p,P,I,Ri,Ro,X))

# Find candidates where chk - f(pay) is CONSTANT across all 4 frames
print("Payload functions giving constant (chk - f):")
for name, fn in cands.items():
    vals = [(CHK[i] - fn(PAYS[i])) & 0xFF for i in range(4)]
    if len(set(vals)) == 1:
        print(f"  {name}: constant = 0x{vals[0]:02x}")