frames = [
    (bytes([0x52,0x45,0x4C,0x59,0x01,0x00,0x00]), b"", 0xA6, "HELLO"),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x0C]), b"bad-checksum", 0x72, "bad"),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), bytes.fromhex("756e6b6e6f776e2d6f70636f64653a30783033"), 0x89, "uo03"),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), bytes.fromhex("756e6b6e6f776e2d6f70636f64653a30783034"), 0x8a, "uo04"),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), bytes.fromhex("756e6b6e6f776e2d6f70636f64653a30783766"), 0xca, "uo7f"),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), bytes.fromhex("756e6b6e6f776e2d6f70636f64653a30786666"), 0x28, "uoff"),
]

def f_wsum_end(p):
    L=len(p); return sum(p[i]*(L-i) for i in range(L))&0xFF
def f_fletcher_b(p):
    a=0;b=0
    for x in p:
        a=(a+x)&0xFF; b=(b+a)&0xFF
    return b

PAY_FNS = { 'wsum_end': f_wsum_end, 'fletcher_b': f_fletcher_b }

# For each frame compute H_needed = chk - f(pay) mod256
for pname, pfn in PAY_FNS.items():
    print(f"\n=== payload fn = {pname} ===")
    Hs = []
    for hdr,pay,chk,label in frames:
        H = (chk - pfn(pay)) & 0xFF
        Hs.append((hdr, H, label))
        print(f"  {label}: op=0x{hdr[4]:02x} len={hdr[5]<<8|hdr[6]} -> H_needed=0x{H:02x}")
    # Now find header function g(hdr) that yields these H.
    # header bytes are: magic(52 45 4C 59), opcode, lenhi, lenlo
    # try: wsum_end over full 7 hdr bytes; wsum_start; sum; xor; wsum over [op,lenhi,lenlo] weights 3,2,1
    def wsum_end_h(h):
        L=len(h); return sum(h[i]*(L-i) for i in range(L))&0xFF
    def wsum_start_h(h):
        L=len(h); return sum(h[i]*(i+1) for i in range(L))&0xFF
    def sum_h(h): return sum(h)&0xFF
    def xor_h(h):
        x=0
        for b in h: x^=b
        return x
    def std_hdr(h):
        region=bytes(h[4:7])  # op,lenhi,lenlo
        L=len(region); return sum(region[i]*(L-i) for i in range(L))&0xFF
    def std_hdr_start(h):
        region=bytes(h[4:7])
        L=len(region); return sum(region[i]*(i+1) for i in range(L))&0xFF
    def fletcher_h(h):
        a=0;b=0
        for x in h: a=(a+x)&0xFF; b=(b+a)&0xFF
        return b
    funcs = {'wsum_end_7':wsum_end_h,'wsum_start_7':wsum_start_h,'sum_7':sum_h,'xor_7':xor_h,
             'wsum_end_oplen':std_hdr,'wsum_start_oplen':std_hdr_start,'fletcher_7':fletcher_h}
    for fname,gfn in funcs.items():
        preds = [gfn(h) for h,_,_ in Hs]
        targets = [t for _,t,_ in Hs]
        if preds == targets:
            print(f"  ** EXACT header fn = {fname}")
        else:
            diff = set((targets[i]-preds[i])&0xFF for i in range(len(targets)))
            if len(diff)==1:
                print(f"  header fn {fname} + const 0x{list(diff)[0]:02x} (matches all)")
            # also check preds-targets constant
        # show
        # print("   ", fname, "preds:", [f'{p:02x}' for p in preds], "targets:", [f'{t:02x}' for t in targets])