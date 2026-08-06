frames = [
    (bytes([0x52,0x45,0x4C,0x59,0x01,0x00,0x00]), b"", 0xA6),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x0C]), b"bad-checksum", 0x72),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), b"unknown-opcode:0x03", 0x89),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), b"unknown-opcode:0x04", 0x8a),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), b"unknown-opcode:0x7f", 0xca),
    (bytes([0x52,0x45,0x4C,0x59,0xEE,0x00,0x13]), b"unknown-opcode:0xff", 0x28),
]

def wsum_payload(pay):
    L = len(pay)
    return sum(pay[i]*(L-i) for i in range(L)) & 0xFF

def wsum_full(hdr, pay):
    # includes magic+opcode+len in weighting? total bytes = 7 + L
    full = hdr + pay
    N = len(full)
    return sum(full[i]*(N-i) for i in range(N)) & 0xFF

def wsum_header_only(hdr):
    N = len(hdr)
    return sum(hdr[i]*(N-i) for i in range(N)) & 0xFF

print("Schema A: chk = K + wsum_payload(pay), find K per frame")
for hdr,pay,chk in frames:
    ws = wsum_payload(pay)
    K = (chk - ws) & 0xFF
    print(f"  chk=0x{chk:02x} wsum_pay=0x{ws:02x} -> K=0x{K:02x}")

print("\nSchema B: chk = wsum_full(hdr+pay) (weight=pos-from-end over all 7+L bytes)")
for hdr,pay,chk in frames:
    ws = wsum_full(hdr, pay)
    print(f"  chk=0x{chk:02x} wsum_full=0x{ws:02x} match={ws==chk}")

print("\nSchema C: chk = K + wsum_full(hdr+pay)")
ks=[]
for hdr,pay,chk in frames:
    ws = wsum_full(hdr, pay)
    K = (chk - ws) & 0xFF
    ks.append(K)
    print(f"  chk=0x{chk:02x} wsum_full=0x{ws:02x} -> K=0x{K:02x}")
print("K consistent:", len(set(ks))==1, set(ks))

print("\nSchema D: chk = wsum over [opcode,lenhi,lenlo]+pay, weight from end of THAT region")
for hdr,pay,chk in frames:
    region = bytes([hdr[4],hdr[5],hdr[6]]) + pay
    N=len(region)
    ws = sum(region[i]*(N-i) for i in range(N)) & 0xFF
    print(f"  chk=0x{chk:02x} ws=0x{ws:02x} match={ws==chk}")