"""
Compare the negotiate packets from smb_chain.py and smb_probe3.py.
"""
import sys
sys.path.insert(0, "scratch")
import smb_chain
import smb_probe3
import binascii

def hexdump(b, n=128):
    h = binascii.hexlify(b[:n]).decode("ascii")
    return " ".join(h[i:i+2] for i in range(0, len(h), 2))

p1 = smb_chain.build_negotiate()
p2 = smb_probe3.smb2_negotiate([0x0311, 0x0302, 0x0300, 0x0210, 0x0202], sec_mode=0x01, msg_id=0)
print(f"smb_chain.build_negotiate: {len(p1)} bytes")
print(f"  {hexdump(p1)}")
print(f"smb_probe3.smb2_negotiate: {len(p2)} bytes")
print(f"  {hexdump(p2)}")
print(f"Same? {p1 == p2}")
