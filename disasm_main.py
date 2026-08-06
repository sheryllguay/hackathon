import struct

data = open('sandworm', 'rb').read()

# Detailed analysis of hook_default (0x1730) and surrounding code
print("=== hook_default detailed ===")
addr = 0x1730
end = 0x17A0
while addr < end:
    b = data[addr]
    hex_bytes = ' '.join('%02x' % data[addr+i] for i in range(min(16, end-addr)))
    print('%04x: %s' % (addr, hex_bytes))
    addr += 16

# Also look at the dispatch table area  
print("\n=== Dispatch table area (0x1170-0x1270) ===")
addr = 0x1170
end = 0x1270
while addr < end:
    b = data[addr]
    hex_bytes = ' '.join('%02x' % data[addr+i] for i in range(min(16, end-addr)))
    print('%04x: %s' % (addr, hex_bytes))
    addr += 16
