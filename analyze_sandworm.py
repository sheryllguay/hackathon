import struct

data = open('sandworm', 'rb').read()

# Focus on specific functions we identified
funcs = {
    'hook_default': 0x1730,
    'emit_flag': 0x1880,
    'check_reg': 0x1690,
    'write_all': 0x16D0,
    'read_exact': 0x16E0,
    'load_program': 0x17A0,
}

with open('func_output.txt', 'w') as f:
    for name, addr in funcs.items():
        f.write("=== %s @ %s ===\n" % (name, hex(addr)))
        for j in range(addr, addr + 128, 16):
            hex_str = ' '.join('%02x' % b for b in data[j:j+16])
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[j:j+16])
            f.write('  %04x: %-48s  %s\n' % (j, hex_str, ascii_str))
        f.write('\n')

print("Done")
