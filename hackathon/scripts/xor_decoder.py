#!/usr/bin/env python3
import sys

def xor_crypt(data, key):
    # Support string and bytes for key/data
    if isinstance(data, str):
        data = data.encode()
    if isinstance(key, str):
        key = key.encode()
        
    out = bytearray()
    for i in range(len(data)):
        out.append(data[i] ^ key[i % len(key)])
    return bytes(out)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <hex_data/string> <hex_key/string>")
        print("Example: xor_decoder.py '414243' 'key'")
        sys.exit(1)
        
    raw_data = sys.argv[1]
    raw_key = sys.argv[2]
    
    # Try parsing as hex, fallback to raw string
    try:
        data_bytes = bytes.fromhex(raw_data)
    except ValueError:
        data_bytes = raw_data.encode()
        
    try:
        key_bytes = bytes.fromhex(raw_key)
    except ValueError:
        key_bytes = raw_key.encode()
        
    result = xor_crypt(data_bytes, key_bytes)
    print(f"Result (Hex): {result.hex()}")
    print(f"Result (ASCII/UTF-8): {result.decode('utf-8', errors='replace')}")
