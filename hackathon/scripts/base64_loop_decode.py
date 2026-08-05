#!/usr/bin/env python3
"""Repeatedly base64-decode an input until it no longer decodes cleanly.

Handles the classic 'multiple/nested encoding' pattern where a flag or file
is base64-encoded several times. Prints each decoding layer so the chain
is visible and stops as soon as a layer is no longer valid base64.

Usage:
    python base64_loop_decode.py "<encoded_string>"
    type enc.flag | python base64_loop_decode.py        # reads stdin
    python base64_loop_decode.py enc.txt                # reads a file
"""
import sys
import base64
import re

_B64_RE = re.compile(rb'^[A-Za-z0-9+/]*={0,2}$')


def strip_and_decode(data: bytes) -> bytes:
    """Decode one base64 layer, tolerating whitespace/newlines."""
    cleaned = b''.join(data.split())
    if not cleaned or not _B64_RE.match(cleaned):
        raise ValueError('not valid base64')
    return base64.b64decode(cleaned)


def main() -> int:
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        # If the argument names an existing file, read it; else treat as the blob.
        try:
            with open(arg, 'rb') as fh:
                data = fh.read()
        except OSError:
            data = arg.encode()
    else:
        data = sys.stdin.buffer.read()

    print(f'[0] {data.decode("utf-8", errors="replace")}')
    layer = 0
    while True:
        try:
            layer += 1
            data = strip_and_decode(data)
        except (ValueError, base64.binascii.Error):
            print(f'[done] not valid base64 after {layer} layer(s); stopped.')
            return 0
        text = data.decode('utf-8', errors='replace')
        print(f'[{layer}] {text.strip()}')
        # Stop early once this is clearly plaintext (common for flags).
        if 'picoCTF{' in text or 'CTF{' in text:
            print(f'[flag] found at layer {layer}')
            return 0


if __name__ == '__main__':
    sys.exit(main())
