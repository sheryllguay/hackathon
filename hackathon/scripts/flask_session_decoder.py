#!/usr/bin/env python3
"""Decode a Flask client-side session cookie.

Flask cookies are SIGNED, not encrypted: payload.timestamp.signature.
The payload is base64url-encoded JSON, zlib-compressed when it starts with '.'.
No external dependencies (stdlib only).

Usage:
    python flask_session_decoder.py '<session.cookie.value>'
"""
import base64
import json
import sys
import zlib


def decode_payload(payload):
    if payload.startswith("."):
        payload = payload[1:]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        return zlib.decompress(base64.urlsafe_b64decode(payload)).decode()
    payload += "=" * ((4 - len(payload) % 4) % 4)
    return base64.urlsafe_b64decode(payload).decode()


def decode_flask(cookie):
    payload = cookie.rsplit(".", 2)[0]  # drop timestamp.signature
    data = decode_payload(payload)
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return data


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <session_cookie>")
        sys.exit(1)
    print("[+] Decoded Flask session:", decode_flask(sys.argv[1]))
