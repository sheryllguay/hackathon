#!/usr/bin/env python3
import sys
import jwt

def decode_jwt(token, key=None, verify=False):
    try:
        # Decode without verification
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        print("[+] Header:", header)
        print("[+] Payload:", payload)
        
        # Verify if key is provided
        if key:
            try:
                verified = jwt.decode(token, key, algorithms=[header.get("alg", "HS256")])
                print("[+] Verified Payload:", verified)
            except Exception as e:
                print("[-] Verification Failed:", str(e))
    except Exception as e:
        print("[-] Error parsing JWT:", str(e))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <jwt_token> [key/secret]")
        sys.exit(1)
    tok = sys.argv[1]
    k = sys.argv[2] if len(sys.argv) > 2 else None
    decode_jwt(tok, k)
