#!/usr/bin/env python3
import sys
from http.cookies import SimpleCookie

def parse_cookies(cookie_string):
    cookie = SimpleCookie()
    cookie.load(cookie_string)
    parsed = {k: v.value for k, v in cookie.items()}
    return parsed

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <raw_cookie_header_string>")
        print("Example: cookie_parser.py 'session=abc; user=admin; role=1'")
        sys.exit(1)
        
    raw = sys.argv[1]
    cookies = parse_cookies(raw)
    print("[+] Parsed Cookies:")
    for k, v in cookies.items():
        print(f"  {k}: {v}")
    print("\n[+] Python Requests Dict format:")
    print(cookies)
