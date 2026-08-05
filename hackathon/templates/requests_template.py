#!/usr/bin/env python3
import requests
import urllib3

# Suppress insecure SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CTFClient:
    def __init__(self, base_url, proxy=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        # Setup Proxy (e.g. Burp Suite proxy='http://127.0.0.1:8080')
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
            self.session.verify = False # Don't verify SSL certs when proxying
            
    def get_flag(self):
        url = f"{self.base_url}/flag"
        try:
            r = self.session.get(url, timeout=5)
            return r.text
        except requests.RequestException as e:
            print(f"[-] Request failed: {e}")
            return None

if __name__ == "__main__":
    # Quick execution test
    # Usage: python3 requests_template.py http://target.local http://127.0.0.1:8080
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com"
    proxy = sys.argv[2] if len(sys.argv) > 2 else None
    
    client = CTFClient(target, proxy)
    res = client.get_flag()
    print("[+] Result:")
    print(res)
