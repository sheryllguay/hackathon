#!/usr/bin/env python3
import sys
import re

def extract_urls(text):
    # Regex pattern for matching URLs
    url_pattern = re.compile(
        r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(?::\d+)?(?:/[^\s"\']*)?'
    )
    urls = url_pattern.findall(text)
    return list(set(urls))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Read from file
        try:
            with open(sys.argv[1], 'r', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"[-] Error reading file: {e}")
            sys.exit(1)
    else:
        # Read from stdin
        print("[*] Reading from stdin (Ctrl+D to end)...")
        content = sys.stdin.read()
        
    found = extract_urls(content)
    print(f"[+] Found {len(found)} unique URLs:")
    for url in found:
        print(url)
