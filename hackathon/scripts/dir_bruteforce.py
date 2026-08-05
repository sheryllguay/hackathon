#!/usr/bin/env python3
import sys
import requests
from concurrent.futures import ThreadPoolExecutor

def request_url(url, word, success_codes):
    target = url.replace("FUZZ", word) if "FUZZ" in url else f"{url.rstrip('/')}/{word}"
    try:
        r = requests.get(target, allow_redirects=False, timeout=3)
        if r.status_code in success_codes:
            print(f"[+] Found: {target} (Status: {r.status_code}, Length: {len(r.content)})")
    except requests.RequestException:
        pass

def brute_force(url, wordlist_path, threads, codes):
    try:
        with open(wordlist_path, 'r') as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"[-] Error opening wordlist: {e}")
        return

    print(f"[*] Starting bruteforce on {url} with {len(words)} words using {threads} threads.")
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for word in words:
            executor.submit(request_url, url, word, codes)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target_url> <wordlist_path> [threads] [comma_separated_status_codes]")
        print("Example: dir_bruteforce.py 'http://127.0.0.1/FUZZ' wordlist.txt 10 200,301,302")
        sys.exit(1)
        
    target = sys.argv[1]
    wl = sys.argv[2]
    th = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    codes_str = sys.argv[4] if len(sys.argv) > 4 else "200,301,302,403"
    status_codes = [int(c) for c in codes_str.split(",")]
    
    brute_force(target, wl, th, status_codes)
