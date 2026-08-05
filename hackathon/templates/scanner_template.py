#!/usr/bin/env python3
import sys
import requests
from concurrent.futures import ThreadPoolExecutor

class CTFScanner:
    def __init__(self, base_url, wordlist_file, max_threads=10):
        self.base_url = base_url.rstrip('/')
        self.max_threads = max_threads
        try:
            with open(wordlist_file, 'r') as f:
                self.paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"[-] Failed to load wordlist: {e}")
            sys.exit(1)
            
    def scan_path(self, path):
        url = f"{self.base_url}/{path.lstrip('/')}"
        try:
            # We only need the headers/status code, so use HEAD first to save bandwidth/time
            r = requests.head(url, timeout=3, allow_redirects=False)
            if r.status_code != 404:
                print(f"[+] Found: {url} (Status: {r.status_code})")
        except requests.RequestException:
            pass
            
    def run(self):
        print(f"[*] Starting scan on {self.base_url} with {len(self.paths)} paths...")
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            executor.map(self.scan_path, self.paths)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target_url> <wordlist_file> [threads]")
        sys.exit(1)
    target = sys.argv[1]
    wl = sys.argv[2]
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    
    scanner = CTFScanner(target, wl, threads)
    scanner.run()
