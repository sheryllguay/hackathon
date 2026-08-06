# CTF Solving Patterns

This file stores reusable solving patterns for future CTF work.
It should capture repeatable workflows and investigation sequences, not challenge-specific details.

## How to Use This File
- Add a pattern when a solved challenge reveals a reusable workflow.
- Prefer generalized steps over one-off observations.
- Keep entries concise and easy to scan.
- Group patterns by category for fast retrieval.

## Web Exploitation
### SQL Injection
- Identify injectable input points.
- Test for syntax errors or response differences.
- Use a minimal payload to confirm behavior.
- Escalate from basic boolean/time-based checks to data extraction.
- Reuse known payload libraries and request templates.

### JWT
- Inspect token structure and claims.
- Check signing algorithm and key handling.
- Decode and analyze token parts before modifying them.
- Reuse existing JWT decoding utilities.

### Authentication Bypass (2FA / Session)
- Look for leaked database files; dump them and crack unsalted hashes offline (rockyou) before attacking the endpoint.
- Treat client-side session cookies (Flask) as readable: decode the payload (zlib if it starts with '.') to find OTP/roles/ids.
- When 2FA/OTP is present, check if the code is stored in the session cookie or brute-forceable (no rate limit).
- Verify auth state server-side; a flag gated by `session['username'] == 'admin'` is trivially reachable once auth is bypassed.

### IDOR (Hash-Obfuscated Object Reference)
- When a profile/object URL uses an opaque token, check it against common one-way functions: `md5("your_leaked_id")` matching the URL confirms the scheme. No cracking needed — it is an encoding, not a secret.
- Your OWN profile page usually leaks your numeric/role ID (e.g. "Guest (ID: 3000)") — the seed for cracking the whole scheme.
- Enumerate small integer ranges (1..25 or both sides of your own ID). "About N users/employees" hints bound the space.
- Distinguish 404 (no such id) from 200 (valid object) to walk the space; 200 + "admin"/role content = flag.
- Obscurity/"not directly exposed" wording in the description => IDOR on a hashed or hidden reference.

### Load Balancer / Failover Bypass
- Identify the load balancer and map which backend serves each response (content/headers/timing).
- Read the provided LB config for `backup` servers, `check fall N`, `inter Ns`, and health-check paths.
- Make the active backend fail its health check (e.g. a rate limiter returning 503) to force failover to the backup that holds the flag.
- Stop flooding once failover occurs so the backup's own rate limit is not tripped; poll with single requests.

### XSS
- Identify reflected or stored sinks.
- Confirm whether script execution is possible in the target context.
- Test with minimal payloads and expand carefully.
- Reuse payload libraries and browser-safe test vectors.

### SSRF / LFI / File Inclusion
- Identify network or file access paths.
- Test for unexpected internal access or local file exposure.
- Verify results through response differences and error behavior.
- Reuse payloads and request templates.

### File Upload -> .htaccess RCE (Apache/PHP)
- FIRST learn the filter rule: upload probes named `.txt`, `.php`, `.png`, `.phtml`, `.htaccess` and
  read accept/reject to tell a **blocklist** (`rejects only php-ish`) from a strict image **allowlist**.
- If `.htaccess` is accepted and only `.php`-style extensions are blocked, use Apache misconfig:
- Upload `.htaccess` with `AddType application/x-httpd-php .png` (or `SetHandler` FilesMatch), then
  upload PHP code named `shell.png`; request `shell.png?c=<cmd>`.
- Distinguish this from magic-byte/Content-Type bypasses: here the server handler (not mime check)
  is what runs PHP, so no `GIF89a` prefix is needed.
- Flags commonly sit OUTSIDE the web root: use `../..` (e.g. `ls ../..`, `cat ../../flag.txt`).

## Linux
### Enumeration
- Check user context, permissions, and writable paths.
- Inspect common files and directories.
- Look for binaries, scripts, cron jobs, and sudo rules.
- Reuse standard command workflows before inventing new ones.

### Shell Jail / Filtered Shell Bypass
- When a login shell "spellchecks"/autocorrects/bans plain WORDS (e.g. `ls`->`Is`, `cat`->`Cap`), first identify the mangling rule by feeding a known word and reading the echo.
- If the filter strips all punctuation before checking, punctuation-injection (`l\s`, `l''s`, `"ls"`) is USELESS — the words still collapse and get corrected. Skip it.
- Instead, wrap the real action in an opaque shell construct the filter does not tokenize as a word: `$(...)`, `${var=value}`, `((...))`, `< redirect`, `&`, `;`, `|`, and glob `*` usually pass straight through to the real shell.
- Use `*` (glob) to discover unknown directory/file names instead of spelling them; use redirection `< file` and `cmd *` so no banned filename/word is typed.
- Working payloads: `<1&cat blargh/*`, `${parameter=cat < blargh/flag.txt}`, `${parameter=ls}`, `((cat)) < blargh/flag.txt`.
- Interactive jails over SSH need a recv->send prompt loop; automate with paramiko (`invoke_shell`) — see `scripts/ssh_interactive_shell.py`.
- Category is distinct from SudoAbuse; see `skills/linux/BashJail.md` and `payloads/Linux.txt`.

### Privilege Escalation
- Identify binaries with unusual permissions.
- Check sudo privileges and misconfigurations.
- Compare common privilege escalation patterns with the current environment.
- Verify each step before escalating.

### Sudo Misconfiguration (GTFOBins)
- Run `sudo -l` FIRST on any shell you obtain; a `NOPASSWD` grant to a binary is the fastest root path.
- Treat any sudo-granted editor/interpreter/pager (emacs, vim, less, python, awk, find) as root-equivalent: look up the binary on GTFOBins for a file-read or shell primitive.
- Prefer non-interactive flags (`--batch -eval`, `-c`, piped stdin) so the exploit works over non-TTY SSH automation.
- Confirm file permissions with `ls -la` (root-owned `r--r-----` flag files are the usual target).
- On Windows/CI, automate password SSH with `paramiko` (`exec_command` + read stdout) instead of sshpass.

## Python Scripting
### Script Reuse
- Prefer existing scripts and templates over new implementations.
- Build small utilities for parsing, decoding, or automation.
- Verify script behavior before using it on a target.
- Keep scripts modular and reusable.

## Binary Exploitation
### ELF Analysis
- Inspect the binary type and architecture.
- Run file, strings, readelf, and objdump.
- Check for helper options such as --help or usage output.
- Look for embedded strings, format strings, or obvious weaknesses.
- Test the program with minimal inputs before developing a full exploit.

### PIE Bypass via Format String Leak + Function Pointer Jump (ret2win)
- If the program echoes your input via `printf(buffer)` AND lets you supply an arbitrary address
  to call (`scanf("%lx")` -> `((void(*)())val)()`), it is a leak-then-jump two-stage pwn.
- Leak a code pointer first: `%p %p ...` to dump; positional `%N$p` to read one slot precisely
  (PIE TIME 2: `%19$p` -> `main+0x41`). A SIGSEGV handler printing "Segfault Occurred" only means
  the address you jumped to was wrong - retry with the corrected win address.
- Derive the target: `nm vuln | grep -wE "main|win"` gives stable compile-time offsets; the base
  is random per run. `win = leak - leak_slot_off - (main_off - win_off)`.
- One connection: leak in stage 1, jump in stage 2. See `skills/pwn/PIEBypass.md`,
  `scripts/pwn_pie_leak.py`, `payloads/FormatString.txt`.

## Reverse Engineering
### Static Inspection
- Start with strings, imports, and symbol information.
- Identify entry points and interesting functions.
- Compare control flow and suspicious logic.
- Reuse disassembly workflows and helper tooling.

## Cryptography
### Token and Encoding Analysis
- Identify the encoding or cipher in use.
- Check whether the challenge depends on weak implementation or reuse of known patterns.
- Verify assumptions with known test vectors.
- Prefer decoding and analysis helpers over manual implementation.

## Forensics
### Evidence Review
- Look for timestamps, metadata, encoded content, and file artifacts.
- Trace the origin of suspicious files or strings.
- Correlate evidence across multiple files when possible.

## OSINT
### Information Gathering
- Gather context from public sources and metadata.
- Correlate names, domains, usernames, and timestamps.
- Validate findings before building a conclusion.

## General Skills
### Pattern Recognition
- Identify the underlying weakness before choosing an exploit path.
- Map the challenge to a known category and reuse prior patterns.
- Prefer minimal, testable steps over broad experimentation.

### Encoding / Decoding Chains
- When handed a gibberish string/file, identify the charset first: base64 `A-Za-z0-9+/=`, base32 `A-Z2-7=`, hex `0-9a-f`, URL `%hh`.
- "Multiple decoding is always good" means the data is encoded multiple times -> decode in a loop.
- Strip newlines/whitespace before each decode (line wrapping at ~76 chars is common and breaks chains).
- Stop early the moment you see a flag prefix (`picoCTF{`, `CTF{`).
- If base64 stops decoding, fall back to base32, then hex, then URL-decoding.
- Reuse `scripts/base64_loop_decode.py` (nested base64) and `payloads/Encoding.txt`.

### Raw Bytes Over Network (send-raw challenges)
- If a CLI/netcat prompt asks for specific HEX bytes ("Send me the HEX BYTE 0xNN N times"), send the ACTUAL bytes via a socket, not the ASCII hex text (`'FF'` != `b'\xff'`).
- Interactive "N times" prompts need a recv -> regex-parse -> send loop repeated until a flag prefix (`picoCTF{`/`flag{`) appears.
- Append a trailing `\n` for `fgets`/`scanf`-style readers — they block until a newline, so without it the server never responds.
- Plain Python `socket` (`create_connection` + `sendall`) is a drop-in for pwntools and works when `nc` is unavailable (Windows). pwntools install can fail (unicorn wheel build) on new Python.
- On Windows, `sys.stdout.reconfigure(encoding="utf-8")` before printing non-ASCII server output.
- Reuse `scripts/bytemancy_solver.py` and `skills/python/RawBytesNetwork.md` / `payloads/RawBytesNetwork.txt`.

## Storage Guidelines
- Keep patterns general and reusable.
- Remove challenge-specific values such as flags, hostnames, or exact payloads when they are not broadly useful.
- Prefer short workflow chains and decision points.
- Optimize for future retrieval by using clear section headings and compact bullet points.
