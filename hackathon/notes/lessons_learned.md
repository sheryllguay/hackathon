# Lessons Learned

## Irish-Name-Repo 1 (picoCTF 2019) - SQL Injection Login Bypass
- **What happened**: The login form concatenated user input directly into an SQL query without sanitization.
- **How we found it**: Submitted a single quote (`'`) in the username field and observed an error page, indicating SQL injection.
- **How we exploited it**: Used the payload `' OR 1=1 --` in the username field (anything in password) to comment out the password check and always evaluate the WHERE clause as true.
- **Fix**: Use prepared statements / parameterized queries, validate and sanitize input, enforce least privilege on the DB account.
- **Reusable payload**: `' OR 1=1 --` (MySQL/SQLite) – remember the space after `--`.
- **Reference**: See `skills/web/SQLi.md` for a general SQLi cheat sheet and `payloads/SQLi.txt` for reusable strings.

## No FA (picoCTF 2026) - 2FA Bypass via Unsalted Hash + Session-Cookie OTP
- **What happened**: Admin password stored as unsalted SHA-256 in leaked `users.db`; the 4-digit 2FA OTP was stored inside the signed-but-readable Flask session cookie.
- **How we found it**: Dumped `users.db` with `sqlite3`, spotted a 64-hex SHA-256 hash and a `two_fa` flag; after login the session cookie payload decoded to reveal `otp_secret`.
- **How we exploited it**: Cracked the hash offline with rockyou (`hashcat -m 1400`) -> `apple@123`; logged in; read the OTP straight out of the session cookie; submitted it -> `logged=true` -> flag on `/`.
- **Fix**: Salt + slow hash (bcrypt/argon2); never store OTP/roles in client-visible sessions; rate-limit and invalidate OTP attempts.
- **Reusable technique**: Flask session cookies are signed, not encrypted -> decode the payload segment (zlib-compressed when it starts with `.`). See `skills/web/AuthBypass.md`, `scripts/flask_session_decoder.py`, `payloads/AuthBypass.txt`.

## Repetitions (picoCTF 2023) - Nested Base64 Decoding
- **What happened**: A provided file/string was base64-encoded 6 times; the wrapped 76-char lines were the giveaway that a chain was present.
- **How we found it**: The data was all base64 charset; the hint "Multiple decoding is always good" pointed to repeated decoding.
- **How we exploited it**: Decoded base64 repeatedly (whitespace stripped each layer) until plaintext appeared -> `picoCTF{...}` at layer 6.
- **Fix**: N/A (solved by decoding); N-level encoding is only an obfuscation, never security.
- **Reusable technique**: Loop-decode until output is no longer valid base64 or a flag pattern is found. See `scripts/base64_loop_decode.py`, `skills/crypto/EncodingDecoding.md`, `payloads/Encoding.txt`.

## SUDO MAKE ME A SANDWICH (picoCTF 2026) - Sudo Misconfiguration / GTFOBins
- **What happened**: `sudo -l` showed `(ALL) NOPASSWD: /bin/emacs`; `flag.txt` was root-owned (`r--r-----`), so we ran emacs as root to read it.
- **How we found it**: After SSH login, the first enumeration step `sudo -l` revealed the loose sudo grant; `ls -la` showed the root-owned flag.
- **How we exploited it**: Ran emacs in batch mode as root: `sudo /bin/emacs --batch -q -eval '(princ (with-temp-buffer (insert-file-contents "flag.txt") (buffer-string)))'` -> printed the flag. (Interactive alt: `M-x shell`/`M-x eshell` for a root shell.)
- **Fix**: Don't grant passwordless sudo to binaries that can read files or spawn shells; restrict to a specific wrapper if needed.
- **Reusable technique**: ANY sudo grant to an editor/interpreter/file-reader is a privilege escalation vector. Check GTFOBins for a sudo -> file-read/shell primitive; prefer non-interactive (batch/eval) variants for SSH automation. See `skills/linux/SudoAbuse.md`, `scripts/ssh_cmd.py`, `payloads/Linux.txt`.

## BYTEMANCY 2 (picoCTF 2026) - Raw Bytes Over Network
- **What happened**: A remote service asked the player to send a specific HEX byte N times ("Send me the HEX BYTE 0xFF 3 times, side-by-side, no space"). The requested bytes are non-printable, so they can't be typed.
- **How we found it**: Connected with a raw socket and read the prompt banner; regex-parsed the hex byte + count.
- **How we exploited it**: Sent `bytes([value]) * count + b"\n"` over a socket in a parse-and-reply loop; the trailing newline is required because the reader uses `fgets`/`scanf`-style buffered input. Flag printed immediately.
- **Fix**: N/A (client-side interaction challenge); send-raw input is expected by design.
- **Reusable technique**: When a prompt demands raw HEX bytes, send the ACTUAL bytes (not the ASCII hex string `'FF'`); interactive "N times" prompts need a recv→parse→send loop that stops on a flag prefix. Plain Python `socket` replaces pwntools/`nc` when unavailable (e.g. unicorn wheel build failure on new Python, no ncat on Windows). On Windows set `sys.stdout.reconfigure(encoding="utf-8")` before printing server output. See `skills/python/RawBytesNetwork.md`, `scripts/bytemancy_solver.py`, `payloads/RawBytesNetwork.txt`.

## Special (picoCTF 2023) - Spellchecked/Filtered Shell Jail
- **What happened**: An SSH login shell "spellchecked" every plain word — `ls` ran as `Is`, `whoami` as `Whom`, `pwd` as `Pod` — so normal commands were mangled. The flag sat in a home-dir folder (a glob revealed it as `blargh/flag.txt`).
- **How we found it**: Fed `ls`/`whoami`/`pwd` and read the mangled echo; the filter strips punctuation and autocorrects each WORD, so `l\s`/`l's`/`"ls"` all collapsed back to `ls`->`Is` and failed. Testing `$(ls)` showed compound syntax executed the real command.
- **How we exploited it**: Wrapped the action in an opaque shell construct the filter does not tokenize: `<1&cat blargh/*` (redirection `<` + glob `*`) read the flag; also `${parameter=cat < blargh/flag.txt}` and `((cat)) < blargh/flag.txt` work.
- **Fix**: A naive word filter/autocorrect is not a jail; any shell construct (`$()`, `${}`, `(( ))`, `<`, `&`, `*`) that survives can execute arbitrary commands.
- **Reusable technique**: Determine the filter rule first; if punctuation is stripped, don't spell commands with quotes — wrap the whole action in an opaque construct and use `*`/`<` to avoid typing filenames. Interactive jails need a paramiko prompt loop. See `skills/linux/BashJail.md`, `scripts/ssh_interactive_shell.py`, `payloads/Linux.txt`.


## byp4ss3d (picoCTF picoMini - CMU-Africa) - File Upload .htaccess RCE
- **What happened**: Registration portal uploaded ID cards to \images/\ with a server-side filter. The filter was a **blocklist** of only .php-ish extensions (rejected .php, .phtml, .PHP) while ACCEPTING .png/.jpg/.gif AND, critically, a file named .htaccess.
- **How we found it**: Uploaded probe files (.txt, .php, .png, .htaccess, .phtml, .jpeg, case-variant) and read accept/reject responses to map the filter rule and the allowed extensions.
- **How we exploited it**: Uploaded an \.htaccess\ containing \AddType application/x-httpd-php .png\, then uploaded \shell2.png\ with \<?php system(\['c']); ?>\. Requesting \images/shell2.png?c=id\ ran commands; \cat ../../flag.txt\ (flag was outside web root, at the filesystem root alongside \html/\) printed the flag.
- **Fix**: Use a strict image **allowlist** (extension + magic bytes + MIME), never a php-extension blocklist; **always reject .htaccess** (and dotfiles); store uploads in dirs with PHP execution disabled; serve via X-Sendfile or a handler that forces disposition.
- **Reusable technique**: When an upload filter is a blocklist, map it with probes; if .htaccess is allowed, force Apache to run an allowed extension as PHP (AddType/SetHandler) then upload a shell in that extension. No magic-byte prefix needed because it is the server handler that runs PHP. Flags often sit outside the web root -> use ../.. See \skills/web/FileUpload.md\, \payloads/PHP.txt\.
