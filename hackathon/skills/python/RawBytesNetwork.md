# Raw Bytes Over Network Sockets (General Skills / Scripting)

## Purpose
Solve challenges that require sending raw binary / non-printable bytes to a networked program over the wire. Terminal typing cannot express bytes like `0xFF`, `0x00`, `0x0A`, etc., so the payload must be sent programmatically with a socket (or pwntools).

## Decision Tree
```
Remote service prints a prompt asking for specific HEX bytes ("Send me the HEX BYTE 0xNN N times")?
 ├── Are the requested bytes printable/typeable?
 │    ├── Yes -> just type them
 │    └── No  -> must send raw bytes over a socket -> continue
 ├── Read the prompt with regex: 0x([0-9A-Fa-f]{2})  and  (\d+) times
 ├── Build payload = bytes([b]) * N
 ├── Append a trailing "\n" (many readers use fgets/scanf and NEED a newline to submit)
 └── sendall(payload); loop until a flag pattern appears (picoCTF{/flag{)
```
If the target is a fire-and-forget stream (no interactive prompt), skip the parse/reply loop and just `sendall` the static payload.

## Recon Checklist
- [ ] Connect with a raw socket first and read the initial banner/prompt (`recv` in a loop).
- [ ] Regex the prompt for the hex byte and repetition count.
- [ ] Consider whether a trailing `\n` is required to submit the line.
- [ ] Watch for `picoCTF{` / `flag{` in the response — that ends the loop.

## Reusable Commands
No netcat on Windows? Use Python `socket` directly (no external deps):
```bash
python - <<'PY'
import socket
s = socket.create_connection(('host', port), timeout=10)
print(s.recv(4096))          # read banner
s.sendall(b'\xff\xff\xff\n') # raw bytes + newline
print(s.recv(4096))
PY
```

## Common Payloads
```python
# Send a specific hex byte N times (side-by-side) + newline
payload = bytes([0xFF]) * 3 + b"\n"
sock.sendall(payload)
```

## Exploitation Workflow
1. Write a small loop: `recv` until prompt marker, regex the byte + count, `sendall` byte*count + `\n`, repeat.
2. Stop as soon as a flag prefix appears in the buffered response.
3. On Windows, `reconfigure(sys.stdout)` to UTF-8 when printing server output that contains non-ASCII box-drawing chars.

## Example CTF Scenario
`bytemancy`/`bytemancy-2` (picoCTF, General Skills): the server prints "Send me the HEX BYTE 0xFF 3 times, side-by-side, no space." The requested bytes are non-printable, so sending `b'\xff\xff\xff\n'` via a raw socket yields the flag.

## Common Mistakes
- Not appending the trailing `\n` — `fgets`-style readers block until newline, so no response comes back.
- Forgetting that a string like `"FF"` sends ascii text, not the raw byte — you must send the actual byte value.
- Printing server output to a cp1252 Windows console — reconfigure stdout to UTF-8.

## CTF Tips
- pwntools (`pwn.remote(...).sendraw(...)`) is the standard tool, but plain `socket` works when pwntools fails to install (e.g. unicorn wheel build errors on new Python).
- Multi-round challenges need a parse-and-reply loop, not a one-shot send.

## References
- picoCTF bytemancy series writeups
- pwntools docs: https://docs.pwntools.com/en/stable/
