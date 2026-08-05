# BYTEMANCY 2 (picoCTF 2026) - Writeup

## Category: General Skills / Raw Bytes Over Network
## Difficulty: Medium

### Challenge Description
> Can you conjure the right bytes? The program's source code can be downloaded here.

A remote service (`nc lonely-island.picoctf.net 58553`) renders a text-menu banner and repeatedly
asks the player to send a specific HEX byte a set number of times:
`Send me the HEX BYTE 0xFF 3 times, side-by-side, no space.`
The difficulty is that the requested bytes (0xFF, 0x00, control characters, etc.) cannot be typed
from a terminal, so they must be sent over the network as raw bytes.

### Recon
1. Connect with a raw socket and read the banner (UTF-8 box-drawing / unicode glyphs).
2. The first prompt asked for `0xFF` x3. Regular-expression parsing of the prompt extracts the byte
   and the count.
3. Steps: `b'\xff\xff\xff'` followed by a trailing newline (the reader uses `fgets`-style input,
   which blocks until a newline is received).

### Exploitation
1. Automate with an interactive Python socket loop:
   - `recv` until the `==> ` prompt marker.
   - regex `0x([0-9A-Fa-f]{2})` for the byte and `(\d+)\s+times` for the count.
   - `sendall(bytes([value]) * count + b"\n")`.
   - repeat until a flag prefix appears.
2. Sending the newline was the key detail — without it the server never echoed the next round /
   flag because the line was never "submitted".

### Flag
```
picoCTF{3ff5_4_d4yz_fa2f490f}
```
*(Instance-specific; instance has since expired.)*

### Why It Worked
The program compares the raw received bytes against an expected sequence. Sending the exact
requested byte the requested number of times satisfies each check. Because the requested bytes are
non-printable, a socket/pwntools send-raw primitive is required instead of a keyboard. The trailing
newline terminates the buffered `fgets`/`scanf` read so the program continues.

### Lessons Learned
- When a CLI prompt demands specific HEX bytes, always send the **actual bytes**, not their ASCII hex
  text (`'FF'` != `b'\xff'`).
- Interactive "N times" prompts need a parse-and-reply loop; stop when a flag prefix
  (`picoCTF{`/`flag{`) appears in the response buffer.
- Plain Python `socket` is a drop-in for pwntools when pwntools fails to install (unicorn wheel
  build errors on new Python) and when `nc`/`ncat` is unavailable on Windows.
- Windows console printing of non-ASCII server output requires `sys.stdout.reconfigure(encoding="utf-8")`.

### Reusable Artifacts
- Skill: `skills/python/RawBytesNetwork.md` (new)
- Script: `scripts/bytemancy_solver.py` (new)
- Payloads: `payloads/RawBytesNetwork.txt` (new)
- Notes: `notes/patterns.md`, `notes/lessons_learned.md`

### References
- pwntools (standard tool for raw byte challenges): https://docs.pwntools.com/en/stable/
