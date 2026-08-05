# Encoding & Decoding (General Skills / Crypto)

Detect and reverse encoding layers. Most "make sense of this file/string"
challenges are simply repeated encoding (base64 -> base64 -> ...) or a mix
of base64 / base32 / hex / URL-encoding.

## When to use
- The challenge gives you a long gibberish string or a file of text.
- Hints mention "Multiple decoding is always good" / "encoding".
- The data is NOT readable ASCII and consists of a known charset.

## Identify the charset first
| Encoding | Character set                         | Padding |
|----------|---------------------------------------|---------|
| base64   | `A-Z a-z 0-9` `+ /` `=`              | `=`     |
| base32   | `A-Z` `2-7` `=`                      | `=`     |
| hex      | `0-9 a-f`                            | none    |
| URL      | `%hh` sequences                      | none    |

## Workflow
1. Identify the outermost encoding from its character set.
2. Decode one layer. If the result is still encoded, decode again.
3. Repeat until the output is readable plaintext / a flag.
4. Finish early the moment you see `picoCTF{`, `CTF{`, or other flag prefixes.
5. If base64 stops being valid, try base32, then hex, then URL-decoding.

## Reusable tooling
- `scripts/base64_loop_decode.py` - decodes nested base64 fully in one run
  (handles line-wrapped input; stops when a layer is not valid base64).
- `payloads/Encoding.txt` - base64/base32/hex/URL one-liners for Linux,
  PowerShell, and Python.

## Important pitfall
Input is often **line-wrapped** at 76 chars. Always strip newlines/whitespace
before decoding, or the decode may fail mid-chain. This is why `base64_loop_decode.py`
removes all whitespace (`data.split()`) between layers.

## Reference
The classic 'Repetitions' (picoCTF 2023) challenge is base64-encoded 6 times.
