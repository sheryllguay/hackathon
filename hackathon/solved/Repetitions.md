# Repetitions (picoCTF 2023) - Writeup

## Category: General Skills / Encoding (Nested Base64)
## Difficulty: Easy

### Challenge Description
> Can you make sense of this file?

A downloadable file (or pasted string) contains a long base64 blob. Hint is
terse: *"Multiple decoding is always good."*

### Recon
1. The provided data is entirely base64 charset (`A-Z a-z 0-9 + / =`).
2. It is line-wrapped at ~76 chars - a strong hint it is a *chain* of encoded
   data, not a single layer.
3. Decoding reveals another valid base64 blob, then another...

### Exploitation
Decode base64 repeatedly until plaintext appears. The chain was 6 layers deep:
```bash
# Manual loop:
data=$(cat enc.flag)
while echo "$data" | base64 -d 2>/dev/null; do
  data=$(echo "$data" | base64 -d)
done
```
Automated (whitespace-tolerant, prints every layer and stops on flag):
```bash
python scripts/base64_loop_decode.py enc.flag
```
Layer 6 output: a `picoCTF{...}` flag.

### Flag
```
picoCTF{base64_n3st3d_dic0d!n8_d0wnl04d3d_4557ec3e}
```
*(Static - no instance variation.)*

### Why It Worked
Base64 is a reversible encoding, not encryption. Nesting encodings adds no
security - it only obfuscates. Given `N` layers, decoding `N` times returns
the original plaintext. The only difficulty is knowing when to keep decoding:
stop as soon as the output is readable / a flag prefix appears.

### Mitigation
- N/A for a CTF decode; the "defense" is purely obfuscation.

### Lessons Learned
- Identify the charset before decoding (base64 vs base32 vs hex vs URL).
- "Multiple decoding" hints mean loop-decode, not a single pass.
- Line wrapping breaks naive decoders: strip whitespace before each layer.
- Stop early on a flag prefix (`picoCTF{`) to avoid over-decoding garbage.
- If base64 stops validating, drop to base32 -> hex -> URL-decoding.

### Reusable Artifacts
- Skill: `skills/crypto/EncodingDecoding.md` (new)
- Script: `scripts/base64_loop_decode.py` (new - nested base64 decoder)
- Payloads: `payloads/Encoding.txt` (new - decode one-liners)
- Notes: `notes/patterns.md`, `notes/lessons_learned.md`
- Playbook: `playbooks/picoCTF.md` (encoding decision-tree branch)

### References
- picoCTF hint: base64 / multiple decoding.
