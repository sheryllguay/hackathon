# Special (picoCTF 2023) - Writeup

## Category: General Skills / Filtered (Spellchecked) Shell Jail
## Difficulty: Medium

### Challenge Description
> Don't power users get tired of making spelling mistakes in the shell? Not anymore! Enter Special, the Spell Checked Interface for Affecting Linux. Now, every word is properly spelled and capitalized... automatically and behind-the-scenes!

An SSH login shell (`ssh -p <port> ctf-player@saturn.picoctf.net`) ran a custom shell that
autocorrected and capitalized each plain WORD the user typed. Common commands were mangled into
nonsense before they reached the real shell (e.g. `ls` ran as `Is`, `whoami` as `Whom`, `pwd` as `Pod`).

### Recon
1. Connected with SSH (password auth via paramiko on Windows, no sshpass needed).
2. Fed common words and read the mangled echo:
   - `ls` -> `Is`, `whoami` -> `Whom`, `pwd` -> `Pod`.
3. Tested punctuation-splitting (`l\s`, `l's`, `"ls"`) — all collapsed back to `ls`->`Is` and failed.
   Conclusion: the filter **strips non-alphanumeric characters** before autocorrecting each word.
4. Tested compound shell syntax: `$(ls)` executed the real command substitution — the filter passes
   metacharacters and compound constructs through unmodified.

### Exploitation
Wrap the whole action in an opaque shell construct the per-word filter does not tokenize, and use
globs/redirection so no filename (or banned word) has to be spelled out:

```bash
*                       # glob expands to the home-dir folder -> reveals `blargh`
<1&cat blargh/*         # redirection + glob reads the flag (the "cannot open 1" is harmless)
```
Equivalent working payloads:
```bash
${parameter=ls}                          # parameter-expansion default-value runs `ls`
${parameter=ls blargh}                   # ... -> reveals flag.txt
${parameter=cat < blargh/flag.txt}
((cat)) < blargh/flag.txt                # command-grouping construct
```

### Flag
```
picoCTF{5p311ch3ck_15_7h3_w0r57_b741d1b1}
```
*(Instance-specific suffix; core string `5p311ch3ck_15_7h3_w0r57_` is stable across instances.)*

### Why It Worked
A word-based filter/autocorrect is not a real security boundary. The developer only transformed
"plain words", so any shell construct that is NOT a plain word — command substitution `$(...)`,
parameter expansion `${...}`, command grouping `((...))`, redirection `<`, and glob `*` — was
forwarded verbatim to the underlying `sh`. `<1&cat blargh/*` therefore ran real `cat` on everything
in `blargh/` (the `1` is a harmless file-descriptor open, `&` backgrounds it, and the file write/
echo still prints the flag).

### Lessons Learned
- Identify the mangling/filter rule FIRST by feeding known words; that determines whether
  punctuation-injection can ever work.
- When the filter strips punctuation and autocorrects words, DO NOT try to spell commands with
  quotes/backslashes — wrap the whole action in an opaque construct instead.
- `*` glob and `<` redirection are separate tokens that usually survive word filters; they let you
  avoid typing the exact directory/file name.
- Interactive jails over SSH need a recv->send prompt loop; automate with paramiko `invoke_shell`.

### Reusable Artifacts
- Skill: `skills/linux/BashJail.md` (new)
- Payloads: `payloads/Linux.txt` (added shell-jail section)
- Script: `scripts/ssh_interactive_shell.py` (new, generic interactive-SSH prompt-loop solver)
- Notes: `notes/patterns.md`, `notes/lessons_learned.md`

### References
- picoCTF 2023 Special (General Skills, Medium): https://play.picoctf.org/practice/challenge/389
- PayloadsAllTheThings - Command Injection / shell bypasses: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
