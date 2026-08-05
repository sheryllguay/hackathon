# Bash / Shell Jail Bypass (Filtered Shell)

## Purpose
Defeat a restricted or filtered shell (aka shell jail / spellcheck shell / rbash-style filter) that blocks, autocorrects, or sanitizes certain words, so you can still read files or execute commands.

## Decision Tree
```
Login / remote shell that mangles or rejects input (autocorrects, bans words, filters).
 ├── Does it only transform SIMPLE words, but pass metacharacters/compound syntax through?
 │    └── YES -> classic filter bypass; drive real bash with non-word constructs (below).
 │         └── Does a common word get autocorrected (ls->Is, whoami->Whom, cat->Cap)? 
 │              └── Autocorrection is per-WORD and strips punctuation -> "spell it via syntax" won't work;
 │                   you MUST wrap the whole thing in an opaque shell construct instead.
 └── Test raw shell syntax BEFORE assuming input is blocked:
     └── `$(cmd)` substitution, `${var=val}`, `((cmd))`, `< redirect`, glob `*`, `&`, pipes.
          └── If any run the real command -> you have an execution primitive via that construct.
```

## Recon Checklist
- [ ] Identify WHAT is filtered: try a banned word (`ls`, `cat`, `whoami`, `sh`, `bash`) and observe the mangled output. The mangling tells you the rule (capitalize? strip punctuation? autocorrect?).
- [ ] If it "autocorrects" (e.g. `ls` -> `Is`), punctuation-injection (`l\s`, `l''s`, `"ls"`) is USELESS if the filter strips non-alpha first. Don't waste time on it.
- [ ] Test which compound constructs pass through: `$(...)`, `${...}`, `((...))`, `<`, `>`, `&`, `;`, `|`, `*`.
- [ ] Locate the target: usually the flag sits in the home dir; glob the directory name first (`*`).
- [ ] `ssh`-mediated jails are interactive: automate the prompt-loop with paramiko (see script section).

## Reusable Commands / Payloads
```bash
# Glob-reveal directory / files (filter-safe, no banned word)
*                                            # expands -> tries to run the dir name -> tells you the dir

# Read flag via redirection + glob (1 = harmless stdin-open error)
<1&cat blargh/*                             # cleanest one-liner

# Read/write/exe via parameter-expansion default-value (opaque to per-word filter)
${parameter=ls}                             # runs `ls` -> finds the dir
${parameter=ls blargh}                      # runs `ls blargh` -> finds the file
${parameter=cat < blargh/flag.txt}          # assign-then-... reads flag

# Same idea with command-grouping construct
((cat)) < blargh/flag.txt                   # (( )) is not seen as a plain word
```

## Exploitation Workflow
1. Determine the filter rule by feeding common words and reading the mangled echo.
2. If punctuation is stripped, stop trying to "spell" a command with quotes/backslashes.
3. Wrap the whole action in an opaque shell construct the filter doesn't tokenize:
   - `$(...)`  - command substitution
   - `${var=...}` - parameter-expansion default/assign (executes assignment context)
   - `((...))`  - arithmetic/command grouping
   - `<`,`>`,`&`,`;`,`|`,`*` - redirections/globs usually survive word filters
4. Use `*`/glob to discover unknown dir/file names instead of spelling them.
5. Redirection `< file` avoids needing a readable command name for the file.
6. Prefer `cmd *` (glob over the whole dir) so you never type the exact filename.

## Common Mistakes
- Assuming you can bypass a word autocorrector by inserting punctuation (`c""at`). If the filter strips all non-alpha before checking, the words still collapse and get corrected.
- Forgetting `*` glob can reveal unknown directory/file names without spelling a banned word.
- Neglecting that redirection (`< file`) is a separate token that survives even when the command word gets mangled.
- Over-typing command names; wrap in `$(...)`/`${...}`/`((...))` so the filter never sees a plain word.

## CTF Tips
- Interactive jails over SSH need a recv->send loop; use paramiko `invoke_shell` and feed each payload, then read until the prompt marker.
- Applied to: picoCTF 2023 **Special** (`<1&cat blargh/*` reads the flag from a home-dir `blargh/flag.txt`).
- This is a category of its own (filtered/jail shell), distinct from SudoAbuse, even though both are Linux shell tasks.

## References
- PayloadsAllTheThings - Command Injection / shell bypasses: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- GTFOBins (for filtered binaries): https://gtfobins.github.io/
