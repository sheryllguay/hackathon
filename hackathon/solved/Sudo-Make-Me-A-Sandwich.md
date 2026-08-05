# SUDO MAKE ME A SANDWICH (picoCTF 2026) - Writeup

## Category: General Skills / Linux Privilege Escalation (Sudo Misconfiguration)
## Difficulty: Easy

### Challenge Description
> Can you read the flag? I think you can!

SSH into a box as `ctf-player` (password provided per instance) and read `flag.txt`, which is owned by root (`r--r-----`) in the player's home directory. Hint: "What is sudo? How do you know what permission you have?"

### Recon
1. Connect via SSH and enumerate the user:
   ```bash
   ssh -p <PORT> ctf-player@green-hill.picoctf.net   # password from challenge
   id; whoami
   ```
2. Check sudo permissions (this is the key move):
   ```bash
   sudo -l
   ```
   Output: `(ALL) NOPASSWD: /bin/emacs` -> we can run emacs as root without a password.
3. `ls -la` shows `flag.txt` is `-r--r-----` owned by `root` -> unreadable by our user, readable by root.

### Exploitation
1. Run emacs as root in **batch mode** and evaluate Elisp that reads the file and prints it:
   ```bash
   sudo /bin/emacs --batch -q -eval '(princ (with-temp-buffer (insert-file-contents "/home/ctf-player/flag.txt") (buffer-string)))'
   ```
2. The `picoCTF{...}` flag is printed to stdout.
   - Elisp breakdown: `with-temp-buffer` creates a scratch buffer, `insert-file-contents` loads the file (as root), `buffer-string` extracts the text, `princ` prints it.
3. Alternative interactive routes: `sudo emacs` then `M-x shell` / `M-x eshell` for a root shell, or `C-x C-f` to open the flag file.

### Flag
```
picoCTF{ju57_5ud0_17_d8e1a280}
```
*(Instance-specific.)*

### Why It Worked
`sudo` grants `ctf-player` the ability to run `/bin/emacs` as root with no password. Emacs is a full scripting environment: even without its interactive UI it can execute arbitrary Elisp (`--batch -eval`), including reading any file as the root user. An "editor" granted via sudo is therefore equivalent to root shell access. This is the classic [GTFOBins](https://gtfobins.github.io/) pattern: many utilities (emacs, vi, less, more, find, awk, python, etc.) expose a file-read or shell-escape primitive when run with elevated privileges.

### Mitigation
- Do not grant `NOPASSWD` sudo to binaries that can read files or spawn shells; if required, use `Defaults` restrictions (`env_reset`, `secure_path`, disabled escapes) or a dedicated wrapper script.
- Grant sudo for the *specific* action needed, not a general-purpose binary.
- Keep the flag out of any directory the lower-priv user can reach, and audit `sudo -l` output regularly.

### Lessons Learned
- **Always run `sudo -l` first** on any box you get a shell on — misconfigured sudo is the fastest path to root.
- A `sudo` binary you don't recognize is an attack surface: check GTFOBins for file-read/shell primitives before anything else.
- Interactive editors (emacs/vi/less) can be driven non-interactively (`--batch -eval`, `-c`, pipe to `less`) to script the exploit.
- For SSH-based automation on Windows/CI, use `paramiko` (sshpass does not exist on Windows): `exec_command` + reading `stdout` avoids password prompts.

### Reusable Artifacts
- Skill: `skills/linux/SudoAbuse.md`
- Script: `scripts/ssh_cmd.py` (paramiko SSH command runner for password auth)
- Payloads: `payloads/Linux.txt` (GTFOBins sudo abuse section)

### References
- GTFOBins (binary abuse database): https://gtfobins.github.io/
- picoCTF hint topics: what is sudo, how to list your privileges (`sudo -l`)
