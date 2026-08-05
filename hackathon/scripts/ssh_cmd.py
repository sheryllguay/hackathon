#!/usr/bin/env python3
"""Run commands over SSH with password auth (no sshpass needed on Windows).

Useful for picoCTF-style boxes where `ssh` prompts interactively for a
password and sshpass is unavailable. Use paramiko + exec_command and read
stdout to avoid interactive prompts entirely.

Usage:
    python ssh_cmd.py <host> <port> <user> <password> [cmd1] [cmd2] ...

Example:
    python ssh_cmd.py green-hill.picoctf.net 59115 ctf-player d401a6db "id" "sudo -l" "cat /flag.txt"
"""
import getpass
import sys

try:
    import paramiko
except ImportError:
    print("[-] paramiko not installed. Run: pip install paramiko")
    sys.exit(1)


def run(client, cmd):
    stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    print(f"== $ {cmd} ==")
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)

    host, port, user, password = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    cmds = sys.argv[5:] or ["id", "sudo -l", "ls -la"]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"[*] connecting to {user}@{host}:{port}")
    client.connect(host, port=port, username=user, password=password, timeout=30)

    for cmd in cmds:
        run(client, cmd)

    client.close()


if __name__ == "__main__":
    main()
