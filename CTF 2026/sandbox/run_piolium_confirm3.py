"""Run /piolium-confirm using winpty for a real TTY."""
import subprocess
import os
import time
import sys

LAUNCHER = r"C:\Users\User\.pi\agent\npm\node_modules\@vigolium\piolium\bin\piolium.mjs"
TARGET_DIR = r"C:\Users\User\Downloads\CTF 2026\sandbox\xVuln-main"
URL = "http://localhost:4443"
LOG = r"C:\Users\User\Downloads\CTF 2026\sandbox\piolium-confirm-winpty.log"

os.chdir(TARGET_DIR)

# winpty creates a real Windows console (ConPTY) for the child process
# This makes Node think it has a TTY, which enables interactive features
cmd = f'winpty node "{LAUNCHER}"'

print(f"[*] Launching: {cmd}")
print(f"[*] CWD: {TARGET_DIR}")
print(f"[*] Log: {LOG}")

with open(LOG, "w", encoding="utf-8") as logf:
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=0
    )

    print("[*] Waiting for pi to initialize (3s)...")
    time.sleep(3)

    # Send the slash command
    slash_cmd = f"/piolium-confirm . --fresh {URL}\n"
    print(f"[*] Sending: {slash_cmd.strip()}")
    try:
        proc.stdin.write(slash_cmd)
        proc.stdin.flush()
    except Exception as e:
        print(f"[!] Write error: {e}")

    print("[*] Waiting for confirm pass to complete (max 15 min)...")
    start = time.time()
    timeout_s = 900
    done = False
    last_report = 0

    while time.time() - start < timeout_s and not done:
        time.sleep(5)
        ret = proc.poll()
        elapsed = int(time.time() - start)
        if ret is not None:
            print(f"[!] Process exited (code: {ret})")
            done = True
            break
        # Periodic progress report
        if elapsed - last_report >= 30:
            last_report = elapsed
            print(f"  [{elapsed}s] Still running... log: {os.path.getsize(LOG)} bytes")

    # Read remaining output
    try:
        proc.stdin.close()
    except:
        pass

    try:
        remaining = proc.stdout.read()
        if remaining:
            logf.write(remaining)
            logf.flush()
    except:
        pass

    try:
        proc.terminate()
    except:
        pass

print(f"\n[*] Done. Log: {LOG}")
print(f"[*] Log size: {os.path.getsize(LOG)} bytes")

# Show last lines
print("\n=== Last 80 lines of log ===")
with open(LOG, "r", encoding="utf-8", errors="replace") as f:
    content = f.read()
    # Strip ANSI escape codes for readability
    import re
    content = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', content)
    content = re.sub(r'\x1b\][^\x07]*\x07', '', content)
    lines = content.split('\n')
    for line in lines[-80:]:
        print(line)
