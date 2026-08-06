"""Run /piolium-confirm in an interactive pi session via pexpect on Windows."""
import sys
import os
import time
import subprocess

# On Windows, use PopenSpawn
from pexpect.popen_spawn import PopenSpawn

LAUNCHER = r"C:\Users\User\.pi\agent\npm\node_modules\@vigolium\piolium\bin\piolium.mjs"
TARGET_DIR = r"C:\Users\User\Downloads\CTF 2026\sandbox\xVuln-main"
URL = "http://localhost:4443"
LOG = r"C:\Users\User\Downloads\CTF 2026\sandbox\piolium-confirm-interactive.log"

os.chdir(TARGET_DIR)

# Use winpty for true TTY
cmd = f'winpty -Xallow-non-tty -Xplain node "{LAUNCHER}"'

print(f"[*] Launching: {cmd}")
print(f"[*] CWD: {TARGET_DIR}")
print(f"[*] Log: {LOG}")

# PopenSpawn doesn't really give us a TTY, but it lets us send input
# The key insight: the slash command needs to be the first thing pi sees
# We need to launch pi with the slash command as an argument, or use --session-dir
# Actually, pi's slash commands only work in interactive mode with proper TTY

# Alternative: use subprocess with stdin pipe
print("[*] Using subprocess approach (no TTY)...")

proc = subprocess.Popen(
    ["node", LAUNCHER],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    encoding="utf-8",
    errors="replace",
    bufsize=1
)

logf = open(LOG, "w", encoding="utf-8")

# Read initial output
print("[*] Reading initial output...")
time.sleep(3)
import select
initial = ""
while True:
    ready, _, _ = select.select([proc.stdout], [], [], 1.0)
    if ready:
        chunk = os.read(proc.stdout.fileno(), 4096).decode("utf-8", errors="replace")
        initial += chunk
        logf.write(chunk)
        logf.flush()
        if len(initial) > 1000 or "model:" in initial.lower():
            break
    else:
        if len(initial) > 500:
            break
        if time.time() - start_time > 30:
            break
        continue

start_time = time.time()
print(f"[+] Initial output: {len(initial)} bytes")
print(f"[+] First 500 chars: {initial[:500]}")

# Send the slash command
slash_cmd = f"/piolium-confirm . --fresh {URL}\n"
print(f"[*] Sending: {slash_cmd.strip()}")
proc.stdin.write(slash_cmd)
proc.stdin.flush()

# Now read output until done
print("[*] Waiting for confirm pass to complete...")
last_size = 0
start = time.time()
timeout_s = 900
done = False

while time.time() - start < timeout_s and not done:
    ready, _, _ = select.select([proc.stdout], [], [], 10.0)
    if ready:
        try:
            chunk = os.read(proc.stdout.fileno(), 8192).decode("utf-8", errors="replace")
            logf.write(chunk)
            logf.flush()
            # Check for completion
            if any(s in chunk for s in ["Confirm pass complete", "confirm complete", "results written", "audit complete"]):
                print(f"[+] Completion signal detected")
                done = True
        except Exception as e:
            print(f"[!] Read error: {e}")
            break
    else:
        # Check process
        ret = proc.poll()
        if ret is not None:
            print(f"[!] Process exited (code: {ret})")
            done = True
        else:
            current_size = os.path.getsize(LOG)
            if current_size != last_size:
                last_size = current_size
                elapsed = int(time.time() - start)
                print(f"  [{elapsed}s] Still running... log: {current_size} bytes")

# Final drain
try:
    remaining, _ = proc.communicate(timeout=5)
    if remaining:
        logf.write(remaining)
        logf.flush()
except:
    pass

logf.close()
try:
    proc.terminate()
except:
    pass

print(f"\n[*] Done. Log: {LOG}")
print(f"[*] Log size: {os.path.getsize(LOG)} bytes")
