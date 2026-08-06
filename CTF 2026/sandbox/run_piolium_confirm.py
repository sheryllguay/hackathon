"""Run /piolium-confirm in an interactive pi session via pexpect on Windows."""
import sys
import os
import time

# On Windows, pexpect.popen_spawn is the right tool
from pexpect.popen_spawn import PopenSpawn

LAUNCHER = r"C:\Users\User\.pi\agent\npm\node_modules\@vigolium\piolium\bin\piolium.mjs"
TARGET_DIR = r"C:\Users\User\Downloads\CTF 2026\sandbox\xVuln-main"
URL = "http://localhost:4443"
LOG = r"C:\Users\User\Downloads\CTF 2026\sandbox\piolium-confirm-interactive.log"

os.chdir(TARGET_DIR)

# Build the command — use winpty for true TTY behavior
cmd = f'winpty -Xallow-non-tty -Xplain node "{LAUNCHER}"'

print(f"[*] Launching: {cmd}")
print(f"[*] CWD: {TARGET_DIR}")
print(f"[*] Log: {LOG}")

# Spawn with PopenSpawn (Windows-compatible)
child = PopenSpawn(cmd, encoding="utf-8", timeout=900, maxread=200000, searchwindowsize=200000)

# Open the log file
logf = open(LOG, "w", encoding="utf-8")

# Read initial output until pi is ready
print("[*] Waiting for pi to initialize...")
buf = ""
start = time.time()
initialized = False
while time.time() - start < 90:
    try:
        chunk = child.read_nonblocking(size=4096, timeout=5).decode("utf-8", errors="replace")
        buf += chunk
        logf.write(chunk)
        logf.flush()
        # Look for pi's ready signal
        if "ctrl+o" in buf.lower() or "thinking:" in buf.lower() or "model:" in buf.lower() or len(buf) > 2000:
            print(f"[+] Pi initialized (buffer: {len(buf)} bytes)")
            initialized = True
            break
    except Exception as e:
        if "Timeout" in str(type(e).__name__):
            if len(buf) > 500:
                print(f"[+] Pi likely initialized (buffer: {len(buf)} bytes)")
                initialized = True
                break
            continue
        break

if not initialized:
    print(f"[!] No clear init signal, proceeding anyway (buffer: {len(buf)} bytes)")

# Give it a moment to fully render
time.sleep(3)

# Send the slash command via stdin
slash_cmd = f"/piolium-confirm . --fresh {URL}\n"
print(f"[*] Sending: {slash_cmd.strip()}")
child.sendline(slash_cmd)

# Now wait for the command to complete
print("[*] Waiting for confirm pass to complete...")
print("[*] (This may take 5-15 minutes for full live verification)")

last_size = 0
start = time.time()
timeout_s = 900
done = False
while time.time() - start < timeout_s and not done:
    try:
        chunk = child.read_nonblocking(size=8192, timeout=15).decode("utf-8", errors="replace")
        logf.write(chunk)
        logf.flush()
        # Check for completion signals
        if "Confirm pass complete" in chunk or "confirm complete" in chunk.lower() or "results written" in chunk.lower():
            print(f"[+] Confirm pass complete signal detected")
            done = True
    except Exception as e:
        err_name = type(e).__name__
        if "Timeout" in err_name:
            current_size = os.path.getsize(LOG)
            if current_size != last_size:
                last_size = current_size
                elapsed = int(time.time() - start)
                print(f"  [{elapsed}s] Still running... log: {current_size} bytes")
            # Check if process is still alive
            if child.proc.poll() is not None:
                print(f"[!] Process exited (code: {child.proc.returncode})")
                done = True
        else:
            print(f"[!] Error: {e}")
            break

# Final drain
try:
    remaining = child.read_nonblocking(size=200000, timeout=5).decode("utf-8", errors="replace")
    logf.write(remaining)
    logf.flush()
except:
    pass

logf.close()
try:
    child.close()
except:
    pass

print(f"\n[*] Done. Log: {LOG}")
print(f"[*] Log size: {os.path.getsize(LOG)} bytes")

# Show last 100 lines of log
print("\n=== Last 100 lines of log ===")
with open(LOG, "r", encoding="utf-8", errors="replace") as f:
    lines = f.readlines()
    for line in lines[-100:]:
        print(line.rstrip())
