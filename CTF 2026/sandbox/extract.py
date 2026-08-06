import tarfile
import os
import sys

target_dir = "C:/Users/User/Downloads/CTF 2026/sandbox"
archive = os.path.join(target_dir, "xVuln.tar.gz")
outdir = os.path.join(target_dir, "xVuln-main")

# Read members from the tarball and filter suspicious ones
safe_members = []
skipped = []
with tarfile.open(archive, "r:gz") as tf:
    for m in tf.getmembers():
        # Reject absolute paths and path traversal segments
        if m.name.startswith("/"):
            skipped.append((m.name, "absolute path"))
            continue
        if ".." in m.name.split("/"):
            skipped.append((m.name, "path traversal segment"))
            continue
        if m.name.startswith("xVuln-main/") and ("..\\" in m.name or "..\\\\" in m.name):
            skipped.append((m.name, "backslash traversal"))
            continue
        # Normalize
        if "\\" in m.name:
            # tar came from Windows; convert backslashes to forward
            new_name = m.name.replace("\\", "/")
            if ".." in new_name.split("/"):
                skipped.append((m.name, "path traversal after normalize"))
                continue
            m.name = new_name
        safe_members.append(m)

print(f"Total: {len(safe_members) + len(skipped)}")
print(f"Safe: {len(safe_members)}")
print(f"Skipped: {len(skipped)}")
for n, why in skipped:
    print(f"  SKIP ({why}): {n}")

# Extract safe members
os.makedirs(outdir, exist_ok=True)
with tarfile.open(archive, "r:gz") as tf:
    for m in safe_members:
        try:
            tf.extract(m, target_dir, set_attrs=False)
        except Exception as e:
            print(f"  EXTRACT ERR: {m.name}: {e}")

# Also extract the suspicious ones into a quarantined subdir for piolium to see
qdir = os.path.join(target_dir, "xVuln-quarantine")
os.makedirs(qdir, exist_ok=True)
with tarfile.open(archive, "r:gz") as tf:
    for m, why in skipped:
        try:
            # Sanitize the name for quarantine
            safe_name = m.name.replace("\\", "_").replace("..", "_dotdot_").replace("/", "_").lstrip("_")
            m.name = safe_name
            tf.extract(m, qdir, set_attrs=False)
        except Exception as e:
            print(f"  QUAR EXTRACT ERR: {m}: {e}")

# List what was extracted
print("\n--- Extracted (xVuln-main) ---")
for root, dirs, files in os.walk(outdir):
    for f in files:
        path = os.path.join(root, f)
        rel = os.path.relpath(path, outdir)
        print(f"  {rel}")
print(f"\n--- Quarantined (xVuln-quarantine) ---")
if os.path.exists(qdir):
    for root, dirs, files in os.walk(qdir):
        for f in files:
            path = os.path.join(root, f)
            rel = os.path.relpath(path, qdir)
            print(f"  {rel}")
