"""
Use impacket to do read-only SMB recon.
- List shares (anonymous/null session)
- Get OS version
- Get server info
"""
import sys
import socket
from impacket.smbconnection import SMBConnection
from impacket import version

print(f"impacket version: {version.BANNER.split(chr(10))[0]}")
TARGET = "10.181.33.90"

# Try anonymous session
print(f"--- Trying anonymous SMB session to {TARGET} ---")
try:
    smb = SMBConnection(TARGET, TARGET, sess_port=445)
    smb.login("", "")  # anonymous / null
    print(f"  Login OK (anonymous)")
    print(f"  getServerOS(): {smb.getServerOS()!r}")
    print(f"  getServerDN(): {smb.getServerDN()!r}")
    print(f"  getServerName(): {smb.getServerName()!r}")
    print(f"  getRemoteName(): {smb.getRemoteName()!r}")
    print(f"  getDialect(): {smb.getDialect()!r}")
    try:
        shares = smb.listShares()
        print(f"  Shares ({len(shares)}):")
        for s in shares:
            print(f"    {s['shi1_netname'][:-1]!r} type=0x{s['shi1_type']:x} comment={s['shi1_remark'][:-1] if s['shi1_remark'] else ''!r}")
    except Exception as e:
        print(f"  listShares err: {e}")
    smb.logoff()
except Exception as e:
    print(f"  ERR: {e}")

# Also try on port 139
print()
print(f"--- Trying anonymous SMB session via netbios-ssn (port 139) to {TARGET} ---")
try:
    smb = SMBConnection(TARGET, TARGET, sess_port=139)
    smb.login("", "")
    print(f"  Login OK (anonymous)")
    print(f"  getServerOS(): {smb.getServerOS()!r}")
    try:
        shares = smb.listShares()
        print(f"  Shares ({len(shares)}):")
        for s in shares:
            print(f"    {s['shi1_netname'][:-1]!r}")
    except Exception as e:
        print(f"  listShares err: {e}")
    smb.logoff()
except Exception as e:
    print(f"  ERR: {e}")
