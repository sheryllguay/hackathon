"""
Use impacket to perform negotiate + session setup to elicit NTLMSSP challenge.
"""
import sys
import socket
import struct
import binascii
from impacket.smbconnection import SMBConnection
from impacket.ntlm import NTLMAuthChallenge

print(f"--- Impacket low-level session setup ---")
TARGET = "10.181.33.90"

smb = SMBConnection(TARGET, TARGET, sess_port=445)
print(f"  Connected. Current dialect: {smb.getDialect()!r}")
print(f"  Server OS: {smb.getServerOS()!r}")
print(f"  Server Name: {smb.getServerName()!r}")
print(f"  Remote Host: {smb.getRemoteHost()!r}")
# Print all attributes
for attr in dir(smb):
    if not attr.startswith('_') and ('Server' in attr or 'get' in attr.lower() or 'info' in attr.lower()):
        try:
            v = getattr(smb, attr)
            if callable(v):
                r = v()
            else:
                r = v
            print(f"  {attr}: {r!r}")
        except Exception as e:
            print(f"  {attr}: ERR {e}")

# The login() call needs credentials. But maybe we can call lower-level methods.
# Try _SMBConnection's request method
# First, send SessionSetup with NTLMSSP_NEGOTIATE
# Actually, login("", "") failed with STATUS_ACCESS_DENIED.
# So we can't get to session setup.

# Let me try a NetBIOS session over port 139 - sometimes it allows null sessions where 445 doesn't
import time
print()
print("--- Trying net view / net session over 139 ---")
try:
    smb2 = SMBConnection(TARGET, TARGET, sess_port=139)
    print(f"  Connected via 139, dialect={smb2.getDialect()!r}")
    smb2.login("", "")
    print("  Login OK")
except Exception as e:
    print(f"  ERR: {e}")
