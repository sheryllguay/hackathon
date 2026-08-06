"""
Use impacket to do raw session setup with NTLMSSP_NEGOTIATE to get NTLMSSP_CHALLENGE.
"""
import sys
import socket
import struct
import binascii
from impacket.smbconnection import SMBConnection
from impacket import ntlm, smb3
from impacket.smb3 import SMB3
from impacket.smbconnection import SMBConnection as SMBConnClass
from impacket import smb as smb_module

print(f"--- Impacket raw session setup probe ---")
TARGET = "10.181.33.90"

smb = SMBConnection(TARGET, TARGET, sess_port=445)
print(f"  Dialect: {smb.getDialect():#x}")
print(f"  Server: {smb.getServerName()!r}")
print(f"  SMB Server type: {type(smb.getSMBServer()).__name__}")
smb_server = smb.getSMBServer()

# Build NTLMSSP_NEGOTIATE message
from impacket.ntlm import NTLMAuthNegotiate
auth = NTLMAuthNegotiate()
auth['flags'] = 0x00088237
negotiate = auth.getData()
print(f"  NTLMSSP_NEGOTIATE: {len(negotiate)} bytes")
print(f"    {binascii.hexlify(negotiate).decode()[:200]}")

# Try SMB2 session setup
# impacket's session setup is via smb.login() but maybe we can use lower-level
# The SMB3 class has a method for this
print(f"  Methods on SMB3: {[m for m in dir(smb_server) if not m.startswith('_')][:30]}")
