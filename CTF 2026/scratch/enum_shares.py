"""
Enumerate shares via SMB2 NetShareEnum over RPC.
"""
import sys
import struct
import binascii
import socket
from impacket.smbconnection import SMBConnection
from impacket.smb3 import SMB3
from impacket.smb3structs import (
    SMB2_SESSION_SETUP, SMB2SessionSetup, SMB2Packet,
    SMB2_NEGOTIATE_SIGNING_ENABLED
)
from impacket import ntlm
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp

TARGET = "10.181.33.90"
PORT = 445

print(f"--- Share enum via NTLMSSP + NetShareEnum on {TARGET}:{PORT} ---")

# Use impacket to do negotiate, session setup, then tree connect
smb = SMBConnection(TARGET, TARGET, sess_port=445)
smb_server = smb.getSMBServer()
print(f"  Initial dialect: {smb.getDialect():#x}")
smb_server._Connection['Dialect'] = 0x0302  # use 3.0.2

# Now do raw session setup with NTLMSSP_NEGOTIATE
sessionSetup = SMB2SessionSetup()
sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED
sessionSetup['Flags'] = 0

blob = SPNEGO_NegTokenInit()
blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
auth = ntlm.getNTLMSSPType1(b'sheryllguay', '', False)
blob['MechToken'] = auth.getData()

sessionSetup['SecurityBufferLength'] = len(blob)
sessionSetup['Buffer'] = blob.getData()

packet = SMB2Packet()
packet['Command'] = SMB2_SESSION_SETUP
packet['Data'] = sessionSetup
smb_server._Session['PreauthIntegrityHashValue'] = smb_server._Connection['PreauthIntegrityHashValue']

packetID = smb_server.sendSMB(packet)
ans = smb_server.recvSMB(packetID)
print(f"  SessionID: 0x{ans['SessionID']:016x}")
print(f"  Status: 0x{ans['Status']:08x}")

if ans['Status'] == 0xC0000016:
    # Got NTLMSSP challenge, now send NTLMSSP_AUTH with anonymous
    from impacket.smb3structs import SMB2SessionSetup_Response
    sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
    session_id = ans['SessionID']
    smb_server._Session['SessionID'] = session_id
    respToken = SPNEGO_NegTokenResp(sessionSetupResponse['Buffer'])
    ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])

    # Generate NTLMSSP_AUTH (anonymous) - this will fail since we don't have creds
    # But we can try with a guest auth or empty
    print(f"  Got NTLMSSP challenge, attempting anonymous auth...")

    # Try to do NetShareEnum via named pipe without auth - won't work
    # We need a successful login first

    # Try guest login
    try:
        # Make a new connection
        smb2 = SMBConnection(TARGET, TARGET, sess_port=445)
        smb2_server = smb2.getSMBServer()
        smb2_server._Connection['Dialect'] = 0x0302
        smb2.login('guest', '', '', '', '')
        print(f"  Guest login succeeded")
        try:
            shares = smb2.listShares()
            print(f"  Shares ({len(shares)}):")
            for s in shares:
                print(f"    {s['shi1_netname'][:-1]!r}")
        except Exception as e:
            print(f"  listShares err: {e}")
        smb2.logoff()
    except Exception as e:
        print(f"  Guest login ERR: {e}")

    # Try with credentials smb:smb
    for u, p in [('', ''), ('guest', 'guest'), ('smb', 'smb'), ('admin', ''), ('Administrator', '')]:
        try:
            print(f"  Trying {u!r}:{p!r}...")
            smb3 = SMBConnection(TARGET, TARGET, sess_port=445)
            smb3.login(u, p, '', '', '')
            print(f"    Success! Listing shares...")
            shares = smb3.listShares()
            for s in shares:
                print(f"      {s['shi1_netname'][:-1]!r}")
            smb3.logoff()
        except Exception as e:
            print(f"    Failed: {str(e)[:60]}")
