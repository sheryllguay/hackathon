"""
Use impacket SMB3 internals to do session setup, get NTLMSSP challenge.
"""
import sys
import struct
import binascii
from impacket.smbconnection import SMBConnection
from impacket.smb3 import SMB3
from impacket import ntlm
from impacket.smb3structs import (
    SMB2_SESSION_SETUP, SMB2Negotiate_Response, SMB2SessionSetup_Response,
    SMB2_NEGOTIATE_SIGNING_ENABLED, SMB2_NEGOTIATE_SIGNING_REQUIRED,
    SMB2_DIALECT_311
)
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

print(f"--- Impacket low-level NTLMSSP challenge probe ---")
TARGET = "10.181.33.90"

smb = SMBConnection(TARGET, TARGET, sess_port=445)
smb_server = smb.getSMBServer()
print(f"  Dialect: {smb.getDialect():#x}")

# Force dialect to 0x0302 to avoid 3.1.1 issues
print(f"  Setting dialect to 0x0302")
smb_server._Connection['Dialect'] = 0x0302

# Now build session setup with NTLMSSP_NEGOTIATE
from impacket.smb3structs import SMB2SessionSetup

sessionSetup = SMB2SessionSetup()
sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED
sessionSetup['Flags'] = 0

# Build SPNEGO with NTLMSSP_NEGOTIATE
blob = SPNEGO_NegTokenInit()
blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
auth = ntlm.getNTLMSSPType1(b'sheryllguay', '', smb_server._Connection.get('RequireSigning', False))
blob['MechToken'] = auth.getData()

sessionSetup['SecurityBufferLength'] = len(blob)
sessionSetup['Buffer'] = blob.getData()

from impacket.smb3structs import SMB2Packet
packet = SMB2Packet()
packet['Command'] = SMB2_SESSION_SETUP
packet['Data'] = sessionSetup
smb_server._Session['PreauthIntegrityHashValue'] = smb_server._Connection['PreauthIntegrityHashValue']

print(f"  Sending session setup (NTLMSSP_NEGOTIATE)...")
packetID = smb_server.sendSMB(packet)
ans = smb_server.recvSMB(packetID)
print(f"  Got response, valid? {ans.isValidAnswer(0xC0000016)}")  # STATUS_MORE_PROCESSING_REQUIRED
print(f"  Status: 0x{ans['Status']:08x}")
print(f"  Flags: 0x{ans['Flags']:08x}")
print(f"  SessionID: 0x{ans['SessionID']:016x}")

if ans['Status'] == 0xC0000016:  # STATUS_MORE_PROCESSING_REQUIRED
    sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
    print(f"  SessionFlags: 0x{sessionSetupResponse['SessionFlags']:04x}")
    buf = sessionSetupResponse['Buffer']
    print(f"  Buffer ({len(buf)} bytes): {binascii.hexlify(buf).decode()}")
    # Parse the SPNEGO response
    respToken = SPNEGO_NegTokenResp(buf)
    ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
    # manual print to avoid dict access issues
    print(f"  NTLMSSP Challenge fields: {dir(ntlmChallenge)}")
    print(f"  MessageType: {ntlmChallenge['MessageType']}")
    print(f"  Flags: 0x{ntlmChallenge['Flags']:08x}")
    if ntlmChallenge['TargetInfoFields_len'] > 0:
        av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']])
        for av_type, (key, val) in av_pairs.items():
            try:
                txt = val.decode('utf-16-le', errors='replace')
            except:
                txt = val.hex() if val else ''
            print(f"  AV {av_type} ({key}): {txt!r}")
    if ntlmChallenge['TargetNameFields']:
        print(f"  TargetName (NB domain): {ntlmChallenge['TargetName'].decode('utf-16-le', errors='replace')!r}")
    # OS Version
    if hasattr(ntlmChallenge, 'Version') or 'Version' in ntlmChallenge:
        v = ntlmChallenge['Version']
        if v and len(v) >= 8:
            major, minor = v[0], v[1]
            build = struct.unpack('<H', v[2:4])[0]
            rev = v[7]
            print(f"  OS Version: Windows {major}.{minor} build {build} rev {rev}")
    # Save raw for later parsing
    with open('scratch/ntlmssp_challenge.bin', 'wb') as f:
        f.write(respToken['ResponseToken'])
    print(f"  Saved {len(respToken['ResponseToken'])} bytes to scratch/ntlmssp_challenge.bin")
else:
    print(f"  Unexpected status: 0x{ans['Status']:08x}")
    print(f"  Data: {binascii.hexlify(ans['Data']).decode()[:200]}")
