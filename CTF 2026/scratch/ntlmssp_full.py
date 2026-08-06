"""
Final NTLMSSP probe - capture full challenge.
"""
import sys
import struct
import binascii
import socket
import datetime
from impacket.smbconnection import SMBConnection

TARGET = "10.181.33.90"
PORT = 445

print(f"--- NTLMSSP Challenge probe to {TARGET}:{PORT} ---")

# Force SMB2 dialect to 0x0302 to avoid 3.1.1 preauth issue
smb = SMBConnection(TARGET, TARGET, sess_port=445)
smb_server = smb.getSMBServer()
print(f"  Initial dialect: {smb.getDialect():#x}")
smb_server._Connection['Dialect'] = 0x0302  # use 3.0.2

# Now do raw session setup with NTLMSSP_NEGOTIATE
from impacket.smb3structs import (
    SMB2_SESSION_SETUP, SMB2SessionSetup, SMB2Packet,
    SMB2_NEGOTIATE_SIGNING_ENABLED
)
from impacket import ntlm
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp

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

if ans['Status'] == 0xC0000016:  # STATUS_MORE_PROCESSING_REQUIRED
    from impacket.smb3structs import SMB2SessionSetup_Response
    sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
    session_id = ans['SessionID']
    buf = sessionSetupResponse['Buffer']
    # Save to file
    with open('scratch/ntlmssp_response.bin', 'wb') as f:
        f.write(buf)
    print(f"  Saved {len(buf)} bytes to scratch/ntlmssp_response.bin")
    # Parse the SPNEGO response
    respToken = SPNEGO_NegTokenResp(buf)
    ntlm_data = respToken['ResponseToken']
    print(f"\n  === NTLMSSP Challenge Analysis ===")
    print(f"  NTLMSSP data: {len(ntlm_data)} bytes")
    print(f"  hex: {ntlm_data.hex()}")

    # Manual parse
    if ntlm_data[:8] == b'NTLMSSP\x00':
        print(f"  Signature OK")
        msg_type = struct.unpack('<I', ntlm_data[8:12])[0]
        print(f"  MessageType: {msg_type} (2=CHALLENGE)")
        domain_len, domain_max, domain_off = struct.unpack('<HHI', ntlm_data[12:20])
        flags = struct.unpack('<I', ntlm_data[20:24])[0]
        challenge = ntlm_data[24:32]
        reserved = ntlm_data[32:40]
        ti_len, ti_max, ti_off = struct.unpack('<HHI', ntlm_data[40:48])
        v = ntlm_data[48:56]
        major, minor = v[0], v[1]
        build = struct.unpack('<H', v[2:4])[0]
        rev = v[7]
        print(f"  OS Version: Windows {major}.{minor} build {build} rev {rev}")
        print(f"  Flags: 0x{flags:08x}")
        # Decode flags
        flag_names = [
            (0x00000001, "NTLMSSP_NEGOTIATE_UNICODE"),
            (0x00000002, "NTLMSSP_NEGOTIATE_OEM"),
            (0x00000004, "NTLMSSP_REQUEST_TARGET"),
            (0x00000008, "NTLMSSP_RESERVED1"),
            (0x00000010, "NTLMSSP_NEGOTIATE_SIGN"),
            (0x00000020, "NTLMSSP_NEGOTIATE_SEAL"),
            (0x00000040, "NTLMSSP_NEGOTIATE_DATAGRAM"),
            (0x00000080, "NTLMSSP_NEGOTIATE_LM_KEY"),
            (0x00000100, "NTLMSSP_RESERVED2"),
            (0x00000200, "NTLMSSP_NEGOTIATE_NTLM"),
            (0x00000400, "NTLMSSP_NEGOTIATE_NT_ONLY"),
            (0x00000800, "NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED"),
            (0x00001000, "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED"),
            (0x00002000, "NTLMSSP_NEGOTIATE_RESERVED3"),
            (0x00004000, "NTLMSSP_NEGOTIATE_00004000"),
            (0x00008000, "NTLMSSP_NEGOTIATE_ALWAYS_SIGN"),
            (0x00010000, "NTLMSSP_TARGET_TYPE_DOMAIN"),
            (0x00020000, "NTLMSSP_TARGET_TYPE_SERVER"),
            (0x00040000, "NTLMSSP_TARGET_TYPE_SHARE"),
            (0x00080000, "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY"),
            (0x00100000, "NTLMSSP_NEGOTIATE_IDENTIFY"),
            (0x00200000, "NTLMSSP_NEGOTIATE_00200000"),
            (0x00400000, "NTLMSSP_RESERVED4"),
            (0x00800000, "NTLMSSP_NEGOTIATE_TARGET_INFO"),
            (0x01000000, "NTLMSSP_NEGOTIATE_VERSION"),
            (0x02000000, "NTLMSSP_NEGOTIATE_02000000"),
            (0x04000000, "NTLMSSP_NEGOTIATE_04000000"),
            (0x08000000, "NTLMSSP_NEGOTIATE_08000000"),
            (0x10000000, "NTLMSSP_NEGOTIATE_10000000"),
            (0x20000000, "NTLMSSP_NEGOTIATE_128"),
            (0x40000000, "NTLMSSP_NEGOTIATE_KEY_EXCH"),
            (0x80000000, "NTLMSSP_NEGOTIATE_56"),
        ]
        for mask, name in flag_names:
            if flags & mask:
                print(f"    +{name}")
        # Server challenge
        print(f"  ServerChallenge: {challenge.hex()}")
        # TargetName (NB domain)
        if domain_len > 0:
            tn = ntlm_data[domain_off:domain_off+domain_len-2]
            print(f"  TargetName (NB): {tn.decode('utf-16-le')!r}")
        # TargetInfo AV pairs
        if ti_len > 0:
            ti = ntlm_data[ti_off:ti_off+ti_len]
            print(f"  TargetInfo ({ti_len} bytes):")
            i = 0
            while i + 4 <= len(ti):
                av_type = struct.unpack('<H', ti[i:i+2])[0]
                av_len = struct.unpack('<H', ti[i+2:i+4])[0]
                i += 4
                if av_type == 0:
                    break
                if i + av_len > len(ti):
                    break
                av_data = ti[i:i+av_len]
                i += av_len
                txt = av_data.decode('utf-16-le', errors='replace')
                av_names = {1: 'NbComputerName', 2: 'NbDomainName', 3: 'DnsComputerName',
                            4: 'DnsDomainName', 5: 'DnsTreeName', 6: 'Flags', 7: 'Timestamp'}
                if av_type == 7:  # Timestamp - 8 bytes little-endian
                    ts = struct.unpack('<Q', av_data)[0]
                    try:
                        ft_dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ts/10)
                        print(f"    AV {av_type} ({av_names.get(av_type, '?')}): {ft_dt} UTC (0x{ts:016x})")
                    except OverflowError:
                        print(f"    AV {av_type} ({av_names.get(av_type, '?')}): 0x{ts:016x}")
                else:
                    print(f"    AV {av_type} ({av_names.get(av_type, '?')}): {txt!r}")
else:
    print(f"  Unexpected status!")
    print(f"  Data: {ans['Data'].hex()}")

smb_server.close_session(session_id) if False else None
