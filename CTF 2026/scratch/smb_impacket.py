from impacket.smbconnection import SMBConnection
from impacket.smb import SMB
import traceback

HOST = '10.181.33.90'

print('=== impacket SMB1 (NetBIOS 139) ===')
try:
    s = SMB(HOST, HOST, timeout=6)
    s.neg_session()
    print('SMB1 negotiate succeeded')
    print('  Native OS:', s.get_native_os())
    print('  Native LanMan:', s.get_native_lm())
    print('  Server name:', s.get_server_name())
    print('  Domain:', s.get_domain())
    print('  Signing required:', s.is_signing_required())
    print('  Signing enabled:', s.is_signing_active())
    s.close()
except Exception as e:
    print('SMB1 ERR:', type(e).__name__, e)
    traceback.print_exc()

print()
print('=== impacket SMB3 (445) ===')
# Use lowercase dialect names
import impacket.smbconnection as smbmod
print('SMB3 enum:', list(smbmod.SMB2_DIALECT))
for d in ['SMB_3_1_1', 'SMB_3_0', 'SMB_2_1', 'SMB_2_0_2']:
    try:
        smb = SMBConnection(HOST, HOST, sess_port=445, timeout=6, preferredDialect=d)
        # Get server info without auth
        print(f'  {d} -- no auth required? {smb._SMBConnection__disconnected}')
        print(f'    Server name:', smb.getServerName())
        print(f'    Server domain:', smb.getServerDomain())
        print(f'    Server OS:', smb.getServerOS())
        print(f'    Server DNS:', smb.getServerDNSDomainName())
        print(f'    Signing required:', smb.isSigningRequired())
    except Exception as e:
        print(f'  {d} ERR:', type(e).__name__, e)
    try:
        smb.close()
    except Exception:
        pass

print()
print('=== Try NULL session with no dialect preferred ===')
try:
    smb = SMBConnection(HOST, HOST, sess_port=445, timeout=6)
    smb.login('', '')
    print('OK (NULL user)')
    print('  Server name:', smb.getServerName())
    print('  Server domain:', smb.getServerDomain())
    print('  Server OS:', smb.getServerOS())
    print('  Server DNS:', smb.getServerDNSDomainName())
    # List shares
    try:
        for share in smb.listShares():
            name = share['shi1_netname'][:-1] if share['shi1_netname'] else ''
            print(f'  SHARE: {name!r:30s} type={share["shi1_type"]}')
    except Exception as e:
        print(f'  listShares ERR: {e}')
    smb.logoff()
except Exception as e:
    print('NULL user ERR:', type(e).__name__, e)
