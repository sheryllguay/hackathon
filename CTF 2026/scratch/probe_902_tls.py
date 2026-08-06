import socket, ssl, re

HOST = '10.181.33.90'

print('=== Port 902: try various TLS versions ===')
for tls_min, tls_max, name in [
    (ssl.TLSVersion.SSLv3, ssl.TLSVersion.TLSv1_2, 'SSL3-TLS1.2'),
    (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2, 'TLS1.0-1.2'),
    (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3, 'TLS1.2-1.3'),
    (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2, 'TLS1.1-1.2'),
    (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1, 'TLS1.0-1.1'),
]:
    try:
        s = socket.socket()
        s.settimeout(6)
        s.connect((HOST, 902))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_min
        ctx.maximum_version = tls_max
        try:
            ts = ctx.wrap_socket(s, server_hostname=HOST)
            print(f'  {name}: OK -- {ts.version()}, cipher={ts.cipher()[0]}')
            try:
                cert = ts.getpeercert()
                if cert:
                    print('    Subject:', dict((x[0][0], x[0][1]) for x in cert.get('subject', [])))
                    print('    Issuer :', dict((x[0][0], x[0][1]) for x in cert.get('issuer', [])))
                    print('    NotBefore:', cert.get('notBefore'))
                    print('    NotAfter :', cert.get('notAfter'))
                    print('    SANs:', [v for k, v in cert.get('subjectAltName', [])])
            except Exception as e:
                print('    cert parse err:', e)
            ts.close()
        except Exception as e:
            print(f'  {name}: TLS handshake ERR: {type(e).__name__} {e}')
            try: s.close()
            except: pass
    except Exception as e:
        print(f'  {name}: connect ERR: {e}')

print()
print('=== Port 902: with different ciphers (try to see what it accepts) ===')
for cipher in ['DEFAULT', 'HIGH:!SSLv3:!RC4', 'AES128-SHA']:
    try:
        s = socket.socket()
        s.settimeout(6)
        s.connect((HOST, 902))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers(cipher)
        try:
            ts = ctx.wrap_socket(s, server_hostname=HOST)
            print(f'  cipher={cipher}: OK -- {ts.version()}')
            ts.close()
        except Exception as e:
            print(f'  cipher={cipher}: ERR {e}')
            try: s.close()
            except: pass
    except Exception as e:
        print(f'  connect ERR: {e}')

print()
print('=== Port 902: try NOPROTOCOL with s_client-style raw TLS client hello to see if server speaks anything ===')
# Send a barebones ClientHello and see what happens
import struct
# This is complex; let us just rely on the ssl lib.
