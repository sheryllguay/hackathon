import socket, ssl

HOST = '10.181.33.90'

print('=== Port 902 TLS probe ===')
s = socket.socket()
s.settimeout(8)
s.connect((HOST, 902))
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    ts = ctx.wrap_socket(s, server_hostname=HOST)
    print('TLS negotiated:', ts.version())
    print('Cipher:', ts.cipher())
    cert = ts.getpeercert(binary_form=True)
    print('Cert bytes len:', len(cert))
    subj = ts.getpeercert()
    if subj:
        print('Subject:', dict((x[0][0], x[0][1]) for x in subj.get('subject', [])))
        print('Issuer:', dict((x[0][0], x[0][1]) for x in subj.get('issuer', [])))
        print('Not Before:', subj.get('notBefore'))
        print('Not After:', subj.get('notAfter'))
        print('SANs:', [v for k, v in subj.get('subjectAltName', [])])
    ts.close()
except Exception as e:
    print('TLS probe ERR:', type(e).__name__, e)
    s.close()

print()
print('=== Port 902 plain text — send HELP / SOAP probe ===')
s = socket.socket()
s.settimeout(5)
s.connect((HOST, 902))
s.sendall(b'HELP\r\n')
try:
    r = s.recv(2048)
    print('after HELP:', repr(r))
except Exception as e:
    print('after HELP ERR:', e)
s.close()

print()
print('=== Port 902 — empty line ===')
s = socket.socket()
s.settimeout(5)
s.connect((HOST, 902))
s.sendall(b'\r\n')
try:
    r = s.recv(2048)
    print('after blank:', repr(r))
except Exception as e:
    print('after blank ERR:', e)
s.close()
