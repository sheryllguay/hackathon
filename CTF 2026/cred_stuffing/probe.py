import socket

HOST = "crystal-peak.picoctf.net"
PORT = 58050

def recv_until_prompt(s, timeout=5):
    s.settimeout(timeout)
    chunks = []
    try:
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
            if b":" in data or b"?" in data or b">" in data or b"flag" in data.lower():
                # small wait for more
                s.settimeout(0.5)
                try:
                    while True:
                        more = s.recv(4096)
                        if not more:
                            break
                        chunks.append(more)
                except socket.timeout:
                    pass
                break
    except socket.timeout:
        pass
    return b"".join(chunks)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
banner = recv_until_prompt(s, 3)
print("=== BANNER ===")
print(banner.decode(errors="replace"))

# try a dummy login
s.sendall(b"testuser\n")
resp = recv_until_prompt(s, 3)
print("=== AFTER USER ===")
print(resp.decode(errors="replace"))

s.sendall(b"testpass\n")
resp = recv_until_prompt(s, 3)
print("=== AFTER PASS ===")
print(resp.decode(errors="replace"))

s.close()