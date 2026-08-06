import socket, struct, sys, time, threading

HOST = "52.76.96.108"
PORT = 9004

def hexd(b):
    return ' '.join(f'{x:02x}' for x in b)

def recv_all(s, timeout=2.5):
    s.settimeout(timeout)
    chunks = []
    try:
        while True:
            d = s.recv(4096)
            if not d: break
            chunks.append(d)
    except Exception:
        pass
    return b''.join(chunks)

def send_frame_and_recv(frame, label, wait=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(6)
        s.connect((HOST, PORT))
        print(f"\n=== {label} ===")
        print("->", hexd(frame))
        s.sendall(frame)
        time.sleep(wait)
        r = recv_all(s, timeout=2.5)
        print(f"<- ({len(r)} bytes):", hexd(r))
        if r:
            parse(r)
        s.close()
        return r
    except Exception as e:
        print("err:", e)
        return b""

def parse(r):
    i = 0
    while i + 8 <= len(r):
        if r[i:i+4] != b"RELY":
            print(f"  [no magic at {i}]")
            break
        op = r[i+4]
        ln = (r[i+5]<<8) | r[i+6]
        chk = r[i+7]
        payload = r[i+8:i+8+ln]
        print(f"  frame: opcode=0x{op:02x} len={ln} checksum=0x{chk:02x} payload={hexd(payload)}")
        i += 8 + ln

# Known-good HELLO
hello = bytes([0x52,0x45,0x4C,0x59,0x01,0x00,0x00,0xA6])
send_frame_and_recv(hello, "HELLO good checksum")

# HELLO with wrong checksum
hello_bad = bytes([0x52,0x45,0x4C,0x59,0x01,0x00,0x00,0x00])
send_frame_and_recv(hello_bad, "HELLO wrong checksum (00)")

# Try opcode 0x02 with empty payload - guess checksum as xor^0xA5 xor empty
def mk(op, payload, csover):
    ln = len(payload)
    full = bytes([0x52,0x45,0x4C,0x59,op,(ln>>8)&0xFF,ln&0xFF]) + payload
    if csover == "hdr":
        x = 0
        for b in full[:7]: x ^= b
    else:
        x = 0
        for b in full: x ^= b
    chk = x ^ 0xA5
    return full[:7] + bytes([chk]) + payload, chk

# echo the server's nonce back maybe? First let's just probe opcodes with empty payload
for op in [0x02, 0x03, 0x04, 0x10, 0x7F, 0xFF]:
    f, chk = mk(op, b"", "hdr")
    send_frame_and_recv(f, f"opcode 0x{op:02x} empty (xor_A5 hdr-only)")