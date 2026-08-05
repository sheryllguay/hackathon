#!/usr/bin/env python3
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class LogRequestHandler(BaseHTTPRequestHandler):
    def log_request_details(self):
        print(f"\n[+] Received {self.command} request from {self.client_address}")
        print(f"Path: {self.path}")
        print("Headers:")
        for k, v in self.headers.items():
            print(f"  {k}: {v}")
            
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            body = self.rfile.read(content_length)
            print("Body:")
            try:
                print(body.decode('utf-8'))
            except UnicodeDecodeError:
                print(body.hex())
                
    def do_GET(self):
        self.log_request_details()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK\n")
        
    def do_POST(self):
        self.log_request_details()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK\n")
        
    def do_PUT(self):
        self.log_request_details()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK\n")

def run_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, LogRequestHandler)
    print(f"[*] HTTP Listener running on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping HTTP Listener...")
        httpd.server_close()

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    run_server(port)
