import socket
import struct
import time

def send_program(host, port, program_bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    s.settimeout(3)
    
    # Read banner
    try:
        data = s.recv(4096)
    except:
        pass
    
    # Send program length + bytecode
    prog_len = len(program_bytes)
    payload = struct.pack('<I', prog_len) + program_bytes
    
    try:
        s.sendall(payload)
        time.sleep(1)
        
        responses = []
        for _ in range(5):
            try:
                s.settimeout(2)
                chunk = s.recv(4096)
                if chunk:
                    responses.append(chunk)
                else:
                    break
            except:
                break
        
        result = b''.join(responses)
        return result.decode(errors='replace')
    except Exception as e:
        return str(e)
    finally:
        s.close()

# Instruction encoding helpers
def encode_mov(dest_reg, src_reg, imm=0):
    """MOV dest, [src+imm]"""
    opcode = 0x01
    hi = (dest_reg << 4) | src_reg
    return bytes([opcode, hi]) + struct.pack('<I', imm) + b'\x00\x00'

def encode_addimr(dest_reg, src_reg, imm):
    """ADDIMR dest, src, imm"""
    opcode = 0x04
    hi = (dest_reg << 4) | src_reg
    return bytes([opcode, hi]) + struct.pack('<I', imm)

def encode_hook(syscall_num, arg1=0, arg2=0, arg3=0):
    """HOOK syscall, args in regs"""
    opcode = 0x13
    return bytes([opcode, 0x00]) + struct.pack('<I', syscall_num) + struct.pack('<I', 0)

def encode_jmp(reg):
    """JMP [reg]"""
    opcode = 0x0C
    return bytes([opcode, reg << 4]) + b'\x00' * 6

def encode_jez(reg):
    """JEZ reg, target_addr"""
    opcode = 0x0D
    return bytes([opcode, reg << 4]) + struct.pack('<I', target_addr) + b'\x00\x00'

# Test various opcodes to discover their behavior
print("=== Discovering opcodes ===")

# Test 1: Basic MOV
print("\n--- MOV r1, r0 [addr=0] ---")
prog = encode_mov(1, 0, 0)
print("Bytes:", prog.hex())
resp = send_program('52.76.96.108', 9006, prog)
print("Response:", resp.strip())

# Test 2: MOV with non-zero immediate (memory address)
print("\n--- MOV r1, r0 [addr=0x4080] (pointer in .data) ---")
prog = encode_mov(1, 0, 0x4080)
print("Bytes:", prog.hex())
resp = send_program('52.76.96.108', 9006, prog)
print("Response:", resp.strip())

# Test 3: Try ADDIMR
print("\n--- ADDIMR r1, r0, 1 ---")
prog = encode_addimr(1, 0, 1)
print("Bytes:", prog.hex())
resp = send_program('52.76.96.108', 9006, prog)
print("Response:", resp.strip())

# Test 4: HOOK with various syscall numbers
for sc in [0, 1, 2, 3, 4, 5, 93]:
    print(f"\n--- HOOK syscall={sc} ---")
    prog = encode_hook(sc)
    resp = send_program('52.76.96.108', 9006, prog)
    print("Response:", resp.strip()[:200])
