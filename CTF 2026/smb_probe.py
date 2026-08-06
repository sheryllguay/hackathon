import asyncio
import struct

TARGET = "10.181.33.90"

async def smb_negotiate():
    """SMB1 Negotiate Protocol to elicit OS version info."""
    # NetBIOS Session Service header: type=0x00, length=0x2F
    # SMB Header
    smb_header = (
        b"\xff\x53\x4d\x42"  # protocol
        b"\x72"              # command: Negotiate Protocol
        b"\x00\x00\x00"      # status (success)
        b"\x18"              # flags
        b"\x53\xc8"          # flags2
        b"\x00\x00"          # pid high
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # signature
        b"\x00\x00"          # reserved
        b"\xff\xfe"          # tree id
        b"\x00\x00"          # uid
        b"\x40\x11"          # pid
        b"\x00"              # mid
    )
    # Negotiate Protocol body
    body = b""
    body += b"\x00"  # word count (0 for SMB1 negotiate)
    body += b"\x12"  # byte count (18)
    body += b"\x02NT LM 0.12\x00"  # dialects
    smb = smb_header + body
    # NetBIOS session header
    netbios = struct.pack(">BBH", 0x00, 0x00, len(smb)) + smb
    return netbios

async def main():
    r, w = await asyncio.wait_for(asyncio.open_connection(TARGET, 445), timeout=3.0)
    pkt = await smb_negotiate()
    w.write(pkt)
    await w.drain()
    data = await asyncio.wait_for(r.read(4096), timeout=3.0)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    # Try to extract OS info
    print(f"Response: {len(data)} bytes")
    print(f"HEX: {data.hex()}")
    print(f"TXT: {data.decode('latin-1', errors='replace')}")
    # Look for "Windows" in response
    if b"Windows" in data:
        idx = data.find(b"Windows")
        print(f"\n*** Found 'Windows' at offset {idx}: {data[idx:idx+80]!r}")
    if b"NTLMSSP" in data:
        idx = data.find(b"NTLMSSP")
        print(f"\n*** Found 'NTLMSSP' at offset {idx}")

asyncio.run(main())
