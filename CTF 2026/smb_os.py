import asyncio
import struct

TARGET = "10.181.33.90"

async def try_smb2_negotiate():
    """SMB2 Negotiate Protocol Request — simpler and well-supported."""
    # SMB2 header
    smb2_header = (
        b"\xfeSMB"               # protocol id (0xFE 'S' 'M' 'B')
        b"\x40\x00"              # header length
        b"\x00\x00"              # credit charge
        b"\x00\x00\x00\x00"      # status
        b"\x00\x00"              # command: Negotiate
        b"\x01\x00"              # credits requested
        b"\x00\x00\x00\x00"      # flags
        b"\x00\x00\x00\x00"      # next command
        b"\x01\x00\x00\x00"      # message id
        b"\x00\x00\x00\x00"      # reserved
        b"\x00\x00\x00\x00"      # tree id
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # session id
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # signature
    )
    # Negotiate request body
    body = (
        b"\x24\x00"              # structure size (0x24)
        b"\x01\x00"              # dialect count
        b"\x00\x00"              # security mode
        b"\x00\x00"              # reserved
        b"\x00\x00\x00\x00"      # capabilities
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # client guid
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # +16
        b"\x00\x00\x00\x00"      # negotiate context offset
        b"\x02\x00"              # negotiate context count
        b"\x00\x00"              # reserved
        # Dialect: SMB 3.1.1
        b"\x11\x00"
    )
    pkt = smb2_header + body
    # NetBIOS session header: type=0, length
    return struct.pack(">BBH", 0x00, 0x00, len(pkt)) + pkt

async def main():
    r, w = await asyncio.wait_for(asyncio.open_connection(TARGET, 445), timeout=3.0)
    pkt = await try_smb2_negotiate()
    w.write(pkt)
    await w.drain()
    data = await asyncio.wait_for(r.read(4096), timeout=4.0)
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    print(f"Response: {len(data)} bytes")
    # Find SMB2 header
    if data[4:8] == b"\xfeSMB":
        print("Got SMB2 response")
        # Negotiate response dialect index at offset 4 in SMB2 body
        # Response starts after NetBIOS header (4 bytes)
        # SMB2 header is 64 bytes
        body_start = 4 + 64
        print(f"Body hex: {data[body_start:body_start+64].hex()}")
        # Try to read dialect
        if len(data) > body_start + 4:
            dialect_idx = struct.unpack_from("<H", data, body_start + 4)[0]
            print(f"Dialect index: {dialect_idx}")
            dialects = {0: "2.0.2", 1: "2.1", 2: "3.0", 3: "3.0.2", 4: "3.1.1"}
            print(f"Dialect: SMB{dialects.get(dialect_idx, '?')}")
        # Look for OS info
        if b"Windows" in data:
            i = data.find(b"Windows")
            print(f"Found 'Windows' at {i}: {data[i:i+50]!r}")
    else:
        print(f"Unexpected: {data[:32].hex()}")

asyncio.run(main())
