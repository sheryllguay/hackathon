import asyncio
import sys

TARGET = "10.181.33.90"
EXTRA_PORTS = [5040, 49689]

PROBES = {
    5040: [
        b"",  # no payload
        b"\r\n",
        b"HELP\r\n",
        b"GET / HTTP/1.0\r\n\r\n",
    ],
    49689: [
        b"",
        b"\r\n",
        b"HELP\r\n",
    ],
}

async def probe(port, payloads):
    findings = []
    for payload in payloads:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(TARGET, port), timeout=2.0)
            if payload:
                try:
                    w.write(payload)
                    await w.drain()
                except Exception:
                    pass
            try:
                data = await asyncio.wait_for(r.read(512), timeout=1.5)
                findings.append((payload, data))
            except Exception:
                findings.append((payload, b"(timeout)"))
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
        except Exception as e:
            findings.append((payload, f"ERR: {e}".encode()))
    return port, findings

async def main():
    tasks = [probe(p, PROBES[p]) for p in EXTRA_PORTS]
    for port, findings in await asyncio.gather(*tasks):
        print(f"=== {TARGET}:{port} ===")
        for sent, recv in findings:
            sent_repr = repr(sent) if sent else "(no payload sent)"
            if isinstance(recv, bytes):
                recv_repr = repr(recv[:120])
            else:
                recv_repr = str(recv)
            print(f"  sent: {sent_repr}")
            print(f"  recv: {recv_repr}")
        print()

asyncio.run(main())
