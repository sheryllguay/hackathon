import asyncio
import sys

TARGET = "10.181.33.90"
TIMEOUT = 0.4
CONCURRENCY = 500

async def check(port, sem):
    async with sem:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(TARGET, port), timeout=TIMEOUT
            )
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return port
        except Exception:
            return None

async def main():
    if len(sys.argv) > 1 and sys.argv[1] == "all":
        # scan in chunks to allow partial progress
        ports = list(range(1, 65536))
    elif len(sys.argv) > 1 and sys.argv[1].startswith("range:"):
        a, b = sys.argv[1].split(":", 1)[1].split("-")
        ports = list(range(int(a), int(b) + 1))
    else:
        ports = [
            21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445,
            465, 514, 587, 631, 636, 873, 902, 989, 993, 995, 1080, 1194, 1234,
            1433, 1521, 1701, 1723, 1812, 1883, 1900, 2049, 2082, 2083, 2086,
            2087, 2095, 2096, 2181, 2222, 2375, 2376, 3000, 3001, 3268, 3269,
            3306, 3389, 3690, 4000, 4040, 4443, 4500, 4567, 4848, 5000, 5001,
            5060, 5222, 5432, 5601, 5672, 5900, 5985, 5986, 5987, 5988, 6000,
            6379, 6443, 6660, 6661, 6667, 7000, 7001, 7077, 7474, 8000, 8001,
            8008, 8009, 8080, 8081, 8082, 8083, 8086, 8087, 8088, 8089, 8090,
            8091, 8181, 8443, 8500, 8880, 8883, 8888, 9000, 9001, 9002, 9042,
            9090, 9091, 9092, 9100, 9200, 9300, 9418, 9443, 9999, 10000, 10250,
            11211, 15672, 15692, 16010, 16030, 18080, 20000, 27017, 27018, 27019,
            28017, 50000,
        ]
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [check(p, sem) for p in ports]
    results = await asyncio.gather(*tasks)
    open_ports = sorted([p for p in results if p is not None])
    print(f"Scanned {len(ports)} ports against {TARGET}")
    print(f"Open ports ({len(open_ports)}):")
    for p in open_ports:
        print(f"  {p}")

asyncio.run(main())
