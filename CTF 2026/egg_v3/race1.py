import http.client, json, time

HOST = '52.76.96.108'
PORT = 3000

class Client:
    def __init__(self):
        self.cookie = None
    def post(self, path, body=None):
        c = http.client.HTTPConnection(HOST, PORT, timeout=10)
        h = {'Content-Type': 'application/json'}
        if self.cookie:
            h['Cookie'] = self.cookie
        c.request('POST', path, body=json.dumps(body) if body is not None else None, headers=h)
        r = c.getresponse()
        data = r.read()
        sc = r.getheader('Set-Cookie')
        if sc:
            self.cookie = sc.split(';', 1)[0]
        c.close()
        try:
            return r.status, json.loads(data)
        except Exception:
            return r.status, data

cl = Client()
cl.post('/api/reset')
print('start:', cl.post('/api/balance'))
# fire 6 withdraws as fast as possible
for i in range(6):
    print(i, cl.post('/api/withdraw', {'amount': 0.5}))
# watch settlement
for i in range(10):
    print('bal:', cl.post('/api/balance'))
    time.sleep(1)
