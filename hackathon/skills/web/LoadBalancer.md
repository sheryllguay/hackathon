# Load Balancer & Failover Bypass (LoadBalancer)

## Purpose
Force a load balancer (HAProxy/nginx) to route traffic to a specific backend, e.g. a failover/backup server that serves the flag, by manipulating health checks and failover logic instead of attacking the app directly.

## Decision Tree
```
Traffic behind a load balancer with multiple backends:
 ├── Can you read the LB config / stats? -> Look for `backup`, `check fall N`, `inter Ns`, admin paths
 ├── Backends answer differently (flag vs "no flag")?
 │    ├── Map which backend is currently serving you
 │    └── Identify how to reach the flag backend
 ├── Health-check-based failover (HAProxy `backup` directive)?
 │    ├── Can you make the active backend return non-2xx?
 │    │    ├── Rate limiter returns 503 -> FLOOD past its limit -> health check fails -> failover
 │    │    └── Trigger 5xx via error/invalid input -> failover
 │    └── Failover detected -> STOP flooding, poll with single requests (backup limiter is fresh)
 └── Backup reachable directly? -> second port/instance, IP enum, Host header routing
```

## Recon Checklist
- [ ] `GET /` repeatedly; diff responses to see if a single backend serves you or round-robin alternates.
- [ ] Check response headers for LB/server fingerprints.
- [ ] Probe admin/stats paths: `/stats`, `/status`, `/health`, `/healthz`, `/haproxy`, `/haproxy?stats`, `/admin`.
- [ ] Read any provided HAProxy/LB config for `backup`, `check`, `fall`, `inter`, `option httpchk`.

## Detection Checklist
- [ ] Response says "No flag in this service" vs contains the flag -> you are hitting different backends.
- [ ] Trigger the app's rate limiter (spam requests) and watch for 503/429 -> this can flip health checks.
- [ ] Observe the transition: `200 primary` -> `503 rate limit` -> `200 backup(flag)`.

## Recon Workflow
1. Identify the load balancer and backend topology (content/headers/timing).
2. Read the provided LB config: `backup` servers only serve when all others are DOWN.
3. Probe for exposed stats/admin endpoints.
4. Determine what makes a backend fail health checks (rate limit, 5xx, crash).

## Enumeration
- HAProxy directives: `server name addr check`, `server name addr backup check`, `fall <n>`, `inter <ms>`.
- Health check path (often `/` or `/healthz`); status expectation (usually 200).
- Rate limiter: limit window + status code on exceed (e.g. 429->503).

## Useful Tools
- `curl` loops (backend mapping)
- `scripts/failover_flood.py` (stdlib flood + poll)
- HAProxy config analysis

## Quick Commands
```bash
# Map backends: repeated requests, print only the <p> content
for i in $(seq 1 20); do curl -s http://HOST/ | grep -oE '<p>[^<]*</p>'; done
# Inspect LB/backend headers
curl -sI http://HOST/
# Flood + poll for failover
python3 scripts/failover_flood.py http://HOST/ 40 15
```

## Linux Commands
```bash
# Loop requests and count distinct responses
for i in $(seq 1 50); do curl -s http://HOST/; done | sort | uniq -c
```

## Common Payloads
```
# Rate-limiter trip: send > N requests/minute (N = limiter window) to the active backend
# Then poll once -> backup may answer with the flag
curl -s http://HOST/ | grep picoCTF
```

## Exploitation Workflow
1. Confirm the current backend serves no flag.
2. Make it fail its health check: flood its rate limiter so it returns 503 (keep it failing for `fall x inter`).
3. Wait for LB to mark it DOWN and fail over to the backup.
4. Poll with single requests; grab the flag from the backup.
5. Stop flooding immediately (the backup has its own fresh limiter).

## Example CTF Scenario
"Failure Failure" (picoCTF 2026): primary returns "No flag in this service", backup (`IS_BACKUP=yes`) returns the flag. Flooding the primary's global 300/min limiter made it return 503; HAProxy marked it DOWN and failed over to the backup, which returned the flag.

## Python Automation Example
```python
# scripts/failover_flood.py  (stdlib, threads)
# 1) concurrent flood to trip the active backend's rate limiter
# 2) poll with single requests until the flag regex matches
```

## Common Mistakes
- Flooding past the failover and tripping the BACKUP's limiter too -> stop polling hard, use single requests.
- Not sustaining the failing status long enough for `fall`/`inter` detection -> keep sending requests during the window.
- Ignoring the provided LB config -> missing the exact failover triggers.

## CTF Tips
- A rate limiter returning 503 is a perfect failover trigger: 503 == DOWN to a health check.
- `backup` servers only receive traffic when every non-backup server is down.
- The backup may also be reachable directly via a second instance/port if disclosed.
- Challenge wording ("high-available", "failover", "load balancer") hints at this class.

## References
- HAProxy health checks & backup servers
- flask-limiter 429/503 handling
