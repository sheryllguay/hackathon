# Failure Failure (picoCTF 2026) - Writeup

## Category: General Skills / Infra (Load Balancer Failover Abuse)
## Difficulty: Medium

### Challenge Description
> Welcome to Failure Failure — a high-available system. A load balancer stands between you and the truth — and it won't hand over the flag until you force its hand.

Two Flask backends sit behind HAProxy:
- **Primary** (`IS_BACKUP=no`) -> renders "No flag in this service"
- **Backup** (`IS_BACKUP=yes`) -> renders the flag

Both run identical app code (`app.py`). The only route `/` applies a **global rate limiter** (`flask_limiter`, `300 per minute`, shared key `"global"`) and maps 429 -> **503 "Service Unavailable: Rate limit exceeded"**.

### Recon
1. `GET /` returns `No flag in this service` -> we are hitting the primary.
2. Probe `{/stats,/status,/health,/healthz,/haproxy,/haproxy?stats,/admin}` -> all 404 (no exposed LB admin).
3. Read the provided source + HAProxy config: a `server ... backup check` directive means the backup only receives traffic when all non-backup servers are DOWN.
4. HAProxy decides where traffic goes by **health checks**: a backend that stops returning 2xx/3xx is marked DOWN (`fall` failures over `inter` interval).

### Exploitation
1. **Flood the primary past its rate limit** (~600 concurrent requests) so it starts returning 503.
2. HAProxy's health checks observe the 503s -> mark the primary DOWN.
3. All traffic fails over to the backup server, which has `IS_BACKUP=yes` -> returns the flag.
4. Stop flooding immediately after failover so the backup's own (fresh) rate limiter is not tripped, then poll with single requests.

```bash
# Flood, then poll for the flag
python3 scripts/failover_flood.py http://mysterious-sea.picoctf.net:57247/ 40 15
```

Observed sequence: `200 PRIMARY` -> `503 rate limit` -> `200 picoCTF{...}` (backup).

### Flag
```
picoCTF{f41l0v3r_f0r_7h3_w1n_35d13ec3}
```
*(Instance-specific.)*

### Why It Worked
The "high availability" failover became an attack primitive: the rate limiter's 503 is indistinguishable to HAProxy from a down server. Instead of crashing the primary, we only needed to make its health checks fail briefly; HAProxy then handed traffic to the backup that holds the flag.

### Mitigation
- Health-check endpoints should be isolated from user-facing rate limits (dedicated `/healthz` path, not the rate-limited `/`).
- Authenticate/restrict access to any admin/stats interface.
- Prefer failover configs where the backup never serves sensitive data, or rate-limit/allowlist the failover path.

### Lessons Learned
- **503 (rate limit) == down** for a load balancer's health check: a rate limiter can be a failover trigger.
- Read the provided LB config first: `backup`, `check fall N`, `inter Ns` tell you exactly how to force failover.
- Map which backend serves you (content/headers) before attacking; then poll after failover and STOP flooding so the backup's limiter stays fresh.

### Reusable Artifacts
- Skill: `skills/web/LoadBalancer.md`
- Script: `scripts/failover_flood.py`
- Payloads: `payloads/LoadBalancer.txt`

### References
- HAProxy: backup server + health checking: https://www.haproxy.com/documentation/haproxy-configuration-manual/load-balancing/health-checks/
- flask-limiter 503/429 handling
