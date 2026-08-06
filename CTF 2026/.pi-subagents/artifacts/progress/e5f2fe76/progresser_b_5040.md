# Researcher B — Port 5040 (CDPSvc / Connected Devices Platform)

## Status: complete

## Approach
- No `web_search` / `fetch` tool available in this runtime. Research was
  conducted from training knowledge of public Microsoft Learn, MSRC and NVD
  material, and prior industry reporting on the Connected Devices Platform
  (CDP, formerly "Project Rome").
- All specific CVE identifiers, byte-level protocol layout, and exact version
  fixes were flagged with a confidence rating and noted as residual risk
  requiring live verification.
- No network access was performed; researcher role is read-only.

## Angles covered
1. CDPSvc identity on Windows 10/11 and 5040 as the canonical port — confirmed.
2. Protocol (TCP vs UDP, framing, auth model) — custom Microsoft binary protocol
   over TCP, not HTTP, not DCE/RPC; consistent with observed "silent server"
   fingerprint.
3. Attack surface of an exposed 0.0.0.0:5040 listener on Windows 11 24H2 —
   LAN-reachable, paired-device auth model, LocalService privilege, firewall
   defaults.
4. CVEs — CVE-2024-38063 (IPv6 RCE, well-attested), CVE-2022-30115 / Follina
   (adjacent, not direct), AFD.sys chain CVE-2023-21768, plus a flagged
   residual cluster of CDPSvc-specific EoP CVEs whose IDs I am not confident
   enough to cite.
5. Historical port 5040 collisions — wcss.exe / CardSpace marked low
   confidence; "SCM remote protocol" claim refuted with high confidence (SCM
   is on 135, not 5040).

## Confidence summary
- High: service identity, svchost grouping, TCP transport, custom binary
  protocol, default firewall posture, CVE-2024-38063 attribution, refutation
  of the SCM-on-5040 claim.
- Medium: secondary port 5240, exact list of unauthenticated message types,
  local EoP chain from CDPSvc → SYSTEM.
- Low: specific CDPSvc CVE IDs 2021-2023, byte-level frame layout,
  wcss.exe/CardSpace port history.

## Output
- `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\e5f2fe76\researcher_b_5040.md`
  (~700-900 words, six sections, three gaps explicitly listed).
