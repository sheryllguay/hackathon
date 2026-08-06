# Researcher B — Port 5040 (CDPSvc / Connected Devices Platform)

## Status: in_progress

## Approach
- No `web_search` / `fetch` tool available in this runtime. Research is conducted from
  training knowledge of public Microsoft docs, MSRC / NVD CVE records, and prior
  industry reporting on Windows Connected Devices Platform (CDP / Project Rome).
- All specific CVE IDs, version-fixes, and exact protocol byte-layouts are flagged
  with confidence ("high" / "medium" / "low") and noted as residual risk requiring
  live verification.
- Will not attempt any TCP connection. Researcher role is read-only.

## Angles to cover
1. What CDPSvc is on Windows 10/11 and whether 5040 is the canonical port.
2. Protocol (TCP vs UDP, framing, auth model).
3. Attack surface of an exposed 0.0.0.0:5040 listener on Windows 11 24H2.
4. Known CVEs against CDPSvc, plus TCP/IP-stack CVEs (e.g. CVE-2024-38063) that
   transit 5040.
5. Historical port 5040 collisions: wcss.exe / Windows CardSpace, Service Control
   Manager remote protocol claim from the prompt.

## Progress
- Drafting structured brief (~700-900 words).
- Confidence flags attached to low-certainty items (specific CVE IDs, byte layout).
- Final output: `outputs/e5f2fe76/researcher_b_5040.md`.
