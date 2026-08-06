# Researcher C — Port 49689 (GlideXService)

## Status: completed

## Delivered
- Brief: `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\e5f2fe76\researcher_c_49689.md` (~10156 bytes, 600–1000 word target met)
- Sections covered: What it is, Protocol on 49689, Interpretation of banner, Attack surface, Known CVEs, Hardening, References, Gaps.

## Methodology
- No `web_search` tool available — used training-data only.
- Each architectural / behavioral fact tagged with explicit confidence (HIGH / MED / LOW).
- All specific CVE IDs and version numbers flagged as `LOW–MED` confidence and explicitly listed under "Residual Risks" for live NVD/ASUS-advisory re-verification.
- Did not connect to any port; research-only as required.

## Key takeaways
- TCP/49689 = ASUS GlideX `GlideXService.exe`, raw TCP, no TLS, no HTTP, no auth on the banner push.
- Banner is a capability/port-list announcement, not a session ID.
- 0xC80D = 51213 likely a secondary streaming port; 4-byte prefix semantics LOW confidence.
- Unauthenticated LAN attacker can fingerprint, force pairing-prompt UX, and historically (per training-data CVEs) trigger pre-auth parser bugs.
- Hardening path: update GlideX, restrict 49689/51213 via Windows Firewall to Private profile, or stop+disable the service.

## Residual risks
- Specific CVE IDs (e.g., CVE-2022-36449, CVE-2022-29971) need live NVD confirmation.
- Whether 2024–2025 GlideX has added TLS / auth to 49689 unverified.
- 4-byte banner prefix semantics inferred, not proven.

---

# Researcher B — Port 5040 (CDPSvc / Connected Devices Platform)

## Status: completed

## Delivered
- Brief: `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\e5f2fe76\researcher_b_5040.md` (~9.9 KB, ~800 words, six sections + Gaps)
- Sections: Summary, What it is, Protocol, Attack surface, Known CVEs, Hardening, References, Gaps.

## Methodology
- No `web_search` / `fetch` tool available in this runtime.
- Research from training knowledge of Microsoft Learn, MSRC, and NVD; all
  specific CVE IDs / protocol byte-layout / version-fix tables tagged with
  confidence (HIGH / MED / LOW).
- Did NOT attempt any TCP connection. Read-only research.

## Key takeaways
- TCP/5040 on Windows 11 24H2 = **CDPSvc** (Connected Devices Platform
  Service), the `svchost -k LocalService -p` group hosting `CDPSvc.dll`.
- Service backs Phone Link, "Continue on PC", Nearby Sharing, Edge
  "Send to devices".
- On-wire protocol is a **proprietary Microsoft binary protocol** (not HTTP,
  not DCE/RPC) — consistent with the observed silent-server fingerprint.
- Default bind is 0.0.0.0/::; Windows Firewall blocks 5040 on the Public
  profile by default, so the realistic threat surface is **LAN**, not
  public-internet.
- Auth model: per-user device pairing (shared secret via QR / OAuth / PIN);
  unauthenticated peers can announce / discover but not invoke privileged
  message types.
- Hardening: install July 2024 CU (CVE-2024-38063), keep the public-profile
  firewall rule, optionally disable CDPSvc if cross-device features are
  unused.

## Residual risks (explicit)
- The prompt's claim that port 5040 has been used by "Service Control
  Manager remote protocol" is **refuted with high confidence** (SCM is on
  135, not 5040).
- `wcss.exe` / Windows CardSpace port history marked LOW confidence — modern
  Windows builds should not have it listening, but stale entries on upgraded
  machines are possible.
- Specific CDPSvc EoP CVE IDs from 2021–2023 not cited; recommend live MSRC
  query by title "Windows Connected Devices Platform Service Elevation of
  Privilege Vulnerability".
- Secondary 5240 port claim is MED confidence; verify with `netstat -ano`.
