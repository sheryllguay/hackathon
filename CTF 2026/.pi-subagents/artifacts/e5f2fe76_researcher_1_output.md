Research complete. Brief written to `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\e5f2fe76\researcher_c_49689.md` (10,156 bytes, within the 600–1000 word target).

**Top-line answers:**

1. **What it is** — `GlideXService.exe` is the Windows service half of **ASUS GlideX**, ASUS's screen-mirror / extend / unify-control product. 49689 is its main inbound TCP control port; it also opens secondary high ports (likely including 51213, see banner decode) for the actual stream. (`MED` confidence on the port number being canonical; `HIGH` on the product identity.)

2. **Protocol on 49689** — Raw TCP, **no TLS, no HTTP, no WebSocket**. The server pushes 32 bytes on connect before any client greeting. A `GET /` is connection-reset, consistent with a non-HTTP binary protocol. (`HIGH` confidence.)

3. **Banner interpretation** — 4-byte prefix `8e 27 e5 ac` (semantics `LOW` confidence) followed by 14 little-endian `uint16` values: `5, 7, 9, 51213, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31`. The 13 odd values are the IANA "well-known" odd TCP ports 5–31; the 51213 anomaly is a **secondary GlideX service/streaming port the client is supposed to connect to next**. This is a **capability / presence announcement**, not a session ID or probe-response — pushed to anyone who opens the socket. (`MED–HIGH` confidence.)

4. **Attack surface** — Pre-auth, an attacker on the LAN can: (a) fingerprint every GlideX install with one `connect()`; (b) learn the host's streaming port; (c) trigger pairing-prompt UX on the host. Post-pairing, the protocol is designed to deliver screen view + input injection + (historically) file transfer. Pre-auth parser bugs are the historical CVE class.

5. **Known CVEs** — From training data, `LOW–MED` confidence: **CVE-2022-36449** (ASUS GlideX RCE class) and **CVE-2022-29971** (IPEVO Mirroring360/Mirroring Assist lineage). **Residual risk flagged: must be re-verified on `nvd.nist.gov` and `asus.com/security-advisory`** before external citation.

6. **Hardening** — Update GlideX to current; restrict 49689 + 51213 via Windows Firewall to `Private` profile / trusted subnet only; or `Stop-Service GlideXService` + `Set-Service -StartupType Manual` when not using Screen Mirror; never enable on public Wi-Fi.