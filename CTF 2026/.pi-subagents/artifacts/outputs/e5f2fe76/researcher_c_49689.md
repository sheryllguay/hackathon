# Research: TCP/49689 — ASUS GlideXService

> **Confidence disclaimer (read first).** This brief was produced without a `web_search` tool. All specific facts below come from model training data (ASUS support pages, NVD, public security write-ups, GitHub mirror references I have seen) and **must be re-verified against live ASUS / NVD / vendor advisories before being cited externally**. Specific CVE IDs, version numbers, port numbers, and protocol field meanings are flagged `LOW–MED` confidence; architectural facts (what the product is, what the service does, what attack surface it has) are `MED–HIGH` confidence because they are corroborated across many sources.

## Summary
TCP/49689 is the listener for `GlideXService.exe`, the Windows service component of **ASUS GlideX** — ASUS's cross-device screen-mirror / screen-extend / remote-input utility. The 32-byte server-pushed banner is almost certainly a **capability / presence announcement** (a list of well-known TCP port numbers, plus one anomaly), and it does **not** appear to be authenticated, encrypted, or TLS-wrapped. On a default install the service binds `0.0.0.0:49689` and exposes enough state that an unauthenticated LAN attacker can identify the host as a GlideX endpoint and likely attempt pairing/connection flows, which historically have been the vector for screen-view and input-injection bugs.

## What it is
**ASUS GlideX** is a free utility from ASUS that lets a Windows PC share its screen with, and be controlled from, other PCs, iPhones, iPads, and Android phones on the same network. It exposes three named features:

- **Screen Mirror** — mobile/secondary device displays the PC's screen.
- **Screen Extend** — the mobile/secondary device acts as an additional display.
- **Unify Control** — use a phone/tablet as a touchpad/keyboard for the PC.

GlideX is a re-branded / re-engineered descendant of **IPEVO Mirroring360** (the same engine family that powered Mirroring Assist and the older ASUS "Screen Mirror" tool). Some code paths, capability-negotiation, and on-wire framing share lineage with that codebase. On Windows the install drops:

- `C:\Program Files\ASUS\GlideX\GlideX.exe` (UI / client)
- `C:\Program Files\ASUS\GlideX\GlideXService.exe` (background listener — this is the process bound to 49689)
- A Windows service registered to start automatically.

The service description in the user's capture ("Provides access to Screen Mirror/Extend/Unify Control features from GlideX.") matches the official ASUS description.

**Is 49689 the documented port?** I am **MED** confidence that 49689 is the canonical GlideX service-control TCP port on current Windows builds. ASUS has not formally registered it with IANA as far as my training data shows; the port is in the IANA dynamic/private range (49152–65535). The same executable also opens additional high ports for the actual screen-streaming sessions, which is what the banner may be advertising (see below).

## Protocol on 49689
Based on the banner shape and known GlideX/Mirroring360 behavior:

- **Transport:** raw TCP, **not** TLS, **not** HTTP, **not** WebSocket. The server does not wait for a client greeting — it pushes 32 bytes immediately on connect. A naïve `GET / HTTP/1.1` is rejected / connection-reset, which is consistent with a non-HTTP binary protocol rather than a misconfigured web server.
- **Framing:** the first 4 bytes look like a fixed magic/header; the remaining 28 bytes are 14 little-endian `uint16` values.
- **Discovery:** GlideX also uses **mDNS / SSDP-style** announcements for the "find a GlideX PC" UX in the mobile apps, but the TCP/49689 push is a per-connection capability beacon, not the LAN-wide mDNS packet.
- **Auth:** pairing is done out-of-band (a PIN displayed on the host's GlideX UI must be typed on the connecting client). However, the *capability* and *presence* messages on 49689 are pushed to anyone who can reach the port — they are not authenticated, and they precede the auth handshake.

## Interpretation of the banner
Bytes (hex): `8e 27 e5 ac | 05 00 07 00 09 00 0d c8 0d 00 0f 00 11 00 13 00 15 00 17 00 19 00 1b 00 1d 00 1f 00`

Parsed as 14 little-endian `uint16` values after the 4-byte prefix:

`5, 7, 9, 51213, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31`

- **5, 7, 9, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31** are the **odd-numbered IANA "well-known" TCP ports** in the low range (echo, discard, daytime, chargen, ftp-data, …, msg-auth). This is the structure of a **service-port capability / "what's listening on me" announcement**, not a session ID.
- **51213 (`0xC80D`)** is the anomaly. It sits in the IANA dynamic range and is consistent with a **secondary GlideX service port** the host has open for the actual screen-stream / control channel (e.g., a per-session TCP port the client is supposed to connect to next).
- **4-byte prefix `8e 27 e5 ac`** does not decode to ASCII, a length field, or any well-known magic I recognise with high confidence. It is most plausibly either a **protocol/version tag** or a **per-host / per-session cookie**; treat its exact semantics as **LOW** confidence. If a second probe gets a different prefix from the same host, it is a session token; if it is identical across reconnects, it is a static magic.

**Likely leak content:** the banner confirms the host is running GlideX, advertises the streaming port(s) the client should target, and (because the prefix may be a host fingerprint) might weakly fingerprint the OS/install. It does **not** by itself leak hostname, username, machine name, or pairing PIN.

## Attack surface
On an internet/LAN-reachable 49689:

| Capability | Reachable pre-auth? | Confidence |
|---|---|---|
| Confirm the host is running GlideX | Yes (the banner) | HIGH |
| Enumerate the host's streaming port(s) | Yes (banner leaks e.g. 51213) | MED |
| Initiate a pairing flow (PIN prompt on host) | Yes — this is the intended client flow | HIGH |
| View the screen / inject input / read files | Only after PIN pairing is accepted on the host UI | HIGH |
| Crash / RCE the service | Has historically been possible via crafted handshake (see CVEs) | MED |

**Key attacker primitives:**

1. **Unauthenticated fingerprinting** of every GlideX install on a subnet by a single `connect()` per host.
2. **Forced pairing prompts / social-engineering window**: an attacker can repeatedly connect, the host's GlideX UI may surface "device wants to connect" affordances, and a nearby user could be tricked into entering a PIN.
3. **Pre-auth parser bugs** in the binary framing — the historical CVE class for this product line is exactly that.
4. **TLS-less transport** means anything sent after the banner (e.g., pairing handshake, stream metadata) is sniffable on the LAN.

## Known CVEs (training-data, re-verify)
`LOW` confidence on the exact IDs/numbers — confirm against `nvd.nist.gov` and `asus.com/security-advisory` before acting:

- **CVE-2022-36449 (LOW–MED conf.)** — ASUS GlideX remote code-execution class issue reported in 2022; fix was in a GlideX update pushed via ASUS Live Update.
- **CVE-2022-29971 (LOW–MED conf.)** — referenced in ASUS 2022 advisories, IPEVO Mirroring360 / Mirroring Assist stack overflow that GlideX shared code paths with.
- **ASUS-ASU-2022 / similar advisory IDs** (LOW conf.) — versions prior to a mid-2022 GlideX refresh were vulnerable to unauthenticated network-triggerable crashes; patched by upgrading to the latest GlideX from the Microsoft Store or ASUS support site.

**Residual risk:** I cannot enumerate every CVE without `web_search`. Check `nvd.nist.gov` for vendor `asustor`/`asus` and product `glidex`, plus the IPEVO `mirroring360`/`mirroring-assist` advisories, before publishing a CVE list.

## Hardening (for the host owner)
1. **Update GlideX** to the latest version from ASUS / Microsoft Store — the relevant pre-auth parser CVEs were fixed by version bumps, not by config.
2. **Restrict the listener.** There is no first-class "GlideX firewall" GUI, but a Windows Defender Firewall rule can scope 49689 (and any high ports the banner advertises, e.g. 51213) to a specific profile/subnet:
   - `New-NetFirewallRule -DisplayName "GlideX restrict" -Direction Inbound -LocalPort 49689 -Protocol TCP -Action Allow -Profile Private -RemoteAddress <home-subnet>`
   - or `Block` entirely on `Public` profile.
3. **Disable the service** when not actively using Screen Mirror/Extend: `Stop-Service GlideXService` and set startup to `Manual` (`Set-Service GlideXService -StartupType Manual`). ASUS does not support this being disabled on all builds — if Screen Mirror is core to your workflow, leave it on and rely on the firewall rule.
4. **Do not leave GlideX enabled on a public Wi-Fi network.** Treat the service as you would SMB: it should never be reachable from untrusted networks.
5. **Watch for unexpected pairing prompts** on the GlideX UI — they indicate someone on the LAN is probing the listener.

## References (training-data only — re-verify live)
- ASUS GlideX product page, `asus.com` (GlideX overview, feature list, supported devices). `MED` confidence the URL is current.
- ASUS Security Advisory portal, `asus.com/security-advisory` (vendor-issued CVE / patch notes for GlideX). `MED` confidence.
- NVD entries search: vendor `asus`, keyword `glidex` — `nvd.nist.gov/vuln/search`. `MED` confidence on exact CVE list above.
- IPEVO Mirroring360 / Mirroring Assist advisories — `ipevo.com` and NVD. `MED` confidence; relevant because of the shared codebase lineage with GlideX.
- Microsoft Store / ASUS Live Update release notes for `GlideX` (version history). `LOW–MED` confidence on specific version numbers.

## Gaps / next steps
- No live NVD / ASUS-advisory lookup was possible — every CVE ID and version number above needs a `web_search` pass.
- The 4-byte banner prefix (`8e 27 e5 ac`) and the 51213 anomaly are educated guesses; dynamic instrumentation of `GlideXService.exe` (Procmon + Wireshark on a real host opening Screen Mirror) would decode them in one capture.
- Whether 49689 has any new TLS / auth wrapping in 2024–2025 GlideX releases is unverified — assume the worst (no TLS) until proven otherwise.
