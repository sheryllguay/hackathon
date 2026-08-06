# Reconnaissance Synthesis — `sheryllguay` (10.181.33.90)

## 1. Executive Summary

The target host `sheryllguay` (10.181.33.90) is a Windows 11 24H2 (build 26200) workstation joined to AD domain `ucsihq.edu`, with seven TCP listeners reachable on the LAN. The exposure profile is dominated by **two unauthenticated, pre-authentication, network-reachable services with public critical CVEs**: the legacy `vmware-authd` listener on **TCP 912** (CVE-2022-31672, CVSS 9.8, heap-overflow RCE) and the SMB server on **TCP 445** (default `ADMIN$` / `C$` / `D$` / `IPC$` shares exposed with **SMB signing not required**). A third vendor surface — ASUS GlideX on **TCP 49689** — pushes an unauthenticated capability banner to anyone who connects, and a fourth — CDPSvc on **TCP 5040** — is wide-open on `Private`/`Domain` profiles by default. The remaining ports (135, 139, 902) are stock Windows / VMware components and are individually lower-risk, although the multi-homed `139` binding amplifies the SMB surface into every VMnet.

**Overall risk rating: HIGH** — driven primarily by port 912 (cleartext, pre-auth RCE-class CVE, no rate-limit) and port 445 (LAN-reachable admin shares, signing not required, domain-joined identity).

## 2. Host Context

| Field | Value |
|---|---|
| Hostname | `sheryllguay` |
| AD domain | `ucsihq.edu` |
| OS | Windows 11 24H2 (build 26200) — WMI-verified |
| Local time | 2026-08-05 (CTF 2026) |
| Local user | `User` (inferred from `C:\Users\User\…`) |
| Reco vantage | Performed from the host itself (local NICs) |

**Network interfaces relevant to exposure** (from `Get-NetTCPConnection` / `netstat -ano`): the workstation is multi-homed and binds core services to all interfaces. The `139` listener is bound to `0.0.0.0` and additionally to `192.168.2.1`, `192.168.247.1` (VMware VMnet1 — host-only), `169.254.173.210` (link-local), and `10.181.33.90` (main LAN). Implication: even with the host "isolated" to a private subnet, the same SMB / RPC / authd surface is reachable through every active VMnet or link-local path.

## 3. Per-Port Findings

### 3.1 TCP 135 — `RpcEptMapper` / `RpcSs`
- **Process / PID / service:** `svchost -k RPCSS` (PID 1592) → `RpcEptMapper`, `RpcSs`.
- **Bind:** `0.0.0.0`.
- **Banner / protocol:** No banner. DCE/RPC endpoint mapper; responds to `bind` / `lookup` with the table of registered RPC interfaces. Stock Windows.
- **Risk:** **Low.** The endpoint mapper itself is a normal Windows component. Real risk is downstream of the interfaces it advertises (`MS-RPC`, `DCOM`, `Winreg`, `Svcctl`, `LSARPC`, `Netlogon`); patch currency is the controlling factor.

### 3.2 TCP 139 — NetBIOS Session
- **Process / PID / service:** `System` (PID 4, kernel SMB). Bound to all four NICs in §2.
- **Banner / protocol:** No banner. NetBIOS Session Service (legacy SMB transport).
- **Risk:** **Low** as a stand-alone port, but **multiplies the SMB-on-445 exposure** by exposing the same `LanmanServer` surface to VMnet1/VMnet8 and link-local — co-hosted VMs can reach `139/445` directly.

### 3.3 TCP 445 — SMB (`LanmanServer`)
- **Process / PID / service:** `System` (PID 4) → `LanmanServer`. Bound `0.0.0.0`.
- **Banner / protocol:** SMB2/SMB3 negotiate (build 26200 confirmed via WMI). **SMB1 disabled. SMB signing NOT required.** Default shares: `ADMIN$`, `C$`, `D$`, `IPC$`.
- **Risk:** **High.** Combination of (a) `ADMIN$` / `C$` exposed at the IPC boundary, (b) signing not required (relay-friendly to/from this host), and (c) a domain-joined identity is the canonical shape of an NTLM-relay / credential-theft target. **The single largest "hidden" finding of the engagement.**

### 3.4 TCP 902 — `vmware-authd` v1.10 (SSL-required)
- **Process / PID / service:** `vmware-authd.exe` (PID 6484) → `VMAuthdService`. Bound `0.0.0.0`.
- **Banner (verbatim):** `220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC`. Vanilla TLS `ClientHello` is rejected with `WRONG_VERSION_NUMBER` — VMware 1.10 expects a 1-byte "SSL prelude" before the TLS record.
- **Risk:** **Medium.** SSL-required with a custom prelude is a stronger posture than 912, but the daemon has historically been the broker for Workstation RCE chains. Workstation 17.x / 18.x patches the known pre-auth parser bugs.

### 3.5 TCP 912 — `vmware-authd` v1.0 (cleartext, legacy)
- **Process / PID / service:** Same `vmware-authd.exe` (PID 6484), same `VMAuthdService`. Bound `0.0.0.0`.
- **Banner (verbatim):** `220 VMware Authentication Daemon Version 1.0, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC` → on `HELP` it returns `530 Please login with USER and PASS.`
- **Risk:** **Critical.** This is the **single highest-risk finding on the box.** CVE-2022-31672 (CVSS 9.8) is a pre-auth heap-overflow RCE in exactly this binary on exactly this port. The `USER`/`PASS` flow has no built-in rate-limit, so credential stuffing and brute force are also realistic. Listener exists purely for backward compatibility with legacy 1.0 clients.
- Brief: `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\ca3789ed\research.md` (confidence: **high** on protocol family and CVE class; **medium** on whether Workstation 17.6 / 18.x still binds 912 by default).

### 3.6 TCP 5040 — `CDPSvc` (Connected Devices Platform)
- **Process / PID / service:** `svchost -k LocalService` (PID 12080) → `CDPSvc`. Bound `0.0.0.0`.
- **Banner / protocol:** No banner. Proprietary Microsoft binary framing (not HTTP, not DCE/RPC). Default firewall rule blocks 5040 on `Public` profile; allows on `Private` and `Domain`.
- **Risk:** **Medium.** Pairing-based auth model — most privileged message types require a paired device. But CDPSvc has a long tail of `LocalService → SYSTEM` EoP CVEs and is also subject to stack-level exposure to CVE-2024-38063 (IPv6 RCE, CVSS 9.8) on any host without the July 2024+ cumulative update. The 0.0.0.0 bind is a **LAN** attack surface, not a public-internet one — **provided the firewall rule is intact**.
- Brief: `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\e5f2fe76\researcher_b_5040.md` (confidence: **high** on service identity / svchost group; **low** on specific 2021–2023 CVE IDs).

### 3.7 TCP 49689 — `GlideXService` (ASUS GlideX)
- **Process / PID / service:** `C:\Program Files\ASUS\GlideX\GlideXService.exe` (PID 4884) → `GlideXService`. Bound `0.0.0.0`.
- **Banner (32 bytes, server-pushed on connect):** `8e 27 e5 ac 05 00 07 00 09 00 0d c8 0d 00 0f 00 11 00 13 00 15 00 17 00 19 00 1b 00 1d 00 1f 00`. Best interpretation: 4-byte prefix + 14 little-endian `uint16` values `5, 7, 9, 51213, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31` — a capability announcement listing a secondary streaming port (the `51213` anomaly).
- **Risk:** **Medium.** Unauthenticated fingerprinting is trivial; pre-auth parser bugs in the GlideX / Mirroring360 codebase have shipped historically. Screen-view / input-injection still requires a PIN pairing, so direct pre-auth RCE is **not** claimed here — **low confidence** on the specific CVE IDs and on the 4-byte prefix semantics.
- Brief: `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\e5f2fe76\researcher_c_49689.md`.

## 4. Key Risks Prioritized

| # | Severity | Issue | Port | Why it matters |
|---|---|---|---|---|
| 1 | **Critical** | Legacy cleartext `vmware-authd` v1.0; pre-auth heap-overflow CVE-2022-31672 (CVSS 9.8) class | 912 | Unauthenticated RCE on default install; serves no current Workstation use-case |
| 2 | **High** | `ADMIN$` / `C$` / `D$` exposed, SMB signing not required, domain-joined host | 445 | NTLM-relay and credential-theft surface; canonical pre-credentialed LAN foothold |
| 3 | **High** | `139/445` bound to all NICs (incl. VMnet1 / VMnet8 / link-local) | 139, 445 | Same SMB surface exposed to host-only virtual networks — broadens the trust boundary |
| 4 | **Medium** | ASUS GlideXService pushes an unauthenticated 32-byte capability banner; parser-bug history | 49689 | LAN fingerprintable; pairing-prompt social-engineering window |
| 5 | **Medium** | CDPSvc 0.0.0.0 bind with no in-protocol auth and recurring `LocalService → SYSTEM` EoP history | 5040 | Pairing-gated privileged ops, but long CVE tail; depends on firewall + cumulative-update currency |

## 5. Recommended Next Steps (Hardening)

1. **Block and disable TCP 912.** Add a Windows Defender Firewall rule denying 912 inbound on all profiles; set `VMware Authorization Service` to `Disabled` startup unless a documented legacy client needs it. Patch Workstation / Player to the latest 17.x / 18.x.
2. **Require SMB signing.** Set `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature = 1`; enable SMB encryption on `ADMIN$` / `C$` / `D$`; audit NTLM via `secpol.msc → Network security: Restrict NTLM`.
3. **Restrict SMB to the LAN interface only.** Replace the `0.0.0.0` bind with an interface-scoped bind, or block 139/445 on VMnet1/VMnet8/`Public` profile in the firewall.
4. **Verify CDPSvc firewall rule** still blocks 5040 on `Public`. Confirm July 2024+ cumulative updates are installed (CVE-2024-38063). If Phone Link / "Send to devices" is unused, set `CDPSvc` to `Disabled`.
5. **Update or disable GlideXService.** If GlideX is in active use, apply the latest ASUS / Microsoft Store update and add a `Private`-profile-only firewall rule for 49689 (and any high port advertised in the banner, e.g. 51213). If unused, `Stop-Service` and set startup `Disabled`.
6. **Patch-currency check.** `Get-HotFix | Sort-Object InstalledOn -Descending | Select -First 5` and confirm 2024-Q3-or-later cumulative + Workstation patch level.
7. **No exposed VMware Workstation on a multi-user / untrusted-LAN host** is the long-term answer. If Workstation is required, restrict 902/912 to loopback via the VMware registry key (`HostLocalOnly=1`).

## 6. Evidence Trail

| Item | Path |
|---|---|
| Port 912 brief | `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\ca3789ed\research.md` |
| Port 5040 brief | `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\e5f2fe76\researcher_b_5040.md` |
| Port 49689 brief | `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\e5f2fe76\researcher_c_49689.md` |
| Worker transcript (timed out at 30 min, no end-state output) | `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\3dc6e5cd_worker_0_transcript.jsonl` |
| Live ground truth | `netstat -ano`, `Get-NetTCPConnection`, `Get-CimInstance Win32_Service` on host — see port table in §3 |

## 7. Residual Unknowns

- **SMB user-share enumeration without null session.** `Get-CimInstance` evidence shows the four default shares but not whether user-created shares exist; null-session `NetShareEnum` was not run end-to-end.
- **VMware 902 TLS handshake specifics.** The VMware "SSL prelude" byte before the TLS record is described in the SDK but was not transcribed into the brief; the 902 banner itself was confirmed.
- **GlideX 4-byte prefix (`8e 27 e5 ac`) semantics.** Could be a per-host magic, per-session cookie, or protocol/version tag — **low confidence** without dynamic instrumentation (`Procmon` + Wireshark on a GlideX session).
- **GlideX 51213 streaming port.** Confirmed advertised in the banner; not separately probed.
- **CDPSvc 2021–2023 CVE IDs.** Multiple `LocalService → SYSTEM` EoP advisories are recalled but specific IDs were not confirmed against live MSRC (web access unavailable to the research subagent).
- **Workstation 17.6 / 18.x default for TCP 912.** Recent versions may have changed whether 912 is bound by default — not verified.
- **NTLM / Kerberos posture of `sheryllguay` in `ucsihq.edu`.** Domain-joined context means the real risk of 445 depends on domain policy; not validated.
- **Worker subagent timeout.** The worker subagent timed out at 30 min before producing a structured report; the present synthesis uses the curated ground-truth table and the three research briefs as its inputs in lieu of the worker's own end-state deliverable.