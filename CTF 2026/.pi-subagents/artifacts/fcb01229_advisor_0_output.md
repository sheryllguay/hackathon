# Per-Port Risk Summary — 10.181.33.90

## Inherited decisions (contract)
- Researcher A established port 5040 is most plausibly WinRM/WSMAN rebound to non-default (svchost + wsmprovhost), with OEM agent as fallback hypothesis.
- Researcher B established port 49689 is a dynamic-RPC-range endpoint, owner ambiguous, silent is expected; identification requires `Get-NetTcpConnection` / `netstat -ano` from a foothold.
- Host resets malformed SMB — treated as a defensive signal, not as OS fingerprint. No version disclosure from 445.
- Two distinct VMware auth daemon versions (1.10 vs 1.0) is treated as an anomaly worth noting, not a single misread banner.

## Per-port findings

**135 — Microsoft RPC Endpoint Mapper (RPCSS)**
- Service / owner: `svchost.exe` (RPCSS service group), kernel-level endpoint mapper
- What it is: Standard Windows service mapper; always present. UUID enumeration possible.
- Risk note: Medium. Recon asset. `rpcdump.py` / `epdump` will enumerate all bound RPC UUIDs (DcomLaunch, SCM, LSAMR, eventlog, etc.) — direct feeder for lateral-movement targeting. Patch levels here are less interesting than the UUID set it exposes.

**139 — NetBIOS Session Service**
- Service / owner: `svchost.exe` (LanmanServer)
- What it is: Legacy SMB1-over-NetBIOS transport; on modern Windows only present if NetBIOS-over-TCP is still enabled (often default for domain members / older GPO baselines).
- Risk note: Medium. NBT name disclosure (`nbtstat -A`, `nbtscan`), NetBIOS NS poisoning (responder), and NTLMv1/v2 reflection. The fact that 139 is open *in addition to* 445 means NetBIOS-over-TCP is not fully disabled — a hardening gap.

**445 — Microsoft SMB (Direct Host)**
- Service / owner: `svchost.exe` (LanmanServer)
- What it is: Default SMB listener. Banner resets malformed packets — strongly suggests an in-line HIPS/EDR component (Defender ASR, CrowdStrike, SentinelOne, or a network IPS) terminating bad SMB before the kernel driver. Not a version disclosure vector.
- Risk note: **Critical (attack surface)** / **informative (defensive signal)**. Pre-auth RCE history: MS17-010 (EternalBlue), CVE-2020-0796 (SMBGhost), CVE-2020-1206 (SMBleed). Coercion surface: PetitPotam, DFSCoerce, PrinterBug, ShadowCoerce → NTLM relay → ADCS ESC8. Auth surface: NTLMv1 downgrades, signing-not-required misconfigs. *Use the reset behavior as evidence the host is instrumented — weight loud exploits lower, weight relay/coercion/credential paths higher.*

**902 — VMware Authentication Daemon v1.10**
- Service / owner: VMware host service (`vmware-hostd` / `vpxd` family) or, in a guest, the vSphere/ESXi management listener forwarded.
- What it is: vCenter/ESXi auth front-door. Banner: *"SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC, NFCSSL supported"* — confirms the TLS data plane; plaintext only echoes banner.
- Risk note: High. Internet-exposed VMware appliances are a top-3 RCE target. Recent relevant: VMSA-2023-0023 (vmtoolsd RCE), VMSA-2022-0022 (CVE-2022-22972 auth bypass, 9.8), VMSA-2021-0028 (vCenter RCE cluster — CVE-2021-21972/21973/21974/22005/21985), VMSA-2024-0010 / VMSA-2025-0003 series. Two auth daemons with *different* major versions on the same host is anomalous — likely a guest running alongside a nested ESXi, or two VMware services (vCenter + ESXi management) on one box. Worth confirming version provenance.

**912 — VMware Authentication Daemon v1.0**
- Service / owner: Same VMware family as 902; "1.0" is a *much* older build line than "1.10" co-resident.
- What it is: Either an older/legacy VMware component (Workstation-era, ESXi 5.x line, or a separate management plane) or a deliberate "Management API on alt port" pattern.
- Risk note: High. v1.0 is well behind current support — pre-dates most recent VMSA patches. If this is a real production management endpoint and not a marketing-stub version string, it is the most likely single-port RCE on the host. Confirm with `ssl-tls` after STARTTLS-equivalent and capture actual build.

**5040 — Silent TCP (per Researcher A)**
- Service / likely owner: Top hypothesis: **WinRM/WSMAN rebound to non-default** (svchost.exe in the `netsvcs`/`wsmprovhost.exe` group). Alternatives: OEM management agent (HP iLO AMS, Dell OMCI, Broadcom/Intel AMT, Lenovo LxPM), MAPS-style app.
- What it probably is: WS-Management SOAP/HTTPS listener — silently drops ASCII probes (`HELP`, `GET`, `CRLF`) because they aren't valid WS-MAN `POST` envelopes. This is the *expected* behavior, not a custom backdoor signature.
- Risk note: **High — if WinRM, this is a primary lateral-movement channel.** CVEs: CVE-2019-1040 (NTLM relay via WSMAN), CVE-2019-1019, CVE-2019-1322, CVE-2019-1384, CVE-2019-1419 (NTLM hashes leaked via WSMAN), plus PSRemoting abuse, CredSSP/Roasting paths. Non-default port is a known evasion of "monitor 5985/5986 only" detections. Identification action: from a foothold, `Get-NetTCPConnection -LocalPort 5040 -State Listen` → look for svchost PID whose service list contains `WinRM` / `WMSVC`.

**49689 — Silent TCP (per Researcher B)**
- Service / likely owner: Ambiguous — inside the dynamic RPC range (49152–65535). Owner candidates: `lsass.exe` (Netlogon/LSA RPC), Print Spooler (`spoolsv.exe`), MSDTC (`msdtc.exe`), `vmtoolsd.exe` (given ports 902/912 are present, this is *elevated probability*), `svchost -k DcomLaunch` (WMI/RPCSS), or `MsSense.exe` (MDE).
- What it probably is: An ephemeral MS-RPC endpoint, dynamically bound. Silent under ASCII probes is normal — the wire protocol is binary, not text.
- Risk note: **Owner-dependent, range from informational to critical.**
  - If `lsass.exe` / Netlogon → **critical**: Zerologon (CVE-2020-1472, pre-auth DA takeover).
  - If Print Spooler → **critical**: PrintNightmare (CVE-2021-34527, CVE-2021-1675), PointAndPrint driver-load abuse.
  - If MSDTC → **high**: CVE-2021-26411 (pre-auth RCE via deserialization), CVE-2021-28478.
  - If `vmtoolsd.exe` → **high**: VMSA-2023-0023 guest-to-host RCE, file/clipboard backchannel abuse.
  - If WMI/DCOM → **medium**: lateral movement via `wmic`, DCOM object construction.
  - If `MsSense.exe` → benign (Microsoft Defender for Endpoint telemetry).
- Identification action (mandatory before further enumeration): `Get-NetTCPConnection -LocalPort 49689 -State Listen` → resolve PID → `(Get-CimInstance Win32_Process -Filter "ProcessId=<pid>").Name` and `(Get-WmiObject Win32_Service | Where-Object {$_.ProcessId -eq <pid>}).Name`.

## Cross-port observations (advisory)

1. **VMware cluster signature is real.** 902 + 912 + 49689's high vmtoolsd probability mean this host is almost certainly either (a) a VMware *guest* with VMware Tools installed, or (b) a workstation/box running nested virtualization. v1.0 vs v1.10 version split is the single most useful anomaly to chase — it should be confirmed via TLS handshake + version probe, not trusted from the banner.
2. **The SMB reset behavior is a defensive signal, not a vulnerability.** Treat as "this host is instrumented"; down-weight noisy pre-auth exploits, up-weight relay/coercion/authentication-paths.
3. **139 + 445 both open = NetBIOS-over-TCP is enabled.** Even on hardened Windows, this is often left on by default for domain-joined hosts. It's a small hardening win to disable if not required.
4. **5040 is the highest-value identification target.** If it's WinRM rebound, the operator has deliberately evaded 5985/5986 monitoring — a behavioral indicator, not a technical one. If it's an OEM agent, the attack profile changes entirely (Intel AMT historically = own OS, own creds, often unpatched).
5. **49689 owner identification is the only remaining unknown that can change severity by 2+ classes.** No further recon is meaningful until owner is confirmed from a foothold or via Out-of-Band capability.

## Recommended next moves
- **Must-do (no foothold required):** TLS-handshake 902/912 and capture the real `x-powered-by` / build string. Resolve the 1.0 vs 1.10 discrepancy.
- **Must-do (requires foothold):** `netstat -ano` for 5040 and 49689, resolve PIDs to services. Without this, both ports stay unrated.
- **Should-do:** RPC endpoint dump against 135 (`impacket-rpcdump`/`epdump`) — pure recon, high yield.
- **Avoid:** Noisy pre-auth SMB exploits against 445 — the reset behavior tells you they're going to be caught. Prioritize NTLM relay surface (SMB signing, ESC8, coerce-and-relay) instead.

---