# Research: TCP 5040 / CDPSvc on Windows 11 24H2 (build 26200)

> **Tooling note (residual risk).** No `web_search` or `fetch` tool is available
> in this research subagent's runtime. The findings below are derived from
> training knowledge of public Microsoft Learn / MSRC / NVD material and prior
> industry reporting on the Connected Devices Platform (CDP, formerly "Project
> Rome"). Specific CVE identifiers, byte-level protocol layout, and exact
> version-fix tables are flagged with a confidence rating and should be
> re-verified against live MSRC / NVD pages before any defensive action is
> taken.

## Summary
TCP/5040 on a stock Windows 11 24H2 host is the listener for **CDPSvc** (the
Connected Devices Platform Service), a `svchost -k LocalService -p` group that
backs Phone Link, "Continue on PC", Nearby Sharing, and Microsoft Edge's
"Send to devices" / cross-device pick-up. The on-the-wire protocol is a
**proprietary Microsoft binary framing** over TCP, not HTTP and not DCE/RPC
(consistent with the "silent server" observation). The port has **no public
broad internet exposure by default**; Windows Firewall blocks 5040 on the
Public profile, so a 0.0.0.0 bind is only risky when the host is on a shared
private network or the firewall rule has been weakened.

## What it is
CDPSvc is a Windows service introduced in Windows 10 1709 (Fall Creators
Update, 2017) and carried forward through Windows 11. The service DLL
(`CDPSvc.dll`) is loaded into the `LocalService` svchost group with the `-p`
flag, which is Microsoft's "LocalService with network SID restrictions
relaxed" mode — it is **not** NetworkRestricted. It implements the
Connected Devices Platform, the API surface that apps like Phone Link,
Microsoft Edge, OneDrive, and Cortana use to enumerate, register, and
exchange messages with the user's other signed-in devices.

(Confidence: **high** for service identity and svchost grouping;
**medium** for the exact DLL name and `-p` flag semantics on 24H2.)

## Protocol on 5040
- **Transport: TCP.** 5040 is the canonical CDPSvc listener port. There is
  also a UDP path used for mDNS-based device discovery on 5353, but 5040
  itself is TCP. (Confidence: **high**.)
- The wire protocol is a **custom Microsoft binary protocol** with
  RPC-style request/response semantics. There is no HTTP `Server:` header,
  which matches the observed "no banner on raw GET" behaviour. (Confidence:
  **high** that it is non-HTTP and non-DCE/RPC; **low** on the exact frame
  layout — treat as proprietary.)
- CDPSvc also exposes:
  - A named pipe `\.\pipe\CDPSvc` for in-box local callers.
  - A second TCP port commonly cited as **5240** in the Phone Link /
    "Your Phone" app, used for the higher-bandwidth media/notification
    path. (Confidence: **medium** — I have seen 5240 cited in third-party
    write-ups; the Microsoft documentation that pins 5240 to CDPSvc is
    harder to pin down in memory.)
- The "no banner, no GET response, no DCE/RPC bind response" fingerprint
  you observed is **consistent** with CDPSvc: it is a binary, length-
  prefixed protocol that does not respond to malformed/foreign
  handshakes. (Confidence: **high**.)

## Attack surface
1. **Default bind.** CDPSvc binds to `0.0.0.0` (and IPv6 `::`) on a clean
   install. This is by design — the service expects to be reached from
   other devices on the same LAN/Personal-Area-Network. (Confidence:
   **high**.)
2. **Authentication model.** CDP uses **per-user device pairing** (a shared
   secret provisioned via QR code, Microsoft-account OAuth, or a one-time
   PIN). Without a paired credential, a remote peer can typically:
   - Detect the service (the port is open).
   - Receive the device's public descriptor.
   - Send a **small set of unauthenticated "announce / pair-request"
     messages** but not the privileged message types (file read/write,
     notification relay, SMS, screen projection, etc.).
   Once a device is paired, the surface widens significantly (clipboard
   sync, SMS/notification mirroring, file transfer, screen control in some
   builds). (Confidence: **medium-high** on the pairing model; **low** on
   the exact list of unauthenticated message types — research has not
   published a clean enumeration.)
3. **Privilege.** Although the network-facing handler runs as LocalService,
   CDP's design has been a recurring target for **local** privilege-
   escalation chains, because several components in the LocalService group
   have weak ACLs or unsafe RPC entrypoints. A successful local exploit
   against CDPSvc typically lands the attacker as LocalService, which is
   one service-hop from SYSTEM on many boxes. (Confidence: **medium**.)
4. **Public exposure.** Windows Firewall on a default install blocks 5040
   inbound on the **Public** profile and allows it on **Private** and
   **Domain** profiles. So a 0.0.0.0 bind is *not* automatically a
   remote-internet exposure — it is a **LAN exposure** unless the host's
   network profile has been downgraded or the firewall rule has been
   removed. (Confidence: **high**.)
5. **Stack-level exposure.** Because the listener uses TCP/IP, it is
   transit-reachable for any RCE-class vulnerability in the Windows
   TCP/IP driver itself (see CVE below).

## Known CVEs (with confidence)
- **CVE-2024-38063** — Windows TCP/IP IPv6 RCE (July 2024 Patch Tuesday,
  CVSS 9.8). This is a **pre-auth, network-reachable** RCE in the IPv6
  stack. CDPSvc does not have to be running for it to be exploited, but
  any host listening on TCP over IPv6 is a target. Fix requires the
  July 2024 cumulative update. (Confidence: **high** — this CVE is well-
  documented in MSRC and NVD.)
- **CVE-2022-30115 ("Follina")** — Microsoft Support Diagnostic Tool
  (MSDT) RCE. Not a CDPSvc vulnerability per se, but the underlying
  `ms-msdt:` handler and a number of CDP-related document-handling
  paths were both weaponised by the same class of Office-borne
  payload chains in 2022. Worth keeping in mind when triaging CDP-adjacent
  telemetry. (Confidence: **high** for the CVE itself; **low** for any
  direct CDPSvc attribution.)
- **CDPSvc-specific EoP cluster (2021-2023).** My training data has
  references to multiple MSRC advisories titled *"Windows Connected
  Devices Platform Service Elevation of Privilege Vulnerability"*
  (typically `LocalService → SYSTEM` via a crafted COM/RPC call to
  `CDPSvc.dll`). I am **not** confident enough in the specific CVE
  numbers to list them without verification; treat as residual risk and
  query MSRC for "CDPSvc" in 2021-2024. (Confidence: **low** on IDs,
  **medium-high** on the fact that this class of bug has shipped
  multiple times.)
- **CVE-2023-21768** — AFD.sys (Winsock filter driver) EoP. Affects any
  process opening many sockets, including CDPSvc; relevant as a chained
  step in CDP-related exploit chains. (Confidence: **high** for the
  CVE; **medium** for its relevance to a 5040-specific chain.)

## Hardening (in priority order)
1. **Patch aggressively.** Make sure the July 2024 cumulative update
   (CVE-2024-38063) and all subsequent CDPSvc fixes are installed.
2. **Do not weaken the firewall rule** that blocks 5040 on Public
   profiles. Verify with:
   `netsh advfirewall firewall show rule name="Connected Devices
   Platform Service"` (rule names vary slightly by build).
3. **Restrict the listener to Private and Domain profiles** if possible
   (this is already the default).
4. **Disable CDPSvc** if the host has no need for Phone Link / "Send to
   devices" / Nearby Sharing:
   `Stop-Service CDPSvc; Set-Service CDPSvc -StartupType Disabled`
   (PowerShell). Note: Microsoft Edge and OneDrive will lose cross-
   device features.
5. **Audit paired devices** periodically under
   *Settings → Bluetooth & devices → Mobile devices / Phone Link*.
6. **Network posture.** Treat any 0.0.0.0 listener on a multi-tenant
   network as in-scope for the threat model.

## References (with confidence)
1. **Microsoft Learn — Connected Devices Platform (overview).**
   The public Learn hub for CDP/Project Rome. (Confidence: **medium** —
   URLs on Learn migrate; search `site:learn.microsoft.com
   "Connected Devices Platform"`.
2. **MSRC — CVE-2024-38063 security update guide.**
   Authoritative for the IPv6 RCE, including the affected-build table.
3. **NVD — CVE-2024-38063 entry.** Independent confirmation of CVSS,
   vectors, and references.
4. **Public security research on Phone Link / "Your Phone" protocol
   analysis** (several independent write-ups during 2019-2022 documented
   the pairing model and the 5040 listener; use as a starting point for
   fuzzing, not as a spec).

## Gaps and residual risk
- **Exact byte-level framing** of the 5040 protocol: not in public spec.
  Needs a Wireshark trace or IDA session on `CDPSvc.dll` to enumerate.
- **Specific CDPSvc CVE IDs from 2021-2023**: should be re-queried on
  MSRC by title rather than by my recalled numbers.
- **Whether `wcss.exe` (Windows CardSpace) ever used 5040**: training
  data associates CardSpace with the deprecated "CardSpace / Windows
  CardSpace" identity service, but I cannot confidently confirm that
  `wcss.exe` (or `idsvc`) listened on 5040 versus a different port.
  CardSpace has been **disabled-by-default and removed** from modern
  Windows builds, so on a 24H2 host it should not be a competing
  listener — but a residual stale service entry is a real possibility on
  upgraded machines. (Confidence: **low** — verify with
  `Get-Service | ? Name -like '*card*'`.)
- **Service Control Manager remote protocol**: that is the **DCE/RPC
  endpoint on TCP/135** (the port mapper), not 5040. The prompt's
  suggestion that 5040 has been used by "SCM remote protocol" is
  almost certainly wrong; SCM does not natively listen on 5040. (Confidence:
  **high**.)
- **The `5240` second-port claim** should be verified against a live
  `netstat -ano` on the target.
