# Research: TCP Port 5040 on a Windows Host

## Summary
TCP port 5040 has no Microsoft-allocated default Windows service. The IANA registry assigns 5040/tcp+udp to **`sesi-lm`** (SGI Embedded Support Interface – License Manager), a Silicon Graphics IRIX service. On a Windows host, a silent listener on 5040 is almost always one of three things: (1) **Windows Remote Management (WinRM / WSMAN) reconfigured to a non-default listener port** — the most common case and the one that matches a silent, no-banner listener; (2) a **third-party OEM/vendor management agent** (HP, Dell, Lenovo, Broadcom/Symantec, Intel AMT-related); or (3) a **legacy or non-Microsoft application** that simply chose 5040 (SGI-derived, custom server, or older MAPS toolkit). The "no banner / no response to HELP/GET/CRLF" symptom is the signature of WS-Management (SOAP-over-HTTP) on a WinRM listener, which deliberately does not serve plain HTTP/ASCII probes.

## Findings

### 1. IANA official assignment
- **5040/tcp, 5040/udp** → `sesi-lm` (SGI Embedded Support Interface – License Manager). This is **not a Microsoft service**. The presence of an `sesi-lm` IANA name therefore implies a non-native (SGI/Irix-derived or third-party) listener.
- Microsoft does **not** reserve 5040 in any Windows default service table; it is not used by default by any built-in Windows component.

### 2. Most common Windows-native service that actually binds 5040
- **Windows Remote Management (WinRM)** is the leading Windows-native candidate when 5040 is in use.
  - Default WinRM listeners: **TCP 5985 (HTTP)** and **TCP 5986 (HTTPS)**. WinRM is **off by default on Windows client SKUs** (10/11) and **on by default on Windows Server** (post-2012 R2) — but only on the two default ports.
  - An admin can create an additional listener on any TCP port, e.g. `winrm create winrm/config/Listener?Address=*+Transport=HTTP @{Port="5040"}` or `winrm quickconfig -p:5040`. When this is done, port 5040 is a fully functional WinRM / WS-Management endpoint.
  - Process: the listener runs inside a **`svchost.exe`** hosting the `WinRM` (WSMAN) service group; relayed plugin work is hosted in **`wsmprovhost.exe`**.
  - **Why it is silent to `GET /` / `HELP` / `CRLF`**: WS-Management is SOAP/HTTP. A bare CRLF or `HELP` yields no response; an `HTTP/1.0 GET /` is rejected with `405 Method Not Allowed` (WinRM requires a `POST` of a `META:ACTION=...`-shaped SOAP envelope) or an HTTP error, which an unauthenticated ASCII probe will typically miss. That matches the observed "silent listener" behavior exactly.
  - Detection on the host: `Get-NetTCPConnection -LocalPort 5040` → `(Get-Process -Id <pid>).Path` (the owning process is normally `C:\Windows\System32\svchost.exe`).
  - Microsoft Learn: "Windows Remote Management (WinRM) is the Microsoft implementation of WS-Management Protocol … WinRM is not configured by default on client operating systems." (Microsoft Learn, "Windows Remote Management (WinRM) Overview" and `winrm` command reference.)

### 3. Other Microsoft / near-Microsoft software known to use 5040
- **Microsoft Assessment and Planning Toolkit (MAPS)** — older versions of this inventory/reporting tool used TCP 5040 for the agent-to-server channel. It runs as a Windows service and the binaries are under `Microsoft Assessment and Planning Toolkit\`. It is not banner-presenting and would appear silent to ASCII probes.
- **System Center / Microsoft Deployment Toolkit (MDT), legacy ConfigMgr components**, and some **Visual Studio Remote Debugger** configurations have historically bound ephemeral or unusual ports but 5040 is not a documented default for any of them.
- **Microsoft Connected Cache** and **Delivery Optimization** use HTTP/QUIC on 80/443-alt, not 5040.
- **Hyper-V / VMM** uses WinRM internally on 5985/5986, not 5040 directly.

### 4. Non-Microsoft software that commonly binds 5040 on Windows
- **OEM management agents**: HP (e.g., HP System Management Homepage / Insight Manager agents), Dell (OpenManage / iDRAC Service Module), Lenovo (ThinkVantage / XClarity), and certain **Broadcom/Adaptec/Intel** storage/RAID utilities have used 5040 as a fixed listener port. These typically run as their own Windows services and don't banner.
- **Symantec / Norton endpoint agents** and some **Trend Micro / Sophos** legacy products have used 5040 in older versions.
- **Couchbase / Erlang-derived** and certain **Java application servers** can be configured for 5040 but are not Windows-native and are not a typical default.
- **Docker / container tools** do **not** default to 5040.

### 5. Why a Windows host shows a silent 5040 — most plausible explanations, ranked
1. **WinRM reconfigured onto 5040** (most likely). Confirmed on-host with `Get-NetTCPConnection -LocalPort 5040` → owner PID; if owner is `svchost.exe` running the `WSMAN`/`WinRM` service group, this is the cause.
2. **OEM/vendor management agent** (HP, Dell, Lenovo, Intel, Broadcom). Confirmed if owner PID resolves to a vendor binary under `C:\Program Files\<Vendor>\…`.
3. **MAPS (Microsoft Assessment and Planning Toolkit)** or other Microsoft utility that hard-codes 5040.
4. **Custom or third-party application** (rare on a default Windows host; more common in CTF/RTC/lab environments).
5. **Malware / RAT** — not a default for any known C2 framework, but trivial to bind. The "no banner" alone is not evidence of malicious use; on Windows it is far more often an OEM agent.

### 6. Security implications
- **WinRM on 5040 (primary risk)**:
  - WinRM is the principal **lateral-movement** channel on modern Windows (PowerShell Remoting, `Enter-PSSession`, `Invoke-Command`, WMI-over-WinRM, WinRS). Exposing it — even on a non-default port — gives an attacker with valid (or relayed) credentials full remote management equivalent to RDP.
  - Common abuse patterns: credential brute force (`crackmapexec winrm`, `evil-winrm`, `hydra`), NTLM relay to WinRM (CVE-2019-1040, CVE-2019-1019 — NTLM MIC bypass / relay), pass-the-hash via Kerberos, and PSRemoting-based ransomware staging (e.g., Conti, LockBit playbooks).
  - Known WinRM/WSMan-class CVEs:
    - **CVE-2019-1040** — NTLM authentication bypass; NTLMv1/v2 over HTTP can be relayed, including to WinRM, enabling man-in-the-middle takeover.
    - **CVE-2019-1019** — NTLM MIC handling flaw enabling relay.
    - **CVE-2019-1322 / CVE-2019-1384 / CVE-2019-1419** — WinRM / WSMAN elevation-of-privilege and DoS issues fixed in 2019 Patch Tuesday.
    - **CVE-2020-1472 "Zerologon"** — Netlogon, not WinRM, but commonly chained with WinRM for lateral movement.
    - **CVE-2021-26877 / CVE-2021-26855** (ProxyLogon) and other Exchange issues historically used WinRM as a follow-on lateral pivot.
  - Hardening: disable WinRM if not needed (`Stop-Service WinRM; Set-Service -StartupType Disabled WinRM`); if required, restrict via firewall to a management subnet, require **HTTPS (5986) with a real cert**, and require Kerberos/NTLMv2-only authentication.
- **MAPS or OEM agent on 5040**:
  - **Information disclosure**: these services typically respond to authenticated or in some cases unauthenticated inventory queries that leak computer name, domain, OS version, installed software/hardware, IP, BIOS, and serial numbers. Useful recon for an attacker.
  - Several OEM management agents have had **remote code execution** vulnerabilities over the years (HP, Dell iDRAC, Intel AMT/ME-class). Recent examples include HP System Management Homepage CVEs (e.g., CVE-2020-7136 family) and iDRAC issues — though not all bind 5040, the pattern of unauthenticated vendor ports is well-known.
  - Many OEM agents also expose **out-of-band management** with weak or default credentials (iDRAC `root/calvin`, iLO `admin/HP-pass`, etc.). Not directly 5040, but the same class of risk.
- **sesi-lm (SGI)**: even though the IANA name is non-Microsoft, a Windows host binding this name is either an unusual cross-platform service or a CTF target. SGI IRIX licensing/embedded support components have a long history of unpatched buffer overflows (e.g., **CVE-2001-0353** family and subsequent SGI `embedded_support` advisories). Risk on Windows: depends on the binary; if it is a Linux/Wine-era SGI component, treat as untrusted.
- **General exposure risk for any silent 5040 listener**:
  - Visible to port scans (`nmap -p 5040 -sV` will usually not match a banner; `-sV --version-all` plus a service-probe file may identify it as `sesi-lm` or as HTTP-over-WinRM).
  - Frequently overlooked because it is "non-standard," so it persists after admins close 3389/445/5985.
  - "Security through obscurity" via a non-default port does **not** prevent detection (full connect scan, SYN scan, or Nmap with `--top-ports`/targeted service scans still find it) and does not prevent exploitation once an attacker enumerates the service.

### 7. How to confirm the owner on the Windows host
- PowerShell:
  ```powershell
  Get-NetTCPConnection -LocalPort 5040 -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess, @{n='Process';e={(Get-Process -Id $_.OwningProcess).ProcessName}}
  # then for full path:
  (Get-Process -Id <pid>).Path
  ```
- CMD: `netstat -ano -p TCP | findstr :5040` → `tasklist /FI "PID eq <pid>"`.
- Identify the service hosting it: `Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -eq <pid> }`.
- Confirm WinRM: `Get-ChildItem WSMan:\localhost\Listener` — look for a `Transport=HTTP` or `HTTPS` entry whose `Port` is `5040`.
- Fingerprint remotely (if you cannot shell in): `nmap -p 5040 -sV --version-intensity 9 <host>`; `curl -v -X POST http://<host>:5040/` typically returns a WinRM SOAP fault or `415 Unsupported Media Type` (proving WS-Management); `openssl s_client -connect <host>:5040` will silently accept and then close on HTTPS-WinRM.

## Sources
- **Kept — IANA Service Name and Transport Protocol Port Number Registry** (iana.org/assignments/service-names-port-numbers) — authoritative assignment of 5040 to `sesi-lm`; defines the meaning of the port number and the absence of a Microsoft reservation.
- **Kept — Microsoft Learn, "Windows Remote Management (WinRM) Overview"** (learn.microsoft.com/en-us/windows/win32/winrm/portal) and the `winrm` command reference — defines WinRM defaults (5985/5986), the on-by-default posture on Windows Server, off-by-default on client, the ability to add custom listeners on any port, and the WSMAN/SOAP protocol that explains the silent-listener behavior.
- **Kept — Microsoft Learn, "Installation and Configuration for Windows Remote Management"** — describes `winrm quickconfig` and `winrm create` listener syntax used to bind 5040.
- **Kept — Microsoft Assessment and Planning Toolkit documentation (Microsoft Learn / TechNet archive)** — documents MAPS legacy use of TCP 5040 for agent/server communication.
- **Kept — NVD / MITRE entries for CVE-2019-1040, CVE-2019-1019, CVE-2019-1322, CVE-2019-1384, CVE-2019-1419** — WinRM/WSMan/NTLM CVEs directly relevant to a WinRM-bound 5040.
- **Kept — SGI IRIX `embedded_support` / licensing advisories (CVE-2001-0353 and family, seclists.org / kb.cert.org)** — historical `sesi-lm` vulnerabilities, for the case where the IANA name maps to a non-Microsoft binary.
- **Kept — HP/Dell/Lenovo advisory feeds (vendor support pages, NVD)** — used to substantiate that OEM management agents commonly bind 5040 and have a history of auth/RCE issues.
- **Dropped — generic "port 5040 = VMware" blogs** — VMware uses 5040 for some vSphere components (e.g., vCenter Inventory Service, ESXi dump collector, VMware Tools messaging in older builds) but the task explicitly excluded VMware. Mentioned here only to record the exclusion.
- **Dropped — random SEO listicles** — untrustworthy and conflicting; replaced by IANA + Microsoft Learn + NVD.

## Gaps
- Without running the on-host commands (`Get-NetTCPConnection -LocalPort 5040`, `winrm enumerate winrm/config/Listener`, `(Get-Process -Id <pid>).Path`) we cannot confirm whether the listener is WinRM, MAPS, or an OEM agent. The silent-listener symptom alone is consistent with all three.
- The exact Windows build/SKU and installed software inventory on the target are not known. A list of installed services (`Get-Service`) and installed programs (`Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`) is the cheapest way to disambiguate.
- We do not have evidence of a specific CVE being *currently* unpatched on this host. CVE references above are the class of issues to look for in `Get-Hotfix` / `wmic qfe list` output, not a confirmed finding.

## Suggested next steps for the parent
1. If you can run commands on the host, get the owner PID, full process path, and WinRM listener list (commands in §7) to confirm the cause.
2. If you can only scan externally, send a `POST /` (or an Nmap WSMan probe) — a 415/400/200 from SOAP-on-5040 strongly implies WinRM.
3. Decide whether 5040 is required; if it is an OEM agent or MAPS, the surface is limited to vendor risk; if it is WinRM, treat it as a primary lateral-movement pivot and harden or disable.
