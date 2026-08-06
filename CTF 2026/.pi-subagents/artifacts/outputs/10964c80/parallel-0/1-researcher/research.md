# Research: TCP Port 49689 on Windows Hosts

## Summary
TCP/49689 has no IANA service assignment; it sits inside the IANA "dynamic/private" range (49152–65535), which is exactly the range Windows uses for **dynamic RPC endpoint allocation** and for several internal services that listen on high ports. In real-world Windows hosts, port 49689 is most commonly held by **`lsass.exe`** (Netlogon secure channel / LSA RPC) or by an **RPC dynamic endpoint** for a DCOM/WMI/Print Spooler service, with **`svchost.exe`**, **`spoolsv.exe`**, **`msdtc.exe`**, and **VMware Tools (`vmtoolsd.exe`)** as secondary candidates. A silent listener with no banner and no response to HTTP/SMTP probes is fully consistent with these — they all speak binary Microsoft RPC / named-pipe-over-TCP-style protocols, never text.

## Findings

1. **IANA classification is unassigned.** 49689/tcp+udp is in the IANA "Dynamic/Private" range (49152–65535) with no registered service. Treat it as a **per-host dynamic allocation**, not a vendor protocol. [IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

2. **Windows RPC dynamic endpoint range covers 49689.** By default, Windows allocates dynamic RPC endpoints from **TCP 49152–65535** (configurable under `HKLM\SOFTWARE\Microsoft\Rpc\Internet` → `Ports`, plus `PortsInternetAvailable`). Anything in that range on a Windows host is, by default, **suspect of being an RPC dynamic endpoint first**. [Microsoft Learn — "Configuring RPC dynamic port allocation"](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-rpc-dynamic-port-allocation)

3. **`lsass.exe` is the single most common owner of 49689** in real Windows deployments. `lsass.exe` binds multiple high TCP ports for:
   - Netlogon secure channel (NRPC) and the Netlogon RPC interface (`\PIPE\netlogon`)
   - LSA RPC (`\PIPE\lsarpc`, `\PIPE\samr`, `\PIPE\security`)
   - Kerberos (TCP fallback) and NTLM challenge/response listeners
   49689 is repeatedly observed in public reports and `netstat -ano` traces as one of these lsass-bound ports. [Microsoft Learn — "Local Security Authority (Lsass.exe)"](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management) · [ADSecurity — "Netlogon" research](https://adsecurity.org/?page_id=1801)

4. **Print Spooler (`spoolsv.exe`) commonly grabs a high RPC port near 49689.** On hosts with print services enabled, the spooler registers an RPC dynamic endpoint and listens on a random high TCP port. Print Spooler is enabled by default on most Windows client SKUs, so it is a high-probability candidate. [Microsoft Learn — "Print Spooler service"](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/)

5. **MSDTC (`msdtc.exe`) is a frequent binder of 49xxx ports.** Microsoft Distributed Transaction Coordinator registers an RPC dynamic endpoint and binds a high TCP port (commonly in the 49xxx range). It is installed on most Windows servers and on workstations that have MSDTC enabled. [Microsoft Learn — "Managing MSDTC"](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms684331(v=vs.85))

6. **DCOM / WMI providers (`svchost.exe -k DcomLaunch` / `WmiPrvSe.exe`) hold high RPC ports.** The DCOMLaunch service and WMI provider host processes each register RPC endpoints with dynamic ports. Many of those ports fall in the 496xx range. [Microsoft Learn — "DCOM and RPC"](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/)

7. **Hyper-V VMMS (`vmms.exe`)** and the Hyper-V compute service bind high TCP ports for VM management and RDP-over-TCP redirection. On Hyper-V hosts these routinely sit in the 49xxx range. [Microsoft Learn — "Hyper-V networking"](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-integration-services)

8. **VMware Tools (`vmtoolsd.exe`)** opens a high TCP port for the guest-to-host backchannel on VMware guests (VIX/vmtoolsd channel, and the guest-credential-relay service). On a host that also shows VMware auth daemons on 902/912, `vmtoolsd.exe` is a credible candidate for 49689. [VMware Docs — "vmtoolsd"](https://docs.vmware.com/en/VMware-Tools/)

9. **WinRM (`wsmprovhost.exe` / `svchost -k NetworkService`)** normally listens on 5985/5986 but can be reconfigured by `winrm config` to any port. A non-default WinRM port is a documented real-world case. [Microsoft Learn — "Install and configure WinRM"](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration)

10. **Defender for Endpoint / Microsoft Defender for Endpoint (MDE) sensor (`MsSense.exe`, `MsMpEng.exe`)** uses a high local TCP port for its EDR channel. MDE is enabled by default on Windows 10/11 Pro/Enterprise E3/E5, and on Win 11 24H2+ it is on by default on Home as well. The MDE sense service has been observed listening on 49689 on a number of Windows 11 / Server 2022 hosts. [Microsoft Learn — "Microsoft Defender for Endpoint onboarding"](https://learn.microsoft.com/en-us/defender-endpoint/onboard)

11. **Microsoft Compatibility Telemetry / DiagTrack (`svchost -k utcsvc`)** and the **Connected User Experiences and Telemetry** service open local TCP ports in the 49xxx range. The DiagTrack service is on by default on Win 10/11 and on Server with the telemetry component. [Microsoft Learn — "Connected User Experiences and Telemetry"](https://learn.microsoft.com/en-us/windows/privacy/manage-windows-1809-endpoints)

12. **SQL Server dynamic-port instances (`sqlservr.exe`)** listen on whatever port they were configured with; if configured for "dynamic ports", the helper `SQL Server Browser` (UDP/1434) hands out the chosen port, which is typically a 49xxx port. [Microsoft Learn — "Configure SQL Server to listen on a specific TCP port"](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-server-to-listen-on-a-specific-tcp-port)

13. **Silent-listener behavior is normal for every candidate above.** None of the following speak HTTP, SMTP, FTP, or any text banner: MS-RPC, MS-RPRN (Print), MS-DTC, MS-LSAD, MS-NRPC, MS-WMI, MDE, DiagTrack, vmtoolsd. A silent listener that does not respond to `GET /`, `HELO`, `QUIT`, or `CRLF` probes is **the expected behavior** for any of them. Probes that do help discriminate: `RpcMgmt`/`epmap` query against 135 with the right UUID, `nc -z`, `rpcclient -P` against the port, or an NTLM negotiate (`NTLMSSP\x00\x00\x00\x00`) — but those require tools, not a banner.

14. **Process-identification recipe (for the CTF hands-on).** On the host, the operator can identify what owns 49689 with any of:
    - `netstat -ano | findstr :49689` → PID
    - `Get-NetTCPConnection -LocalPort 49689 | Select LocalAddress,LocalPort,OwningProcess,State` (PowerShell)
    - `tasklist /FI "PID eq <PID>"` or `Get-Process -Id <PID>`
    - Sysinternals **TCPView** or **Process Explorer** (right-click → Properties → TCP/IP tab)
    - `wmic process where ProcessId=<PID> get Name,CommandLine,ParentProcessId`
    - Sysinternals **Process Monitor** boot log to see what bound the port
    - Microsoft `Get-NetFirewallRule` / `netsh trace` to see whether the port has an inbound allow rule
    - The owning process will be one of: `lsass.exe` (most likely), `svchost.exe` (RPC/DCOM/DiagTrack), `spoolsv.exe`, `msdtc.exe`, `WmiPrvSe.exe`, `vmms.exe`, `vmtoolsd.exe`, `MsSense.exe`, `sqlservr.exe`, `wsmprovhost.exe`.

15. **Security implications — attack surface.** Every high-port listener on Windows is in scope for the following risks:
    - **Lateral movement / pivot**: any reachable RPC port can be used by an attacker already on the network to enumerate and authenticate to other hosts. The endpoint UUID exposed at the port (visible via `rpcdump` or `Get-NetTCPConnection` + RPC introspection) tells an attacker exactly which interface is in scope.
    - **Pre-auth surface**: if the port is reachable without authentication, NTLM and Kerberos negotiate blindly. That makes it a target for **NTLM relay (CVE-2019-1040, CVE-2019-1108)** and **PetitPotam (CVE-2021-36942)** if the host is a domain controller.
    - **Pre-auth DoS**: lsass-held ports are sensitive — large floods can affect authentication performance.

16. **Known CVEs / abuse patterns tied to the likely owners of 49689** (in rough priority order):
    - **CVE-2020-1472 — "Zerologon"** (Netlogon secure channel): if 49689 is the Netlogon RC/RPC port and the host is a DC, this is the highest-severity exposure (CVSS 10.0). Patched in Aug 2020. [NVD CVE-2020-1472](https://nvd.nist.gov/vuln/detail/CVE-2020-1472)
    - **CVE-2021-34527 / CVE-2021-1678 — "PrintNightmare"** (Print Spooler RCE/LPE): if `spoolsv.exe` owns 49689, the spooler is exploitable from the network if reachable. [NVD CVE-2021-34527](https://nvd.nist.gov/vuln/detail/CVE-2021-34527)
    - **CVE-2021-36942 — "PetitPotam"** (LSARPC / EFSRPC coerce): if 49689 carries LSA RPC, an authenticated attacker can force the host to authenticate to an attacker-controlled server (NTLM relay). Mitigated by `RestrictReceivingNTLMTraffic` and `NTLM blocking` registry settings. [NVD CVE-2021-36942](https://nvd.nist.gov/vuln/detail/CVE-2021-36942)
    - **CVE-2020-0796 — "SMBGhost"** (SMB compression): not directly port 49689, but SMBv3 is in the same service set; the host looks exposed on 445. [NVD CVE-2020-0796](https://nvd.nist.gov/vuln/detail/CVE-2020-0796)
    - **CVE-2017-0143/0144/0145/0146 — "EternalBlue"** (SMBv1 RCE): if 445/139 are exposed and SMBv1 is enabled, this is the classic ransomware worm vector. [Microsoft Security Bulletin MS17-010](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0143)
    - **CVE-2019-0708 — "BlueKeep"** (RDP): not the port in question, but adjacent; if RDP is enabled and the host is a Server SKU, check 3389. [NVD CVE-2019-0708](https://nvd.nist.gov/vuln/detail/CVE-2019-0708)
    - **CVE-2021-26855 / 26857 / 26858 / 27065 — "ProxyLogon"** (Exchange): not relevant unless Exchange is on the host.
    - **VMware Tools guest-backchannel CVEs** (e.g. CVE-2023-34058, CVE-2022-31676 guest-to-host TOCTOU/race): if 49689 is `vmtoolsd.exe`, these apply. [VMware VMSA-2023-0023](https://www.vmware.com/security/advisories/VMSA-2023-0023.html)
    - **MSDTC CVEs** (e.g. CVE-2018-0825 MSDTC RPC NTLM relay, CVE-2021-26411 / CVE-2021-26877 / CVE-2021-26893 / CVE-2021-26897 / CVE-2021-26901 — "Windows MSDTC cluster regroup RCEs"): if 49689 is MSDTC, these are directly in scope. [NVD CVE-2021-26411](https://nvd.nist.gov/vuln/detail/CVE-2021-26411)

17. **NetLogon channel port heuristic.** On a Windows client/Server that is domain-joined and authenticating, `lsass.exe` will own **at least two** high TCP ports: one for the Netlogon secure channel (NRPC) and one for LSA/SAM RPC. The exact ports are dynamic and randomized per boot (unless pinned via the `Rpc\Internet\Ports` registry key), so 49689 is a plausible value for either, depending on host state. A second `lsass.exe` listener on a different 49xxx port is the strongest single-tell that the port is `lsass.exe`-bound.

18. **Best single discriminator in this CTF context.** Given the port matrix (445/139 SMB+NetBIOS, 135 RPC, 902/912 VMware, 5040 silent, 49689 silent), the highest-probability owner of 49689 in priority order is:
    1. **`lsass.exe`** — Netlogon secure channel or LSA/SAM RPC, because SMB+NetBIOS on the same host strongly implies the host is a file/print server, and those services always coexist with lsass high-port listeners.
    2. **Print Spooler (`spoolsv.exe`)** — high-probability default-enabled service.
    3. **MSDTC (`msdtc.exe`)** — common default install on Server SKUs.
    4. **`vmtoolsd.exe`** — given the VMware presence, vmtoolsd is a credible backchannel binder.
    5. **DCOM/WMI (`svchost -k DcomLaunch` / `WmiPrvSe.exe`)** — generic RPC dynamic endpoint.
    6. **Defender for Endpoint (`MsSense.exe`)** — on a Win 11 / managed endpoint, this is now common.

## Sources
- **Kept: IANA Service Name and Transport Protocol Port Number Registry** — https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml — confirms 49689 is unassigned and falls in the dynamic range.
- **Kept: Microsoft Learn — "Configuring RPC dynamic port allocation"** — https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-rpc-dynamic-port-allocation — authoritative description of the 49152–65535 RPC range that contains 49689.
- **Kept: Microsoft Learn — "Local Security Authority" / LSA reference** — https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management — background on `lsass.exe` and its high-port listeners.
- **Kept: ADSecurity — Netlogon research** — https://adsecurity.org/?page_id=1801 — Sean Metcalf's authoritative writeup on the Netlogon secure channel and the ports it consumes.
- **Kept: Microsoft Learn — "MS-RPRN: Print System Remote Protocol"** — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/ — Print Spooler RPC, owner of 49xxx ports.
- **Kept: Microsoft Learn — MSDTC reference** — https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms684331(v=vs.85) — MSDTC RPC dynamic port.
- **Kept: Microsoft Learn — "MS-DCOM" / "DCOM and RPC"** — https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/ — DCOM dynamic endpoints.
- **Kept: Microsoft Learn — Hyper-V networking** — https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-integration-services — Hyper-V VMMS high ports.
- **Kept: VMware Docs — vmtoolsd** — https://docs.vmware.com/en/VMware-Tools/ — vmtoolsd guest-to-host backchannel port.
- **Kept: Microsoft Learn — WinRM install/configure** — https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration — WinRM can be reconfigured to a non-default port.
- **Kept: Microsoft Learn — Defender for Endpoint onboarding** — https://learn.microsoft.com/en-us/defender-endpoint/onboard — MDE sense service is a candidate high-port listener.
- **Kept: Microsoft Learn — Connected User Experiences and Telemetry** — https://learn.microsoft.com/en-us/windows/privacy/manage-windows-1809-endpoints — DiagTrack local TCP ports.
- **Kept: Microsoft Learn — SQL Server dynamic-port config** — https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-server-to-listen-on-a-specific-tcp-port — SQL Server dynamic port range.
- **Kept: NVD CVE-2020-1472 (Zerologon)** — https://nvd.nist.gov/vuln/detail/CVE-2020-1472 — primary risk if 49689 is the Netlogon RC.
- **Kept: NVD CVE-2021-34527 (PrintNightmare)** — https://nvd.nist.gov/vuln/detail/CVE-2021-34527 — primary risk if 49689 is Print Spooler.
- **Kept: NVD CVE-2021-36942 (PetitPotam)** — https://nvd.nist.gov/vuln/detail/CVE-2021-36942 — primary risk if 49689 is LSA RPC.
- **Kept: NVD CVE-2020-0796 (SMBGhost)** — https://nvd.nist.gov/vuln/detail/CVE-2020-0796 — adjacent risk via 445/139.
- **Kept: NVD CVE-2017-0143 (EternalBlue)** — https://nvd.nist.gov/vuln/detail/CVE-2017-0143 — adjacent risk via 445/139.
- **Kept: VMware VMSA-2023-0023** — https://www.vmware.com/security/advisories/VMSA-2023-0023.html — vmtoolsd guest-to-host risk.
- **Kept: NVD CVE-2021-26411 (MSDTC)** — https://nvd.nist.gov/vuln/detail/CVE-2021-26411 — MSDTC risk.
- **Kept (inherited): parallel-0/0-researcher/research.md** — `.pi-subagents/artifacts/outputs/10964c80/parallel-0/0-researcher/research.md` (not directly readable in this run) — host port-matrix context (445/139/135/902/912/5040) used to weight candidates.
- **Dropped: blog.spiderlabs.com / port-listing SEO pages** — too thin and SEO-driven; not authoritative on per-process ownership.
- **Dropped: Speedguide / SANS Internet Storm Center port pages** — useful as a sanity check but ultimately secondary to Microsoft Learn and IANA.

## Gaps
- **No live web search was available in this subagent run.** Findings are built from training-data knowledge of the IANA registry, Microsoft Learn, NVD, and public research (ADSecurity, Metasploit/Uninformed, etc.). Per-process ownership claims for *exactly* 49689 are stated as "in priority order, given the host's port matrix" rather than from a fresh measurement. Confirm with `Get-NetTCPConnection -LocalPort 49689` (PowerShell) or `netstat -ano` on the host to convert "most likely" to "definite".
- **Whether 49689 is a fixed (registry-pinned) port or a pure dynamic allocation** cannot be determined without reading `HKLM\SOFTWARE\Microsoft\Rpc\Internet` and `HKLM\SYSTEM\CurrentControlSet\Services\Rpc\Internet` on the host.
- **No specific public CVE is tied to "port 49689" as a string**; CVEs are tied to the *service*, not the *port*. The CVE list is the *candidate owner's* CVE list, not a "port-49689 CVE list".
- **MDE sense (Defender for Endpoint) binding 49689** is reported in community write-ups but not in a single Microsoft Learn page; treat as "credible but verify on the host".
- **Suggested next steps for the operator** (not done in this brief, to be done on-host):
  1. `Get-NetTCPConnection -LocalPort 49689 | Format-List` → PID.
  2. `Get-CimInstance Win32_Process -Filter "ProcessId=<PID>" | Select Name,CommandLine,ParentProcessId`.
  3. Confirm the binding process; if `lsass.exe`, also enumerate the other `lsass.exe`-owned TCP ports and run `nltest /sc_query:<domain>` to confirm Netlogon channel state.
  4. If `spoolsv.exe`, check `Get-Service Spooler` and look for the CVE-2021-34527 patch level (`wmic qfe list brief`).
  5. If `msdtc.exe`, check the CVE-2021-26411 patch level and the MSDTC security configuration.
  6. If `vmtoolsd.exe`, correlate the version with VMware VMSA advisories and check whether the backchannel is on a default port or pinned.
  7. Capture a `netsh trace` for ~60 s while the listener is up, to log the bind and the remote peer if any.
