# Task for worker

You are doing READ-ONLY network reconnaissance against the Windows host 10.181.33.90. The following TCP ports are confirmed open:
- 135 (Microsoft RPC)
- 139 (NetBIOS)
- 445 (SMB)
- 902 (VMware Authentication Daemon v1.10 — banner: '220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC')
- 912
- 5040
- 49689

CRITICAL CONSTRAINTS:
- READ-ONLY reconnaissance ONLY. Do NOT attempt authentication, do NOT connect with credentials, do NOT exploit any service, do NOT write to any remote share.
- You may use PowerShell, Python, nmap (install via winget if not present), smbclient (if available), or other read-only tools.
- Stay on 10.181.33.90 only. Do not touch other hosts.

DELIVERABLES — return a structured report covering:

1. SMB (445) — Windows version detection:
   - Try `Test-NetConnection -ComputerName 10.181.33.90 -Port 445 -InformationLevel Detailed`
   - Try a Python script using raw SMB negotiate to grab the OS version string (e.g., SMBv2 negotiate request, parse NativeOS / NativeLanMan fields)
   - If nmap is available: `nmap -sV -p 445 --script smb-os-discovery 10.181.33.90`
   - Report the Windows version / build if discoverable, plus the SMB dialect (SMB1/SMB2/SMB3), signing status, and any banner info.

2. SMB share enumeration (anonymous / null session):
   - Try `net view \\10.181.33.90` (likely will fail without creds, but try)
   - Try a Python script with impacket (if installed) or raw NetShareEnum against the null session
   - Try `smbclient -L //10.181.33.90 -N` if smbclient is available
   - Report which shares are visible (e.g., ADMIN$, C$, IPC$, print$, hidden shares, custom shares).

3. Port 912 service identification:
   - Try `Test-NetConnection -ComputerName 10.181.33.90 -Port 912 -InformationLevel Detailed`
   - Try a TCP connect + grab banner (e.g., `python -c "import socket; s=socket.socket(); s.settimeout(5); s.connect(('10.181.33.90',912)); print(s.recv(2048))"`)
   - Try sending an empty / HTTP probe and see what comes back.
   - Report whatever the banner / response reveals.

4. Port 5040 service identification:
   - Same approach: Test-NetConnection, banner grab, HTTP probe.
   - Note: on Windows, 5040 is commonly the Windows Service Notification / Windows CardSpace / WCF port (often svchost.exe), but verify.

5. Port 49689 service identification:
   - Same approach: Test-NetConnection, banner grab, HTTP probe.
   - Note: 49689 is in the high RPC ephemeral range, often a Windows service using dynamic RPC allocation.

6. Port 902 VMware daemon — extra probing:
   - After grabbing the existing banner, try sending a minimal probe (e.g., an empty line, or `HELP\r\n`, or a SOAP XML envelope header) to see if it leaks more info.
   - Check whether SSL is required (the banner says so) and report the SSL/TLS version observable if you do an `openssl s_client` style probe.
   - Do NOT attempt to authenticate or issue SOAP calls.

7. RPC (135) and NetBIOS (139):
   - `Test-NetConnection -ComputerName 10.181.33.90 -Port 135 -InformationLevel Detailed` and same for 139.

8. nmap service version scan (preferred, install via winget if not present):
   - `winget install -e --id Insecure.Nmap` (or use chocolatey `choco install nmap`)
   - If installed: `nmap -sV -p 135,139,445,902,912,5040,49689 --version-intensity 5 10.181.33.90`
   - Also `nmap -sV -p 135,139,445,902,912,5040,49689 --script=banner --script-timeout 30s 10.181.33.90`
   - Capture the full output and quote the service detection lines verbatim.

OUTPUT FORMAT: Return a single structured markdown report with one section per port, plus a final "Open Questions / Cannot Determine" section listing anything that couldn't be determined and why. Include the exact commands you ran and the exact output (truncated sensibly) so the findings are auditable.

Working directory: C:\Users\User\Downloads\CTF 2026
You may write intermediate scripts to a local scratch folder (e.g., C:\Users\User\Downloads\CTF 2026\scratch\) but do NOT upload or exfiltrate anything.

## Acceptance Contract
Acceptance level: attested
Completion is not accepted from prose alone. End with a structured acceptance report.

Criteria:
- criterion-1: Return concrete findings with file paths and severity when applicable

Required evidence: review-findings, residual-risks

Finish with a fenced JSON block tagged `acceptance-report` in this shape:
Use empty arrays when no items apply; array fields contain strings unless object entries are shown.
`criteriaSatisfied[].status` must be exactly one of: satisfied, not-satisfied, not-applicable.
`commandsRun[].result` must be exactly one of: passed, failed, not-run.
`manualNotes` and `notes` are optional strings; an empty string means no note and does not satisfy `manual-notes` evidence.
```acceptance-report
{
  "criteriaSatisfied": [
    {
      "id": "criterion-1",
      "status": "satisfied",
      "evidence": "specific proof"
    }
  ],
  "changedFiles": [
    "src/file.ts"
  ],
  "testsAddedOrUpdated": [
    "test/file.test.ts"
  ],
  "commandsRun": [
    {
      "command": "command",
      "result": "passed",
      "summary": "short result"
    }
  ],
  "validationOutput": [
    "validation output or concise summary"
  ],
  "residualRisks": [
    "none"
  ],
  "noStagedFiles": true,
  "diffSummary": "short description of the diff",
  "reviewFindings": [
    "blocker: file.ts:12 - issue found, or no blockers"
  ],
  "manualNotes": "anything else the parent should know"
}
```