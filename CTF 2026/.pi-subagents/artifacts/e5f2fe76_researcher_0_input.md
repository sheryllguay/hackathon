# Task for researcher

You are a research subagent. Your job: investigate what service typically runs on a specific TCP port and document its attack surface. Note: no web_search tool is available in your runtime, so use your training knowledge of public Microsoft docs and NVD entries; clearly flag confidence and note this as a residual risk.

**Target port: TCP 5040**

I have already observed the following on a Windows 11 24H2 host (build 26200):
- Port 5040 listens, process is `svchost.exe -k LocalService -p`, hosting the service **CDPSvc** (Connected Devices Platform Service), path `C:\WINDOWS\system32\svchost.exe -k LocalService -p`.
- Service description: "This service is used for Connected Devices Platform scenarios"
- Service start mode: Auto, running
- TCP connect succeeds; no banner is sent. A raw HTTP GET returns nothing. A DCE/RPC bind returns nothing. The server is silent.
- Port 5040 binds to 0.0.0.0 (all interfaces).

Your research tasks:
1. Confirm what **CDPSvc** (Connected Devices Platform Service) is on Windows 10/11. What protocol does it speak on port 5040? Is it TCP or UDP? Is 5040 the canonical CDPSvc port, or is something else (e.g., 5040 is also historically associated with "Windows Service Notification Service" / `wcss.exe`)?
2. Document the **attack surface** of an exposed 5040/CDPSvc:
   - Is the protocol authenticated?
   - Are there any CVEs against CDPSvc (search for "CDPSvc", "Connected Devices Platform", "CVE-2024-38063" Windows TCP/IP, "CVE-2022-30115 Follina" related CDPSvc issues, etc.)?
   - Can a remote attacker enumerate devices, pair devices, or read/write files via 5040 without authentication?
   - Does Windows Firewall normally allow 5040 publicly, and is exposure on 0.0.0.0 a misconfiguration?
3. Note: in Microsoft's MSDN, port 5040 has also been used by "Service Control Manager remote protocol" historically. Confirm whether 5040 is also the `wcss.exe` (Windows CardSpace) port and whether that is separate from CDPSvc.
4. Cite 2-4 authoritative sources (Microsoft docs, MSRC, NVD, public security research). Use your training knowledge; flag low confidence where appropriate.

Return a focused brief: 600-1000 words, with a "What it is", "Protocol", "Attack surface", "Known CVEs", "Hardening", and "References" section. Do not attempt to connect to any port; you are researching only.

---
Update progress at: C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\progress\e5f2fe76\progress.md

---
**Output:**
Write your findings to exactly this path: C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\e5f2fe76\researcher_b_5040.md
This path is authoritative for this run.
Ignore any other output filename or output path mentioned elsewhere, including output destinations in the base agent prompt, system prompt, or task instructions.

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