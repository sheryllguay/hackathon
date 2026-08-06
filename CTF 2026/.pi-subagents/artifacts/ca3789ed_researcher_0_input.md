# Task for researcher

You are a research subagent. Your job: investigate what service typically runs on a specific TCP port and document its attack surface.

**Target port: TCP 912**

I have already observed the following on a Windows 11 24H2 host:
- Port 912 listens and the process is `C:\Program Files (x86)\VMware\VMware Workstation\vmware-authd.exe` (VMware Authorization Service, a.k.a. VMAuthdService).
- On connect, port 912 immediately sends: `220 VMware Authentication Daemon Version 1.0, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , , \r\n`
- The companion service on port 902 of the same process sends: `220 VMware Authentication Daemon Version 1.10: SSL Required, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported/t, \r\n`
- After sending `HELP\r\n` to port 912, the server replied: `530 Please login with USER and PASS.\r\n`
- Port 902 requires TLS but a TLS handshake to 902 fails with `WRONG_VERSION_NUMBER` / connection-aborted (likely uses a VMware custom SSL prelude before TLS, not vanilla TLS).
- This looks like the legacy **cleartext** VMware Authentication Daemon on 912, while 902 is the newer SSL-required v1.10.

Your research tasks:
1. Confirm the history and purpose of port 912 in VMware products. Which VMware product (Workstation, Server, ESXi) historically listened on 912? When was it deprecated? Is it still enabled by default in current VMware Workstation 17/18? What does the `USER`/`PASS` cleartext protocol do — is it a remote "login" to manage VMs, or just a legacy connection-handshake that does not transmit useful credentials?
2. Document the **attack surface** of an exposed 912: what could an unauthenticated remote attacker do? Are there any CVEs against vmware-authd on 912 (e.g., CVE-2022-31672 VMBR or auth bypass on 912)? Is the cleartext USER/PASS response indicative of a vulnerable or unauthenticated code path?
3. Compare 912 vs 902 (modern) — what changed and why is 912 still open?
4. Cite 2-4 authoritative sources (VMware docs, NVD CVE entries, third-party security advisories, StackOverflow).

Return a focused brief: 600-1000 words, with a "What it is", "Why 912 specifically", "Attack surface", "Known CVEs", "Hardening", and "References" section. Do not attempt to connect to any port; you are researching only.

---
**Output:**
Write your findings to exactly this path: C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\ca3789ed\research.md
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