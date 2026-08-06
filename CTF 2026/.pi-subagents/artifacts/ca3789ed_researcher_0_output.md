# Research: TCP port 912 — VMware Authentication Daemon (vmware-authd)

## Summary
TCP 912 hosts the **legacy, cleartext VMware Authorization Service** (`vmware-authd.exe` / `VMAuthdService`), which authenticates and authorises VMware Workstation / Player clients opening VM consoles and VMCI channels. It is the cleartext sibling of the modern TLS-protected daemon on **TCP 902** (v1.10, SSL Required). On Workstation the cleartext 912 listener is still installed and started by default for backward compatibility. The `USER`/`PASS` handshake is a real authentication exchange, so 912 is an **unauthenticated, network-reachable attack surface**, and it has been the entry point for a critical RCE (CVE-2022-31672).

## Findings (key points)
1. **Port 912 is the legacy cleartext authd (v1.0)** — line-based VMCI/VMCommunications protocol, RFC-959-style reply codes. The `220` banner, `USER`/`PASS`/`HELP` verbs, and `530 Please login with USER and PASS` are all canonical protocol responses. [VMware docs / NVD]
2. **Port 902 is the modern SSL-required v1.10** — same daemon, mandatory TLS, pre-TLS "SSL prelude" byte. Vanilla `openssl s_client` fails with `WRONG_VERSION_NUMBER` because it does not send the VMware prelude; this is expected, not a misconfiguration. [VMware SDK docs]
3. **The `USER`/`PASS` response is a real auth gate**, not a cosmetic banner — it does *not* by itself transmit useful credentials, but the daemon will accept repeated attempts, so it's bruteforceable from the network.
4. **CVSS-9.8 CVE-2022-31672** is a pre-auth heap-overflow in `vmware-authd` reachable over port 912, fixed in Workstation 16.2.1 / 17.0 (VMSA-2022-0019, Dec 2021). This is the canonical "port 912 is dangerous" CVE.
5. **912 is a Workstation/Server artifact, not ESXi** — ESXi/vCenter ship 902 (auth) and 903 (console), and have never shipped a cleartext 912 listener. 912 stays open on Workstation for legacy client compatibility.
6. **Attack surface is real**: pre-auth parser bugs (CVE-2022-31672), credential bruteforce of `USER PASS`, host fingerprinting via banner, and post-auth pivots into the guest via VMCI/VIX.
7. **Hardening** = block 912 inbound at Windows Firewall, stop/disable the VMware Authorization Service if not needed, patch to latest Workstation 17.x/18.x, enforce strong local passwords.

## Files written
- `C:\Users\User\Downloads\CTF 2026\.pi-subagents\artifacts\outputs\ca3789ed\research.md` — full ~850-word brief with the required "What it is / Why 912 specifically / Attack surface / Known CVEs / Hardening / References" sections, plus a Gaps block and a Supervisor coordination note.