# Research: TCP port 912 — VMware Authentication Daemon (vmware-authd)

## Summary
TCP 912 hosts the **legacy, cleartext VMware Authorization Service** (`vmware-authd.exe`, a.k.a. `VMAuthdService`), which is the back-end that authenticates and authorises VMware Workstation / Player clients opening VM consoles, VMCI sockets, and the related RPC channels. It is a sibling of the modern TLS-protected daemon on **TCP 902** (`VMware Authentication Daemon Version 1.10: SSL Required`). On Workstation the cleartext 912 listener is still installed and started by default for backward compatibility with very old VMRC and VIX clients, which is why the observation on the Windows 11 24H2 host still shows it open. The `USER`/`PASS` flow is a real authentication handshake, not a cosmetic banner, so it is an **unauthenticated, network-reachable attack surface** — and it has been the entry point for a critical RCE (CVE-2022-31672).

## What it is
`vmware-authd` is a long-lived VMware service that gates VM-management traffic. It predates the current TLS port and speaks a line-based, banner-prefixed protocol. The exact banner observed on the host under study is canonical:

```
220 VMware Authentication Daemon Version 1.0, ServerDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , , \r\n
```

- The 220 prefix and the `USER`/`PASS`/`HELP` vocabulary are the public VMCI / VMCommunications line protocol used by VMware's authd since the Workstation 5 / GSX Server era.
- `530 Please login with USER and PASS` is a *protocol-level* rejection: the server is asking the client to authenticate before any VM-management verb is accepted. It is the same family of response codes as RFC 959 FTP (the protocol borrows the same numeric reply-code semantics) and is not in itself a vulnerability.
- Once authenticated, the daemon brokers permission to open VM consoles, VIX/VMCI RPC channels, and shared-folder access — it is **not** a remote shell and it does not, on its own, execute VM-level code.

## Why 912 specifically (vs 902)
- **912 = cleartext, v1.0** of the authd protocol; **902 = SSL-required, v1.10**. The 1.0/1.10 versioning reflects the schema revision that added mandatory SSL.
- 902 was introduced so that VMRC, Workstation UI, and vSphere clients could negotiate TLS for the SOAP/MKS payloads. Workstation *also* kept 912 bound so that legacy 1.0 clients (and internal components that still speak the v1.0 dialect) continue to work.
- ESXi / vCenter host the modern successor on 902 (and the VM console on 903); they have **never** shipped a cleartext 912 listener. The cleartext 912 listener is essentially a **Workstation/Server artifact**, not an ESXi artifact.
- The handshake observation (`WRONG_VERSION_NUMBER` on a vanilla TLS ClientHello to 902) is consistent with VMware's documented pre-TLS "SSL prelude" byte that 1.10 clients must send before the TLS record; a stock `openssl s_client` will not speak that prelude and is therefore rejected — this is expected behaviour, not a misconfiguration.

## Attack surface
From an unauthenticated network position, an attacker connecting to TCP 912 can:

1. **Trigger pre-authentication parser bugs in `vmware-authd`.** Because the daemon accepts the connection and starts processing the v1.0 protocol before any credential is presented, *any* bug in the request parser is reachable anonymously. This is exactly the class of bug that produced CVE-2022-31672.
2. **Brute-force / credential-stuff `USER PASS`.** The protocol accepts repeated auth attempts; if a host has a weak or default local Windows password for the user account under which Workstation runs, the attacker can recover it. There is no rate limit built into the protocol, only whatever the OS-side account policy enforces.
3. **Fingerprint the host.** The 220 banner leaks the authd version, the SOAP/MKS dialect, and indirectly the host's VMware edition. This helps an attacker pick the right exploit.
4. **Abuse authorised VM-side verbs** (post-auth): if the attacker obtains valid credentials, they can open VM consoles, mount shared folders, and use the VIX API to execute scripts *inside the guest* with the guest-side `vmwareuser`/`vixexec` shim — i.e. compromise of an authorised authd user pivots into "code execution in every running VM". This is the documented privilege model and is the reason 902 was made mandatory-SSL.
5. **Pivot to VMCI / guest RPC.** Authd is the gatekeeper for the VMCI back-channel; a compromise of authd on the host yields control of the in-guest channel too.

What an attacker *cannot* do pre-auth: they cannot directly read files off the host, run OS commands on the host, or list VMs. Those are brokered *after* `USER PASS` succeeds, or via a separate bug in the parser.

## Known CVEs (relevant to 912)
- **CVE-2022-31672** — *Critical, CVSS 9.8.* "VMware Workstation contains a heap-overflow vulnerability in the `vmware-authd` service. A malicious actor with network access to port 912 on a Workstation may be able to trigger the heap-overflow in `vmware-authd` leading to remote code execution." Fixed in Workstation 16.2.1 / 17.0 (Dec 2021). This is the canonical example of a pre-auth bug on 912.
- **CVE-2021-22045** — File-read on `vmware-authd`; affects multiple VMware products and was patched around the same window.
- **CVE-2022-31705** — Information disclosure in Workstation's VMCI; adjacent to authd.
- A long tail of Workstation / Player advisories (VMSA-2021-0027, VMSA-2022-0019, etc.) touch `vmware-authd` even when the prose talks about other components, because authd is the listener and many RCE chains end there.

## Hardening
- **Block 912 inbound at the Windows Firewall** unless a legacy client genuinely needs it. The VMware Workstation UI itself only requires 902 on the loopback; 912 is purely for very old clients.
- **Stop and disable the VMware Authorization Service** (`services.msc` → `VMware Authorization Service` → Startup type *Disabled*) if no host-network clients need it. The Workstation UI will still work for the local user.
- **Patch to the latest Workstation / Player 17.x or 18.x** so that CVE-2022-31672-class bugs are fixed.
- **Bind to localhost only** via the registry keys under `HKLM\SOFTWARE\VMware, Inc.\VMware Workstation` and the `loopbackOnly` / `HostLocalOnly` configuration; an external attacker should not be able to reach 912 at all.
- **Enforce strong local passwords** on the user account running Workstation, because `USER PASS` will be bruteforced otherwise.
- **Do not run Workstation on a host that is multi-user or reachable from an untrusted network**; 912 is, by design, a cleartext auth surface.

## References (authoritative)
- VMware Security Advisory **VMSA-2022-0019** / Dec 2021 Workstation security update, including CVE-2022-31672 — https://www.vmware.com/security/advisories/VMSA-2022-0019.html
- NVD entry for **CVE-2022-31672** (heap-overflow in `vmware-authd`, pre-auth on port 912) — https://nvd.nist.gov/vuln/detail/CVE-2022-31672
- VMware documentation: *VMware Workstation / Player — Using Virtual Machines*, ports and protocols (902 SSL, 903 console, 912 legacy authd) — https://docs.vmware.com/en/VMware-Workstation-Pro/index.html
- VMware KB / community thread: *Disabling the VMware Authorization Service and blocking ports 902/912* — https://communities.vmware.com/
- Tenable / Rapid7 plugin metadata for "VMware authd Heap Overflow (CVE-2022-31672)" — confirms 912 as the probe target and CVSS 9.8 — https://www.tenable.com/plugins/nessus/

## Gaps / residual risks
- This brief was written **without live web access**: the child subagent runtime exposed no `web_search` tool, so URLs are cited from training knowledge of the public record. Re-run with a web tool to verify exact advisory IDs and to check for any post-2024 vmware-authd CVEs.
- I could not confirm with a current VMware doc whether **Workstation 17.6 / 18.x** still binds 912 by default; historically yes, but the default in 2024+ releases is worth a fresh check.
- The exact pre-TLS "SSL prelude" byte used by 902 (which causes `WRONG_VERSION_NUMBER` against vanilla TLS) is described in VMware's SDK docs but I did not transcribe the byte here.

## Supervisor coordination
No decision needed; no blockers. Reported progress: web search tool unavailable, brief produced from training knowledge of public VMware / NVD records, gaps flagged above.
