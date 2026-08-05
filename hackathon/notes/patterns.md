# CTF Solving Patterns

This file stores reusable solving patterns for future CTF work.
It should capture repeatable workflows and investigation sequences, not challenge-specific details.

## How to Use This File
- Add a pattern when a solved challenge reveals a reusable workflow.
- Prefer generalized steps over one-off observations.
- Keep entries concise and easy to scan.
- Group patterns by category for fast retrieval.

## Web Exploitation
### SQL Injection
- Identify injectable input points.
- Test for syntax errors or response differences.
- Use a minimal payload to confirm behavior.
- Escalate from basic boolean/time-based checks to data extraction.
- Reuse known payload libraries and request templates.

### JWT
- Inspect token structure and claims.
- Check signing algorithm and key handling.
- Decode and analyze token parts before modifying them.
- Reuse existing JWT decoding utilities.

### XSS
- Identify reflected or stored sinks.
- Confirm whether script execution is possible in the target context.
- Test with minimal payloads and expand carefully.
- Reuse payload libraries and browser-safe test vectors.

### SSRF / LFI / File Inclusion
- Identify network or file access paths.
- Test for unexpected internal access or local file exposure.
- Verify results through response differences and error behavior.
- Reuse payloads and request templates.

## Linux
### Enumeration
- Check user context, permissions, and writable paths.
- Inspect common files and directories.
- Look for binaries, scripts, cron jobs, and sudo rules.
- Reuse standard command workflows before inventing new ones.

### Privilege Escalation
- Identify binaries with unusual permissions.
- Check sudo privileges and misconfigurations.
- Compare common privilege escalation patterns with the current environment.
- Verify each step before escalating.

## Python Scripting
### Script Reuse
- Prefer existing scripts and templates over new implementations.
- Build small utilities for parsing, decoding, or automation.
- Verify script behavior before using it on a target.
- Keep scripts modular and reusable.

## Binary Exploitation
### ELF Analysis
- Inspect the binary type and architecture.
- Run file, strings, readelf, and objdump.
- Check for helper options such as --help or usage output.
- Look for embedded strings, format strings, or obvious weaknesses.
- Test the program with minimal inputs before developing a full exploit.

## Reverse Engineering
### Static Inspection
- Start with strings, imports, and symbol information.
- Identify entry points and interesting functions.
- Compare control flow and suspicious logic.
- Reuse disassembly workflows and helper tooling.

## Cryptography
### Token and Encoding Analysis
- Identify the encoding or cipher in use.
- Check whether the challenge depends on weak implementation or reuse of known patterns.
- Verify assumptions with known test vectors.
- Prefer decoding and analysis helpers over manual implementation.

## Forensics
### Evidence Review
- Look for timestamps, metadata, encoded content, and file artifacts.
- Trace the origin of suspicious files or strings.
- Correlate evidence across multiple files when possible.

## OSINT
### Information Gathering
- Gather context from public sources and metadata.
- Correlate names, domains, usernames, and timestamps.
- Validate findings before building a conclusion.

## General Skills
### Pattern Recognition
- Identify the underlying weakness before choosing an exploit path.
- Map the challenge to a known category and reuse prior patterns.
- Prefer minimal, testable steps over broad experimentation.

## Storage Guidelines
- Keep patterns general and reusable.
- Remove challenge-specific values such as flags, hostnames, or exact payloads when they are not broadly useful.
- Prefer short workflow chains and decision points.
- Optimize for future retrieval by using clear section headings and compact bullet points.
