// Run piolium-confirm programmatically using the pi SDK + piolium extension
import { createAgentSession, DefaultResourceLoader, getAgentDir, SessionManager } from "@earendil-works/pi-coding-agent";
import { runConfirmAudit } from "@vigolium/piolium/extensions/piolium/modes/confirm.ts";
import path from "node:path";
import os from "node:os";

const TARGET = process.argv[2] || "C:/Users/User/Downloads/CTF 2026/sandbox/xVuln-main";
const URL = process.argv[3] || "http://localhost:4443";

console.log(`[*] Target: ${TARGET}`);
console.log(`[*] URL:    ${URL}`);
console.log(`[*] CWD:    ${process.cwd()}`);

try {
  // Set up agent directory (piolium uses its own)
  const agentDir = path.join(os.homedir(), ".piolium", "agent");
  process.env.PI_CODING_AGENT_DIR = agentDir;

  console.log("[*] Loading piolium confirm audit...");
  console.log("[*] This will run V1-V7 confirm phases against the live target");

  const result = await runConfirmAudit({
    cwd: TARGET,
    forceFresh: true,
    target: URL,
    ui: {
      notify: (text, level) => console.log(`[${level || "info"}] ${text}`),
      setStatus: (id, status) => console.log(`[status] ${id}: ${status}`),
      onAgentEvent: (e) => console.log(`[event] ${e.type}`),
      onPhaseHeartbeat: (h) => console.log(`[heartbeat] ${h.phase}: ${h.status}`),
    },
  });

  console.log("\n[+] Confirm audit complete!");
  console.log(`    Audit ID: ${result.auditId}`);
  console.log(`    Status:   ${result.status}`);
  console.log(`    Phases:`);
  for (const [phase, status] of Object.entries(result.phases)) {
    console.log(`      ${phase}: ${status}`);
  }
} catch (err) {
  console.error("[!] Error:", err.message);
  console.error(err.stack);
  process.exit(1);
}
