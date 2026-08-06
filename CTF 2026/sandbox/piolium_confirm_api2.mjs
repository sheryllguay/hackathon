// Run piolium-confirm by spawning through the pi agent (uses jiti to load TS)
import { spawn } from "node:child_process";
import path from "node:path";

const TARGET = "C:/Users/User/Downloads/CTF 2026/sandbox/xVuln-main";
const URL = "http://localhost:4443";
const PIOLIUM_HOME = "C:/Users/User/.piolium";
const PIOLIUM_PKG = "C:/Users/User/.pi/agent/npm/node_modules/@vigolium/piolium";

console.log(`[*] Target: ${TARGET}`);
console.log(`[*] URL:    ${URL}`);

// Use jiti to load the TypeScript piolium extension
const jiti = await import("jiti").then(m => m.default || m);

const tiLoader = jiti(PIOLIUM_PKG, {
  interopDefault: true,
  esmResolve: true,
  requireCache: false,
  alias: {
    "@earendil-works/pi-coding-agent": "C:/Users/User/.pi/agent/npm/node_modules/@earendil-works/pi-coding-agent/dist/index.js",
    "@earendil-works/pi-ai": "C:/Users/User/.pi/agent/npm/node_modules/@earendil-works/pi-ai/dist/index.js",
    "@earendil-works/pi-agent-core": "C:/Users/User/.pi/agent/npm/node_modules/@earendil-works/pi-agent-core/dist/index.js",
    "@earendil-works/pi-tui": "C:/Users/User/.pi/agent/npm/node_modules/@earendil-works/pi-tui/dist/index.js",
  },
});

// Load the confirm mode
const confirmModule = tiLoader("./extensions/piolium/modes/confirm.ts");
console.log("[*] Loaded confirm module, keys:", Object.keys(confirmModule));

const { runConfirmAudit } = confirmModule;

// Set up environment
process.env.PIOLIUM_HOME = PIOLIUM_HOME;
process.env.PIOLIUM_PACKAGE_DIR = PIOLIUM_PKG;
process.env.PI_CODING_AGENT_DIR = path.join(PIOLIUM_HOME, "agent");

console.log("[*] Running confirm audit...");
try {
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
} catch (err) {
  console.error("[!] Error:", err.message);
  console.error(err.stack);
}
