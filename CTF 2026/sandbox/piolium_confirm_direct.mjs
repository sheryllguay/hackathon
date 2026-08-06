// Run piolium-confirm by directly invoking the runConfirmAudit function
// This uses the same module resolution as the piolium extension itself
import path from "node:path";
import os from "node:os";
import { pathToFileURL } from "node:url";

const TARGET = "C:/Users/User/Downloads/CTF 2026/sandbox/xVuln-main";
const URL = "http://localhost:4443";
const PIOLIUM_PKG = "C:/Users/User/.pi/agent/npm/node_modules/@vigolium/piolium";
const NPM_ROOT = "C:/Users/User/AppData/Roaming/npm/node_modules";
const PI_AGENT_NM = "C:/Users/User/AppData/Roaming/npm/node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works";

// Set up piolium environment
process.env.PIOLIUM_HOME = path.join(os.homedir(), ".piolium");
process.env.PIOLIUM_PACKAGE_DIR = PIOLIUM_PKG;
process.env.PI_CODING_AGENT_DIR = path.join(process.env.PIOLIUM_HOME, "agent");
process.env.NODE_PATH = NPM_ROOT;

console.log(`[*] Target: ${TARGET}`);
console.log(`[*] URL:    ${URL}`);
console.log(`[*] Piolium: ${PIOLIUM_PKG}`);

// Use jiti to load the TypeScript piolium extension
const JITI_PATH = "C:/Users/User/.pi/agent/npm/node_modules/jiti/lib/jiti.mjs";
const { default: createJiti } = await import(pathToFileURL(JITI_PATH).href);

const jiti = createJiti(import.meta.url, {
  interopDefault: true,
  esmResolve: true,
  requireCache: false,
  alias: {
    "@earendil-works/pi-coding-agent": path.join(NPM_ROOT, "@earendil-works/pi-coding-agent"),
    "@earendil-works/pi-ai": path.join(PI_AGENT_NM, "pi-ai"),
    "@earendil-works/pi-agent-core": path.join(PI_AGENT_NM, "pi-agent-core"),
    "@earendil-works/pi-tui": path.join(PI_AGENT_NM, "pi-tui"),
  },
});

// Load the confirm mode module
const confirmPath = path.join(PIOLIUM_PKG, "extensions/piolium/modes/confirm.ts");
console.log(`[*] Loading: ${confirmPath}`);

try {
  const confirmModule = jiti(confirmPath);
  console.log("[*] Module keys:", Object.keys(confirmModule));

  const { runConfirmAudit } = confirmModule;
  if (!runConfirmAudit) {
    console.error("[!] runConfirmAudit not found in module");
    console.log("    Available:", Object.keys(confirmModule));
    process.exit(1);
  }

  console.log("[*] Running confirm audit (V1-V7) against live target...");
  console.log("[*] This may take several minutes...");

  const result = await runConfirmAudit({
    cwd: TARGET,
    forceFresh: true,
    target: URL,
    ui: {
      notify: (text, level) => console.log(`[${level || "info"}] ${text}`),
      setStatus: (id, status) => console.log(`[status:${id}] ${status}`),
      onAgentEvent: (e) => {
        if (e.type !== "text") return;
        const preview = (e.text || "").slice(0, 200);
        if (preview) console.log(`[event:${e.type}] ${preview}`);
      },
      onPhaseHeartbeat: (h) => console.log(`[heartbeat] ${h.phase}: ${h.status}`),
    },
  });

  console.log("\n[+] Confirm audit complete!");
  console.log(`    Audit ID: ${result.auditId}`);
  console.log(`    Status:   ${result.status}`);
  if (result.phases) {
    console.log(`    Phases:`);
    for (const [phase, status] of Object.entries(result.phases)) {
      console.log(`      ${phase}: ${status}`);
    }
  }
} catch (err) {
  console.error("[!] Error:", err.message);
  if (err.stack) console.error(err.stack.split("\n").slice(0, 10).join("\n"));
  process.exit(1);
}
