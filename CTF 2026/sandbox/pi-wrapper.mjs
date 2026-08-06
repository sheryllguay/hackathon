#!/usr/bin/env node
// pi wrapper for piolium
import { spawn } from "node:child_process";
const cli = "C:/Users/User/AppData/Roaming/npm/node_modules/@earendil-works/pi-coding-agent/dist/cli.js";
const child = spawn("node", [cli, ...process.argv.slice(2)], { stdio: "inherit" });
child.on("exit", code => process.exit(code || 0));
