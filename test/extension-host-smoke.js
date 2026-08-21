"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vscode = require("vscode");

async function run() {
  const extension = vscode.extensions.getExtension("traceguard.traceguard-vscode");
  assert.ok(extension, "TraceGuard is visible to the Extension Host");

  const api = await extension.activate();
  assert.equal(extension.isActive, true, "TraceGuard activates successfully");
  assert.ok(api?.audit?.session, "TraceGuard creates its audit session");

  const commands = new Set(await vscode.commands.getCommands(true));
  for (const command of [
    "traceguard.startAudit",
    "traceguard.traceCrossFileFlow",
    "traceguard.exportReviewSession",
  ]) {
    assert.ok(commands.has(command), `${command} is registered`);
  }

  if (process.env.TRACEGUARD_SMOKE_MARKER) {
    fs.writeFileSync(process.env.TRACEGUARD_SMOKE_MARKER, JSON.stringify({
      extensionId: extension.id,
      active: extension.isActive,
      commandsVerified: 3,
      vscodeVersion: vscode.version,
    }));
  }
}

module.exports = { run };
