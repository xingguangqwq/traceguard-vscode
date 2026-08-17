"use strict";

const assert = require("node:assert/strict");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");

class EventEmitter {
  constructor() { this.listeners = new Set(); this.event = listener => { this.listeners.add(listener); return { dispose: () => this.listeners.delete(listener) }; }; }
  fire(value) { for (const listener of this.listeners) listener(value); }
  dispose() { this.listeners.clear(); }
}

function loadAuditSession(workspaceRoot) {
  const originalLoad = Module._load;
  Module._load = function(request, parent, isMain) {
    if (request === "vscode") {
      return { EventEmitter, workspace: { workspaceFolders: [{ name: "repo", uri: { fsPath: workspaceRoot } }] } };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  delete require.cache[require.resolve("../src/audit-session")];
  const loaded = require("../src/audit-session");
  Module._load = originalLoad;
  return loaded.AuditSession;
}

function contextWith(initial) {
  const state = new Map(Object.entries(initial));
  return {
    state,
    workspaceState: {
      get: (key, fallback) => state.has(key) ? state.get(key) : fallback,
      update: async (key, value) => state.set(key, value),
    },
  };
}

test("review session export removes absolute paths and import merges state", async () => {
  const workspaceRoot = path.resolve("C:\\review-workspace");
  const AuditSession = loadAuditSession(workspaceRoot);
  const context = contextWith({
    "traceguard.audit.statuses": { old: { status: "reviewed", updatedAt: "2026-01-01" } },
    "traceguard.audit.evidence": [{ id: "old-note", relativePath: "src/old.js", absolutePath: path.join(workspaceRoot, "src/old.js"), type: "Observation", code: "old" }],
  });
  const session = new AuditSession(context, { warn() {}, info() {} });
  const exported = session.exportPortableState();
  assert.equal(exported.evidence[0].absolutePath, undefined);

  const imported = await session.importPortableState({
    schema: "traceguard-review-session",
    version: 1,
    statuses: { current: { status: "in_review", updatedAt: "2026-02-01" } },
    evidence: [
      { id: "new-note", relativePath: "src/new.js", type: "Sink", code: "exec(value)", line: 4 },
      { id: "unsafe-note", relativePath: "../outside.txt", type: "Observation", code: "ignored", line: 1 },
    ],
  });
  assert.deepEqual(imported, { statuses: 1, evidence: 1 });
  assert.equal(context.state.get("traceguard.audit.statuses").old.status, "reviewed");
  assert.equal(context.state.get("traceguard.audit.statuses").current.status, "in_review");
  assert.equal(context.state.get("traceguard.audit.evidence").length, 2);
  assert.equal(context.state.get("traceguard.audit.evidence")[1].absolutePath, path.join(workspaceRoot, "src/new.js"));
  session.dispose();
});

test("review session import rejects unsupported data", async () => {
  const AuditSession = loadAuditSession(path.resolve("C:\\review-workspace"));
  const session = new AuditSession(contextWith({}), { warn() {}, info() {} });
  await assert.rejects(() => session.importPortableState({ version: 99 }), /not a supported TraceGuard review session/);
  session.dispose();
});
