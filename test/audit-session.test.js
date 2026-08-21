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
  return loadAuditSessionModule([{ name: "repo", uri: { fsPath: workspaceRoot } }]).AuditSession;
}

function loadAuditSessionModule(workspaceFolders, workspaceOverrides = {}) {
  const originalLoad = Module._load;
  Module._load = function(request, parent, isMain) {
    if (request === "vscode") {
      return {
        EventEmitter,
        workspace: {
          workspaceFolders,
          getWorkspaceFolder: uri => workspaceFolders.find(folder => path.resolve(uri.fsPath).startsWith(`${path.resolve(folder.uri.fsPath)}${path.sep}`)),
          getConfiguration: () => ({ get: (_key, fallback) => fallback }),
          ...workspaceOverrides,
        },
      };
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  delete require.cache[require.resolve("../src/audit-session")];
  const loaded = require("../src/audit-session");
  Module._load = originalLoad;
  return loaded;
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

test("portable evidence keeps its workspace root in multi-root workspaces", async () => {
  const apiRoot = path.resolve("C:\\review-workspace\\api");
  const webRoot = path.resolve("C:\\review-workspace\\web");
  const loaded = loadAuditSessionModule([
    { name: "api", uri: { fsPath: apiRoot } },
    { name: "web", uri: { fsPath: webRoot } },
  ]);
  const context = contextWith({});
  const session = new loaded.AuditSession(context, { warn() {}, info() {} });
  const webFile = { fsPath: path.join(webRoot, "src", "view.js") };

  assert.equal(loaded.workspaceRelativePath(webFile), "web/src/view.js");
  const imported = await session.importPortableState({
    schema: "traceguard-review-session",
    version: 1,
    statuses: {},
    evidence: [
      { id: "ambiguous", relativePath: "src/view.js", type: "Observation", code: "ignored", line: 1 },
      { id: "web-note", relativePath: "web/src/view.js", type: "Observation", code: "kept", line: 1 },
    ],
  });
  assert.equal(imported.evidence, 1);
  assert.equal(context.state.get("traceguard.audit.evidence")[0].absolutePath, webFile.fsPath);
  session.dispose();
});

test("cancelled indexing keeps the previous index and concurrent refreshes share work", async () => {
  const workspaceRoot = path.resolve("C:\\review-workspace");
  const files = [
    { fsPath: path.join(workspaceRoot, "one.js") },
    { fsPath: path.join(workspaceRoot, "two.js") },
  ];
  let reads = 0;
  let requestedLimit = 0;
  const loaded = loadAuditSessionModule([{ name: "repo", uri: { fsPath: workspaceRoot } }], {
    findFiles: async (_include, _exclude, limit) => { requestedLimit = limit; return files; },
    fs: {
      stat: async () => ({ size: 32 }),
      readFile: async () => { reads += 1; return Buffer.from("function safe() {}", "utf8"); },
    },
  });
  const session = new loaded.AuditSession(contextWith({}), { warn() {}, info() {} });
  const previous = { absolutePath: "C:\\previous.js" };
  session.analyses = [previous];
  const token = { get isCancellationRequested() { return reads >= 1; } };

  const first = session.indexWorkspace(undefined, token);
  const second = session.indexWorkspace(undefined, token);
  assert.equal(first, second);
  await first;

  assert.equal(requestedLimit, loaded.MAX_SOURCE_FILES + 1);
  assert.deepEqual(session.analyses, [previous]);
  assert.equal(session.indexStatus.cancelled, true);
  session.dispose();
});

test("single-file refresh before a workspace scan is labeled partial", async () => {
  const workspaceRoot = path.resolve("C:\\review-workspace");
  const file = { fsPath: path.join(workspaceRoot, "current.js") };
  const loaded = loadAuditSessionModule([{ name: "repo", uri: { fsPath: workspaceRoot } }]);
  const session = new loaded.AuditSession(contextWith({}), { warn() {}, info() {} });

  await session.reindexDocument({ uri: file, getText: () => "function run(req) { exec(req.body.command); }" });

  assert.equal(session.snapshot.indexIncomplete, true);
  assert.equal(session.snapshot.indexScope, "current-files");
  assert.equal(session.snapshot.files, 1);
  session.dispose();
});

test("legacy line-based review status is read through the stable target ID", () => {
  const AuditSession = loadAuditSession(path.resolve("C:\\review-workspace"));
  const context = contextWith({
    "traceguard.audit.statuses": { legacy: { status: "reviewed", updatedAt: "2026-08-21" } },
  });
  const session = new AuditSession(context, { warn() {}, info() {} });
  session.model = {
    ...session.model,
    items: [{ id: "stable", legacyIds: ["legacy"], line: 10, endLine: 12 }],
  };

  assert.equal(session.snapshot.items[0].status, "reviewed");
  assert.equal(session.snapshot.coverage, 100);
  session.dispose();
});

test("failed dataflow rebuild keeps the previous analyses and model", async () => {
  const workspaceRoot = path.resolve("C:\\review-workspace");
  const AuditSession = loadAuditSession(workspaceRoot);
  const session = new AuditSession(contextWith({}), { warn() {}, info() {} });
  const previousAnalyses = [];
  const previousModel = session.model;
  session.analyses = previousAnalyses;
  session.dataflowWorker = {
    analyze: async () => { throw new Error("worker failed"); },
    dispose: async () => {},
  };

  await assert.rejects(
    () => session._replaceAnalysis(
      { fsPath: path.join(workspaceRoot, "current.js") },
      "function run(req) { exec(req.body.command); }",
    ),
    /worker failed/,
  );
  assert.equal(session.analyses, previousAnalyses);
  assert.equal(session.model, previousModel);
  session.dispose();
});
