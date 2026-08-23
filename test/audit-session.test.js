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
      const configuredFs = workspaceOverrides.fs || {};
      return {
        EventEmitter,
        Uri: {
          joinPath: (base, ...segments) => ({ fsPath: path.join(base.fsPath, ...segments) }),
        },
        workspace: {
          workspaceFolders,
          getWorkspaceFolder: uri => workspaceFolders.find(folder => path.resolve(uri.fsPath).startsWith(`${path.resolve(folder.uri.fsPath)}${path.sep}`)),
          getConfiguration: () => ({ get: (_key, fallback) => fallback }),
          ...workspaceOverrides,
          fs: {
            stat: async uri => {
              if (path.basename(uri.fsPath) === ".traceguard.json" && configuredFs.configText === undefined) throw fileNotFound();
              if (path.basename(uri.fsPath) === ".traceguard.json") return { size: Buffer.byteLength(configuredFs.configText, "utf8") };
              if (configuredFs.stat) return configuredFs.stat(uri);
              throw fileNotFound();
            },
            readFile: async uri => {
              if (path.basename(uri.fsPath) === ".traceguard.json" && configuredFs.configText !== undefined) return Buffer.from(configuredFs.configText, "utf8");
              if (configuredFs.readFile) return configuredFs.readFile(uri);
              throw fileNotFound();
            },
          },
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

function fileNotFound() {
  const error = new Error("File not found");
  error.code = "FileNotFound";
  return error;
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
  assert.deepEqual(imported, { statuses: 1, findingStatuses: 0, evidence: 1 });
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

test("workspace indexing exposes real idle, active and failed states", async () => {
  const workspaceRoot = path.resolve("C:\\review-workspace");
  const loaded = loadAuditSessionModule([{ name: "repo", uri: { fsPath: workspaceRoot } }], {
    findFiles: async () => [],
  });
  const session = new loaded.AuditSession(contextWith({}), { warn() {}, info() {} });
  let rejectAnalysis;
  session.dataflowWorker.initializeWorkspace = () => new Promise((_resolve, reject) => { rejectAnalysis = reject; });

  assert.equal(session.snapshot.indexing, false);
  assert.equal(session.snapshot.indexStage.phase, "idle");
  assert.equal(session.snapshot.indexError, undefined);

  const indexing = session.indexWorkspace();
  while (!rejectAnalysis) await new Promise(resolve => setImmediate(resolve));
  assert.equal(session.snapshot.indexing, true);
  assert.equal(session.snapshot.indexStage.phase, "analyzing");

  const failure = new Error("synthetic worker failure\ninternal details");
  failure.code = "WORKER_REQUEST_ERROR";
  rejectAnalysis(failure);
  await assert.rejects(indexing, /synthetic worker failure/);
  assert.equal(session.snapshot.indexing, false);
  assert.equal(session.snapshot.indexStage.phase, "failed");
  assert.equal(session.snapshot.indexError, "synthetic worker failure");
  session.dispose();
});

test("a workspace scan with skipped files never orphans review state", async () => {
  const workspaceRoot = path.resolve("C:\\review-workspace");
  const good = { fsPath: path.join(workspaceRoot, "good.js") };
  const skipped = { fsPath: path.join(workspaceRoot, "unreadable.js") };
  const loaded = loadAuditSessionModule([{ name: "repo", uri: { fsPath: workspaceRoot } }], {
    findFiles: async () => [good, skipped],
    fs: {
      stat: async uri => {
        if (uri.fsPath === skipped.fsPath) throw new Error("permission denied");
        return { size: 64 };
      },
      readFile: async () => Buffer.from("function safe() {}", "utf8"),
    },
  });
  const context = contextWith({
    "traceguard.audit.statuses": { missing: { status: "reviewed", updatedAt: "2026-08-20" } },
  });
  const session = new loaded.AuditSession(context, { warn() {}, info() {} });

  await session.indexWorkspace();
  assert.equal(session.snapshot.indexIncomplete, true);
  assert.equal(session.workspaceCoverageComplete, false);
  assert.equal(context.state.get("traceguard.audit.statuses").missing.orphanedAt, undefined);

  await session.reindexDocument({ uri: good, getText: () => "function safe() { return true; }" });
  assert.equal(context.state.get("traceguard.audit.statuses").missing.orphanedAt, undefined);
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

test("finding review decisions persist independently from review-target coverage", async () => {
  const AuditSession = loadAuditSession(path.resolve("C:\\review-workspace"));
  const context = contextWith({});
  const session = new AuditSession(context, { warn() {}, info() {} });
  session.model = { ...session.model, findings: [{ id: "finding_one", title: "Potential SSRF" }] };

  assert.equal(await session.setFindingStatus("finding_one", "false_positive"), true);
  assert.equal(session.snapshot.findings[0].status, "false_positive");
  assert.equal(session.snapshot.findingStatusCounts.false_positive, 1);
  assert.equal(session.exportPortableState().findingStatuses.finding_one.status, "false_positive");
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
    updateFile: async () => { throw new Error("worker failed"); },
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

test("project configuration keeps the last valid model when a later edit is invalid", async () => {
  const workspaceRoot = path.resolve("C:\\review-workspace");
  const virtualFs = {
    configText: JSON.stringify({
      sources: [{ language: "javascript", function: "tenantInput" }],
      excludePaths: ["generated/**"],
    }),
  };
  const loaded = loadAuditSessionModule([{ name: "repo", uri: { fsPath: workspaceRoot } }], { fs: virtualFs });
  const warnings = [];
  const session = new loaded.AuditSession(contextWith({}), { warn: message => warnings.push(message), info() {} });

  const first = await session.reloadProjectConfiguration({ rebuild: false });
  assert.equal(first.valid, true);
  assert.equal(session.projectConfiguration.semanticModels.length, 1);
  const fingerprint = session.projectConfiguration.fingerprint;

  virtualFs.configText = "{ invalid json";
  const second = await session.reloadProjectConfiguration({ rebuild: false });
  assert.equal(second.valid, false);
  assert.equal(session.projectConfiguration.fingerprint, fingerprint);
  assert.ok(session.projectConfigurationIssues.some(item => item.severity === "error"));
  assert.match(warnings.at(-1), /kept the last valid/);
  session.dispose();
});

test("project exclude paths stay out of the workspace Worker and coverage counts", async () => {
  const workspaceRoot = path.resolve("C:\\review-workspace");
  const kept = { fsPath: path.join(workspaceRoot, "src", "kept.js") };
  const excluded = { fsPath: path.join(workspaceRoot, "generated", "client.js") };
  let excludeGlob;
  const virtualFs = {
    configText: JSON.stringify({ excludePaths: ["generated/**"] }),
    stat: async () => ({ size: 64 }),
    readFile: async uri => Buffer.from(uri.fsPath === kept.fsPath ? "function kept() {}" : "function generated() {}", "utf8"),
  };
  const loaded = loadAuditSessionModule([{ name: "repo", uri: { fsPath: workspaceRoot } }], {
    findFiles: async (_include, exclude) => { excludeGlob = exclude; return [kept, excluded]; },
    fs: virtualFs,
  });
  const session = new loaded.AuditSession(contextWith({}), { warn() {}, info() {} });

  await session.indexWorkspace();
  assert.match(excludeGlob, /generated/);
  assert.equal(session.snapshot.files, 1);
  assert.equal(session.snapshot.indexDiscoveredFiles, 1);
  assert.equal(session.analysisForUri(excluded), undefined);
  assert.equal(session.snapshot.projectConfiguration.excludedPatterns, 1);
  session.dispose();
});
