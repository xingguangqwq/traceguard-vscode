"use strict";

const assert = require("node:assert/strict");
const path = require("node:path");
const test = require("node:test");
const { isRelevantDiskChange, synchronizeWorkspaceChanges } = require("../src/analysis/workspace-file-sync");

function harness() {
  const root = path.resolve("sync-fixture");
  const calls = [];
  const workspace = {
    isTrusted: true, textDocuments: [],
    getWorkspaceFolder: uri => uri.fsPath.startsWith(root + path.sep) ? { uri: { fsPath: root } } : undefined,
    getConfiguration: () => ({ get: () => 1000 }),
    fs: { stat: async () => ({ size: 10 }) },
  };
  const session = {
    analyses: [], indexStage: { phase: "ready" },
    analysisForUri: uri => session.analyses.find(item => item.absolutePath === uri.fsPath),
    _isExcludedUri: () => false,
    reindexFile: async (uri, options) => calls.push(["file", uri.fsPath, options]),
    reindexDocument: async document => calls.push(["document", document.getText()]),
    removeFiles: async uris => calls.push(["remove", uris.map(uri => uri.fsPath)]),
    reloadProjectConfiguration: async () => calls.push(["config"]),
    reloadProjectIdentities: async () => calls.push(["identity"]),
    indexWorkspace: async () => calls.push(["index"]),
  };
  return { workspace, session, calls, uri: local => ({ fsPath: path.join(root, local) }) };
}

test("disk synchronization preserves unsaved text over an external replacement", async () => {
  const { workspace, session, calls, uri } = harness();
  const file = uri("a.py");
  workspace.textDocuments.push({ uri: file, isDirty: true, getText: () => "unsaved editor text" });
  await synchronizeWorkspaceChanges(workspace, session, { changes: [{ kind: "change", uri: file }] });
  assert.deepEqual(calls, [["document", "unsaved editor text"]]);
});

test("disk deletions remove indexed descendants and delete/recreate uses current disk state", async () => {
  const { workspace, session, calls, uri } = harness();
  session.analyses = [{ absolutePath: uri("src/a.py").fsPath }, { absolutePath: uri("src/b.py").fsPath }, { absolutePath: uri("src-other.py").fsPath }];
  workspace.fs.stat = async () => { throw Object.assign(new Error("missing"), { code: "FileNotFound" }); };
  await synchronizeWorkspaceChanges(workspace, session, { changes: [{ kind: "delete", uri: uri("src") }] });
  assert.deepEqual(calls[0], ["remove", [uri("src/a.py").fsPath, uri("src/b.py").fsPath]]);
  workspace.fs.stat = async () => ({ size: 10 });
  await synchronizeWorkspaceChanges(workspace, session, { changes: [{ kind: "delete", uri: uri("src/a.py") }] });
  assert.equal(calls[1][0], "file");
});

test("metadata and workspace root changes reload configuration before a single full index", async () => {
  const { workspace, session, calls, uri } = harness();
  await synchronizeWorkspaceChanges(workspace, session, { rescan: true, changes: [{ kind: "change", uri: uri(".traceguard.json") }] });
  assert.deepEqual(calls, [["config"], ["identity"], ["index"]]);
});

test("trust, workspace boundaries and default/project exclusions are respected", () => {
  const { workspace, session, uri } = harness();
  assert.equal(isRelevantDiskChange(workspace, session, uri("a.java"), "change"), true);
  assert.equal(isRelevantDiskChange(workspace, session, uri("node_modules/a.js"), "change"), false);
  assert.equal(isRelevantDiskChange(workspace, session, { fsPath: path.resolve("outside.js") }, "change"), false);
  session._isExcludedUri = () => true;
  assert.equal(isRelevantDiskChange(workspace, session, uri("generated.js"), "change"), false);
  workspace.isTrusted = false;
  assert.equal(isRelevantDiskChange(workspace, session, uri(".traceguard.json"), "change"), false);
});

test("index quotas and large event bursts use bounded full indexing", async () => {
  const { workspace, session, calls, uri } = harness();
  workspace.getConfiguration = () => ({ get: () => 1 });
  session.analyses = [{ absolutePath: uri("existing.py").fsPath }];
  await synchronizeWorkspaceChanges(workspace, session, { changes: [{ kind: "create", uri: uri("new.py") }] });
  assert.deepEqual(calls, [["index"]]);
});

test("filesystem updates wait for an in-flight full index", async () => {
  const { workspace, session, calls, uri } = harness();
  let release;
  session.indexPromise = new Promise(resolve => { release = resolve; });
  const sync = synchronizeWorkspaceChanges(workspace, session, { changes: [{ kind: "change", uri: uri("a.py") }] });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.length, 0);
  release(); await sync;
  assert.equal(calls[0][0], "file");
});
