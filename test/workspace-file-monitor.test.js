"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { WorkspaceFileMonitor } = require("../src/analysis/workspace-file-monitor");

function harness(options = {}) {
  const listeners = {};
  const event = name => listener => { listeners[name] = listener; return { dispose() { delete listeners[name]; } }; };
  const workspace = {
    createFileSystemWatcher: () => ({ onDidCreate: event("create"), onDidChange: event("change"), onDidDelete: event("delete"), dispose() {} }),
    onDidChangeWorkspaceFolders: event("roots"),
  };
  const batches = [], states = [], errors = [];
  const monitor = new WorkspaceFileMonitor(workspace, {
    debounceMs: 10000,
    isRelevant: () => true,
    onBatch: async batch => { batches.push(batch); },
    onPending: pending => states.push(pending),
    onError: error => errors.push(error),
    ...options,
  });
  return { monitor, listeners, batches, states, errors };
}

test("filesystem events coalesce by path and workspace root changes request a rescan", async () => {
  const { monitor, listeners, batches, states } = harness();
  try {
    const uri = { fsPath: "C:/repo/a.java" };
    listeners.create(uri); listeners.change(uri); listeners.delete(uri);
    listeners.roots({ added: [], removed: [] });
    await monitor.flush();
    assert.equal(batches.length, 1);
    assert.deepEqual(batches[0].changes, [{ kind: "delete", uri }]);
    assert.equal(batches[0].rescan, true);
    assert.equal(states.at(-1), false);
  } finally { monitor.dispose(); }
});

test("events arriving during synchronization are serialized into a later batch", async () => {
  let release, started;
  const entered = new Promise(resolve => { started = resolve; });
  const barrier = new Promise(resolve => { release = resolve; });
  let active = 0, maximum = 0, calls = 0;
  const { monitor, listeners } = harness({ onBatch: async () => {
    active++; maximum = Math.max(maximum, active); calls++;
    if (calls === 1) { started(); await barrier; }
    active--;
  } });
  try {
    listeners.change({ fsPath: "/repo/a.py" });
    const first = monitor.flush();
    await entered;
    listeners.change({ fsPath: "/repo/b.py" });
    const second = monitor.flush();
    release(); await Promise.all([first, second]);
    assert.equal(maximum, 1);
    assert.equal(calls, 2);
  } finally { release(); monitor.dispose(); }
});

test("ignored files and disposed watchers never schedule analysis", async () => {
  const { monitor, listeners, batches } = harness({ isRelevant: uri => !uri.fsPath.includes("node_modules") });
  listeners.change({ fsPath: "/repo/node_modules/a.js" });
  await monitor.flush();
  assert.equal(batches.length, 0);
  listeners.change({ fsPath: "/repo/a.js" });
  monitor.dispose(); await monitor.flush();
  assert.equal(batches.length, 0);
  assert.equal(listeners.change, undefined);
});

test("queue overflow is bounded and becomes one full rescan", async () => {
  const { monitor, listeners, batches } = harness({ maxPending: 3 });
  try {
    for (let i = 0; i < 20; i++) listeners.change({ fsPath: `/repo/${i}.js` });
    assert.ok(monitor.changes.size <= 3);
    await monitor.flush();
    assert.equal(batches.length, 1);
    assert.equal(batches[0].rescan, true);
  } finally { monitor.dispose(); }
});

test("failed synchronization stays stale and the next event retries with a full rescan", async () => {
  let fail = true;
  const batches = [];
  const { monitor, listeners, states, errors } = harness({ onBatch: async batch => {
    batches.push(batch);
    if (fail) throw new Error("disk temporarily unavailable");
  } });
  try {
    listeners.change({ fsPath: "/repo/a.js" }); await monitor.flush();
    assert.equal(states.at(-1), true);
    assert.equal(errors.length, 1);
    fail = false;
    listeners.change({ fsPath: "/repo/b.js" }); await monitor.flush();
    assert.equal(batches[1].rescan, true);
    assert.equal(states.at(-1), false);
  } finally { monitor.dispose(); }
});
