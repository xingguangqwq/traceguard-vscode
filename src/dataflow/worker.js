"use strict";

const { parentPort } = require("node:worker_threads");
const { runDataflowAnalysis } = require("./pipeline");
const { WorkspaceAnalysisEngine } = require("../analysis/workspace-engine");

if (!parentPort) throw new Error("TraceGuard dataflow worker must run in a worker thread.");

const engine = new WorkspaceAnalysisEngine();
const cancelled = new Set();
const queued = [];
let draining = false;
let drainScheduled = false;
let activeRequestId;

parentPort.on("message", message => {
  if (message.type === "cancel") {
    if (activeRequestId === message.requestId || queued.some(item => item.id === message.requestId)) cancelled.add(message.requestId);
    return;
  }
  queued.push(message);
  scheduleDrain();
});

function scheduleDrain() {
  if (drainScheduled || draining) return;
  drainScheduled = true;
  setImmediate(() => void drainQueue());
}

async function drainQueue() {
  drainScheduled = false;
  if (draining) return;
  draining = true;
  try {
    while (queued.length) {
      const message = queued.shift();
      if (cancelled.delete(message.id)) continue;
      activeRequestId = message.id;
      try {
        await dispatch(message);
      } finally {
        activeRequestId = undefined;
      }
    }
  } finally {
    draining = false;
    if (queued.length) scheduleDrain();
  }
}

async function dispatch(message) {
  try {
    if (cancelled.delete(message.id)) return;
    let result;
    if (!message.type || message.type === "analyze") result = runDataflowAnalysis(message.analyses, message.options);
    else if (message.type === "initializeWorkspace") result = await engine.initializeWorkspace(message.files, message.options);
    else if (message.type === "updateFile") result = await engine.updateFile(message.file, message.options);
    else if (message.type === "removeFile") result = await engine.removeFile(message.absolutePath, message.options);
    else if (message.type === "reanalyzeAffectedFunctions") result = engine.reanalyzeAffectedFunctions(message.options);
    else if (message.type === "configure") result = await engine.configure(message.options);
    else if (message.type === "queryPaths") result = engine.queryPaths(message.options);
    else if (message.type === "queryAudit") result = engine.queryAudit(message.options);
    else throw new Error(`Unknown TraceGuard worker request: ${message.type}`);
    if (!cancelled.delete(message.id)) parentPort.postMessage({ id: message.id, result });
  } catch (error) {
    parentPort.postMessage({
      id: message.id,
      error: { message: String(error?.message || error), stack: String(error?.stack || "") },
    });
  }
}
