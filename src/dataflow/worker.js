"use strict";

const { parentPort } = require("node:worker_threads");
const { runDataflowAnalysis } = require("./pipeline");
const { WorkspaceAnalysisEngine } = require("../analysis/workspace-engine");
const { buildAuditModel } = require("../audit-analyzer");
const { normalizePath } = require("../identity");

if (!parentPort) throw new Error("TraceGuard dataflow worker must run in a worker thread.");

const engine = new WorkspaceAnalysisEngine();
const cancelled = new Set();
const queued = [];
let draining = false;
let drainScheduled = false;
let activeRequestId;
let peakRssBytes = 0;

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
  const startedAt = performance.now();
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
    else if (message.type === "getAnalysis") {
      result = engine.analyses().find(item => normalizePath(item.absolutePath) === normalizePath(message.absolutePath));
    }
    else throw new Error(`Unknown TraceGuard worker request: ${message.type}`);
    if (message.options?.compactResult && [
      "initializeWorkspace", "updateFile", "removeFile", "reanalyzeAffectedFunctions", "configure",
    ].includes(message.type)) {
      result.auditModel = buildAuditModel(engine.analyses(), engine.reviewReachability());
      if (Array.isArray(result.analyses)) result.analyses = result.analyses.map(compactAnalysis);
      if (result.analysis) result.analysis = compactAnalysis(result.analysis);
    }
    if (result && typeof result === "object") {
      const memory = process.memoryUsage();
      peakRssBytes = Math.max(peakRssBytes, memory.rss);
      result.metadata = {
        ...(result.metadata || {}),
        workerRequestMs: roundMetric(performance.now() - startedAt),
        workerRssBytes: memory.rss,
        workerPeakRssBytes: peakRssBytes,
        workerHeapUsedBytes: memory.heapUsed,
      };
    }
    if (!cancelled.delete(message.id)) parentPort.postMessage({ id: message.id, result });
  } catch (error) {
    parentPort.postMessage({
      id: message.id,
      error: { message: String(error?.message || error), stack: String(error?.stack || "") },
    });
  }
}

function compactAnalysis(analysis) {
  return {
    absolutePath: analysis.absolutePath,
    relativePath: analysis.relativePath,
    language: analysis.language,
    frontend: analysis.frontend,
    signals: analysis.signals || [],
  };
}

function roundMetric(value) {
  return Math.round(value * 100) / 100;
}
