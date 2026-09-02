"use strict";

const path = require("node:path");
const { Worker } = require("node:worker_threads");
const { normalizePath } = require("../identity");

class DataflowWorkerClient {
  constructor(options = {}) {
    this.nextId = 1;
    this.pending = new Map();
    this.pendingByKey = new Map();
    this.worker = undefined;
    this.readyPromise = undefined;
    this.disposed = false;
    this.initialized = false;
    this.needsReplay = false;
    this.files = new Map();
    this.unsavedFiles = new Map();
    this.fileLoader = options.fileLoader;
    this.pendingReplayMetrics = undefined;
    this.workspaceOptions = {};
    this.queryTimeoutMs = normalizeTimeout(options.queryTimeoutMs ?? options.timeoutMs, 30_000);
    this.indexTimeoutMs = normalizeTimeout(options.indexTimeoutMs, 300_000);
    this.workerPath = options.workerPath || path.join(__dirname, "worker.js");
    this.workerMemoryLimitMb = Math.min(4096, Math.max(256, Number(options.workerMemoryLimitMb) || 1024));
  }

  analyze(analyses, options = {}) {
    return this._request("analyze", { analyses, options }, { timeoutMs: this.indexTimeoutMs });
  }

  async initializeWorkspace(files, options = {}) {
    const result = await this._request("initializeWorkspace", { files, options }, {
      skipReplay: true,
      timeoutMs: this.indexTimeoutMs,
    });
    const skipped = new Set((result.metadata?.sourceAdmissionSkippedDetails || []).map(item => normalizePath(item.absolutePath)));
    const admittedFiles = (files || []).filter(file => !skipped.has(normalizePath(file.absolutePath)));
    this.files = new Map(admittedFiles.map(file => [normalizePath(file.absolutePath), replayMetadata(file)]));
    this.unsavedFiles = new Map(admittedFiles.filter(file => file.unsaved).map(file => [normalizePath(file.absolutePath), { ...file }]));
    if (!this.fileLoader) {
      for (const file of admittedFiles) this.unsavedFiles.set(normalizePath(file.absolutePath), { ...file });
    }
    this.workspaceOptions = { ...options };
    this.initialized = true;
    this.needsReplay = false;
    return result;
  }

  async updateFile(file, options = {}) {
    if (!this.initialized) {
      const initialized = await this.initializeWorkspace([file], options);
      return { ...initialized, analysis: initialized.analyses[0], cacheHit: false };
    }
    const key = normalizePath(file.absolutePath);
    const result = await this._request("updateFile", { file, options }, { cancelKey: `update:${key}` });
    if (result.skippedFile) {
      this.files.delete(key);
      this.unsavedFiles.delete(key);
    } else {
      this.files.set(key, replayMetadata(file));
      if (file.unsaved || !this.fileLoader) this.unsavedFiles.set(key, { ...file });
      else this.unsavedFiles.delete(key);
    }
    return result;
  }

  async removeFile(absolutePath, options = {}) {
    if (!this.initialized) return { removed: false, affectedFiles: [] };
    const key = normalizePath(absolutePath);
    const result = await this._request("removeFile", { absolutePath, options }, { cancelKey: `remove:${key}` });
    if (result.removed) {
      this.files.delete(key);
      this.unsavedFiles.delete(key);
    }
    return result;
  }

  reanalyzeAffectedFunctions(options = {}) {
    if (!this.initialized) return Promise.resolve(emptyDelta());
    return this._request("reanalyzeAffectedFunctions", { options }, { cancelKey: "reanalyze" });
  }

  async configure(options = {}) {
    if (!this.initialized) {
      this.workspaceOptions = { ...this.workspaceOptions, ...options };
      return emptyDelta();
    }
    const result = await this._request("configure", { options }, { cancelKey: "configure" });
    this.workspaceOptions = { ...this.workspaceOptions, ...options };
    return result;
  }

  queryPaths(options = {}) {
    if (!this.initialized) return Promise.resolve({ paths: [], findings: [], metadata: { truncated: false, totalCandidates: 0 } });
    return this._request("queryPaths", { options }, { cancelKey: "query" });
  }

  queryAudit(options = {}) {
    if (!this.initialized) return Promise.resolve({
      schema: "traceguard-audit-query",
      version: 1,
      kind: options.kind,
      title: "TraceGuard Audit Query",
      roots: [],
      summary: { nodes: 0, statuses: {} },
      truncated: false,
    });
    return this._request("queryAudit", { options }, { cancelKey: "audit-query" });
  }

  getAnalysis(absolutePath) {
    if (!this.initialized) return Promise.resolve(undefined);
    return this._request("getAnalysis", { absolutePath }, { cancelKey: `analysis:${normalizePath(absolutePath)}` });
  }

  setIndexTimeoutMs(timeoutMs) {
    this.indexTimeoutMs = normalizeTimeout(timeoutMs, 300_000);
  }

  async dispose() {
    this.disposed = true;
    const error = new Error("TraceGuard dataflow worker was stopped.");
    error.code = "WORKER_DISPOSED";
    this._rejectPending(error);
    const worker = this.worker;
    this.worker = undefined;
    this.readyPromise = undefined;
    if (worker) await worker.terminate();
  }

  cancelActive(reason = "TraceGuard analysis was cancelled.") {
    const error = new Error(reason);
    error.code = "WORKER_CANCELLED";
    const worker = this.worker;
    this.worker = undefined;
    this.readyPromise = undefined;
    this.needsReplay = this.initialized;
    this._rejectPending(error);
    if (worker) void worker.terminate();
  }

  async _request(type, payload, control = {}, retry = true) {
    if (this.disposed) throw new Error("TraceGuard dataflow worker is disposed.");
    try {
      const worker = await this._ensureReady(Boolean(control.skipReplay));
      const result = await this._post(worker, { type, ...payload }, control);
      if (this.pendingReplayMetrics && result && typeof result === "object") {
        result.metadata = { ...(result.metadata || {}), ...this.pendingReplayMetrics };
        this.pendingReplayMetrics = undefined;
      }
      return result;
    } catch (error) {
      if (retry && !this.disposed && isRetriableWorkerFailure(error)) {
        this.needsReplay = this.initialized && type !== "initializeWorkspace";
        return this._request(type, payload, control, false);
      }
      throw error;
    }
  }

  async _ensureReady(skipReplay) {
    if (this.worker) return this.worker;
    if (this.readyPromise) return this.readyPromise;
    this.readyPromise = (async () => {
      const worker = this._spawnWorker();
      try {
        if (this.needsReplay && !skipReplay) {
          const replayStartedAt = performance.now();
          this.pendingReplayMetrics = undefined;
          const files = await this._materializeReplayFiles();
          const replay = await this._post(worker, {
            type: "initializeWorkspace",
            files,
            options: this.workspaceOptions,
          }, { timeoutMs: this.indexTimeoutMs });
          this.pendingReplayMetrics = {
            workerReplayMs: roundMetric(performance.now() - replayStartedAt),
            workerReplayFiles: files.length,
            workerReplayRssBytes: replay?.metadata?.workerRssBytes,
            workerReplayPeakRssBytes: replay?.metadata?.workerPeakRssBytes,
          };
          this.needsReplay = false;
        }
        return worker;
      } catch (error) {
        this._fail(worker, error);
        void worker.terminate();
        throw error;
      }
    })();
    try {
      return await this.readyPromise;
    } finally {
      this.readyPromise = undefined;
    }
  }

  async _materializeReplayFiles() {
    const materialized = [];
    for (const [key, metadata] of [...this.files]) {
      const unsaved = this.unsavedFiles.get(key);
      const file = unsaved || (this.fileLoader ? await this.fileLoader({ ...metadata }) : undefined);
      if (!file || typeof file.text !== "string") {
        this.files.delete(key);
        this.unsavedFiles.delete(key);
        continue;
      }
      materialized.push({ ...metadata, ...file });
      this.files.set(key, replayMetadata({ ...metadata, ...file }));
    }
    return materialized;
  }

  _spawnWorker() {
    const worker = new Worker(this.workerPath, {
      execArgv: [],
      resourceLimits: { maxOldGenerationSizeMb: this.workerMemoryLimitMb, stackSizeMb: 8 },
    });
    worker.on("message", message => {
      const request = this.pending.get(message.id);
      if (!request) return;
      this._finishRequest(message.id, request);
      if (message.error) {
        const error = new Error(message.error.message);
        error.stack = message.error.stack || error.stack;
        request.reject(error);
      } else request.resolve(message.result);
    });
    worker.on("error", error => {
      error.code ||= "WORKER_ERROR";
      this._fail(worker, error);
    });
    worker.on("exit", code => {
      if (!this.disposed && this.worker === worker) {
        const error = new Error(`TraceGuard dataflow worker exited with code ${code}.`);
        error.code = "WORKER_EXIT";
        this._fail(worker, error);
      }
    });
    this.worker = worker;
    return worker;
  }

  _post(worker, message, control = {}) {
    const cancelKey = control.cancelKey;
    if (cancelKey) this._supersede(cancelKey, worker);
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timeoutMs = control.timeoutMs === undefined ? this.queryTimeoutMs : control.timeoutMs;
      const timer = timeoutMs > 0 ? setTimeout(() => {
        const request = this.pending.get(id);
        if (!request) return;
        this._finishRequest(id, request);
        const error = new Error(`TraceGuard analysis worker timed out after ${timeoutMs} ms while handling ${message.type}.`);
        error.code = "WORKER_TIMEOUT";
        reject(error);
        this._fail(worker, error);
        void worker.terminate();
      }, timeoutMs) : undefined;
      const request = { resolve, reject, timer, cancelKey };
      this.pending.set(id, request);
      if (cancelKey) this.pendingByKey.set(cancelKey, id);
      try {
        worker.postMessage({ id, ...message });
      } catch (error) {
        this._finishRequest(id, request);
        reject(error);
      }
    });
  }

  _supersede(cancelKey, worker) {
    const previousId = this.pendingByKey.get(cancelKey);
    const previous = this.pending.get(previousId);
    if (!previous) return;
    this._finishRequest(previousId, previous);
    const error = new Error("TraceGuard discarded a superseded analysis request.");
    error.code = "SUPERSEDED";
    previous.reject(error);
    try { worker.postMessage({ type: "cancel", requestId: previousId }); } catch {}
  }

  _finishRequest(id, request) {
    if (request.timer) clearTimeout(request.timer);
    this.pending.delete(id);
    if (request.cancelKey && this.pendingByKey.get(request.cancelKey) === id) this.pendingByKey.delete(request.cancelKey);
  }

  _fail(worker, error) {
    if (this.worker !== worker) return;
    this.worker = undefined;
    this.pendingReplayMetrics = undefined;
    this.needsReplay = this.initialized;
    this._rejectPending(error);
  }

  _rejectPending(error) {
    for (const [id, request] of [...this.pending]) {
      this._finishRequest(id, request);
      request.reject(error);
    }
    this.pendingByKey.clear();
  }
}

function normalizeTimeout(value, fallback) {
  if (value === 0) return 0;
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 100 ? Math.floor(numeric) : fallback;
}

function replayMetadata(file = {}) {
  const { text: _text, analysis: _analysis, ...metadata } = file;
  return metadata;
}

function roundMetric(value) {
  return Math.round(Number(value) * 100) / 100;
}

function emptyDelta() {
  return { affectedFiles: [], findingDelta: { upsert: [], removedIds: [] }, pathDelta: { upsert: [], removedIds: [] } };
}

function isRetriableWorkerFailure(error) {
  return error?.code === "WORKER_EXIT" || error?.code === "WORKER_ERROR";
}

module.exports = { DataflowWorkerClient, isRetriableWorkerFailure };
