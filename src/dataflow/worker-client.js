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
    this.workspaceOptions = {};
    this.timeoutMs = Math.max(100, options.timeoutMs || 30_000);
    this.workerPath = options.workerPath || path.join(__dirname, "worker.js");
  }

  analyze(analyses, options = {}) {
    return this._request("analyze", { analyses, options });
  }

  async initializeWorkspace(files, options = {}) {
    const result = await this._request("initializeWorkspace", { files, options }, { skipReplay: true });
    this.files = new Map((files || []).map(file => [normalizePath(file.absolutePath), { ...file }]));
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
    this.files.set(key, { ...file });
    return result;
  }

  async removeFile(absolutePath, options = {}) {
    if (!this.initialized) return { removed: false, affectedFiles: [] };
    const key = normalizePath(absolutePath);
    const result = await this._request("removeFile", { absolutePath, options }, { cancelKey: `remove:${key}` });
    if (result.removed) this.files.delete(key);
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
      return await this._post(worker, { type, ...payload }, control.cancelKey);
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
      if (this.needsReplay && !skipReplay) {
        await this._post(worker, {
          type: "initializeWorkspace",
          files: [...this.files.values()],
          options: this.workspaceOptions,
        });
        this.needsReplay = false;
      }
      return worker;
    })();
    try {
      return await this.readyPromise;
    } finally {
      this.readyPromise = undefined;
    }
  }

  _spawnWorker() {
    const worker = new Worker(this.workerPath, { execArgv: [] });
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

  _post(worker, message, cancelKey) {
    if (cancelKey) this._supersede(cancelKey, worker);
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const request = this.pending.get(id);
        if (!request) return;
        this._finishRequest(id, request);
        const error = new Error(`TraceGuard analysis worker timed out after ${this.timeoutMs} ms.`);
        error.code = "WORKER_TIMEOUT";
        reject(error);
        this._fail(worker, error);
        void worker.terminate();
      }, this.timeoutMs);
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
    clearTimeout(request.timer);
    this.pending.delete(id);
    if (request.cancelKey && this.pendingByKey.get(request.cancelKey) === id) this.pendingByKey.delete(request.cancelKey);
  }

  _fail(worker, error) {
    if (this.worker !== worker) return;
    this.worker = undefined;
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

function emptyDelta() {
  return { affectedFiles: [], findingDelta: { upsert: [], removedIds: [] }, pathDelta: { upsert: [], removedIds: [] } };
}

function isRetriableWorkerFailure(error) {
  return error?.code === "WORKER_EXIT" || error?.code === "WORKER_ERROR";
}

module.exports = { DataflowWorkerClient, isRetriableWorkerFailure };
