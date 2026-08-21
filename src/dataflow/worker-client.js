"use strict";

const path = require("node:path");
const { Worker } = require("node:worker_threads");

class DataflowWorkerClient {
  constructor() {
    this.nextId = 1;
    this.pending = new Map();
    this.worker = undefined;
    this.disposed = false;
  }

  analyze(analyses, options = {}) {
    if (this.disposed) return Promise.reject(new Error("TraceGuard dataflow worker is disposed."));
    const worker = this._worker();
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try {
        worker.postMessage({ id, analyses, options });
      } catch (error) {
        this.pending.delete(id);
        reject(error);
      }
    });
  }

  async dispose() {
    this.disposed = true;
    const error = new Error("TraceGuard dataflow worker was stopped.");
    for (const request of this.pending.values()) request.reject(error);
    this.pending.clear();
    const worker = this.worker;
    this.worker = undefined;
    if (worker) await worker.terminate();
  }

  _worker() {
    if (this.worker) return this.worker;
    const worker = new Worker(path.join(__dirname, "worker.js"), { execArgv: [] });
    worker.on("message", message => {
      const request = this.pending.get(message.id);
      if (!request) return;
      this.pending.delete(message.id);
      if (message.error) {
        const error = new Error(message.error.message);
        error.stack = message.error.stack || error.stack;
        request.reject(error);
      } else request.resolve(message.result);
    });
    worker.on("error", error => this._fail(worker, error));
    worker.on("exit", code => {
      if (!this.disposed && this.worker === worker) {
        this._fail(worker, new Error(`TraceGuard dataflow worker exited with code ${code}.`));
      }
    });
    this.worker = worker;
    return worker;
  }

  _fail(worker, error) {
    if (this.worker !== worker) return;
    for (const request of this.pending.values()) request.reject(error);
    this.pending.clear();
    this.worker = undefined;
  }
}

module.exports = { DataflowWorkerClient };
