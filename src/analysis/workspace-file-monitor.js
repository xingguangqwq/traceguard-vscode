"use strict";

const { normalizePath } = require("../identity");

// One bounded, serialized queue for disk changes (including terminal/git edits).
// Filtering happens before enqueueing; an overflow requests a quota-bound rescan.
class WorkspaceFileMonitor {
  constructor(workspace, options) {
    this.options = options;
    this.changes = new Map();
    this.rescan = false;
    this.disposed = false;
    this.maxPending = options.maxPending || 1000;
    this.debounceMs = options.debounceMs ?? 250;
    const watcher = workspace.createFileSystemWatcher("**/*");
    this.subscriptions = [watcher,
      watcher.onDidCreate(uri => this.enqueue("create", uri)),
      watcher.onDidChange(uri => this.enqueue("change", uri)),
      watcher.onDidDelete(uri => this.enqueue("delete", uri)),
      workspace.onDidChangeWorkspaceFolders(() => this.requestRescan()),
    ];
  }

  enqueue(kind, uri) {
    if (this.disposed || !this.options.isRelevant(uri, kind)) return;
    if (!this.rescan) this.changes.set(normalizePath(uri.fsPath), { kind, uri });
    if (this.changes.size > this.maxPending) {
      this.changes.clear();
      this.rescan = true;
    }
    this._schedule();
  }

  requestRescan() {
    if (this.disposed || this.options.isActive?.() === false) return;
    this.rescan = true;
    this._schedule();
  }

  _schedule() {
    this.options.onPending?.(true);
    clearTimeout(this.timer);
    this.timer = setTimeout(() => { void this.flush(); }, this.debounceMs);
  }

  flush() {
    clearTimeout(this.timer);
    if (this.disposed) return Promise.resolve();
    if (this.running) return this.running;
    const run = this._drain();
    this.running = run;
    return run.finally(() => { if (this.running === run) this.running = undefined; });
  }

  async _drain() {
    let failed = false;
    while (!this.disposed && (this.rescan || this.changes.size)) {
      const batch = { rescan: this.rescan, changes: [...this.changes.values()] };
      this.rescan = false;
      this.changes.clear();
      try { await this.options.onBatch(batch); }
      catch (error) {
        // Keep a stale indicator, but do not spin retrying an unavailable disk.
        this.rescan = true;
        failed = true;
        clearTimeout(this.timer);
        this.options.onError?.(error);
        break;
      }
    }
    if (!this.disposed) this.options.onPending?.(failed);
  }

  dispose() {
    this.disposed = true;
    clearTimeout(this.timer);
    this.changes.clear();
    for (const subscription of this.subscriptions) subscription.dispose();
  }
}

module.exports = { WorkspaceFileMonitor };
