const path = require("path");
const vscode = require("vscode");
const { analyzeText, buildAuditModel, shortHash } = require("./audit-analyzer");
const { DataflowWorkerClient } = require("./dataflow/worker-client");
const { languageForPath } = require("./language-support");
const { reconcileReviewStatuses } = require("./review/status-store");

const SOURCE_GLOB = "**/*.{java,jsp,jspx,php,phtml,php3,php4,php5,inc,js,jsx,mjs,cjs,ts,tsx,py,cs,go}";
const EXCLUDE_GLOB = "**/{.git,.svn,node_modules,vendor,target,build,dist,coverage,.gradle,.mvn,.venv,venv,__pycache__,bin,obj,storage,cache,tmp,temp}/**";
const MAX_FILE_SIZE = 2 * 1024 * 1024;
const MAX_SOURCE_FILES = 8000;

class AuditSession {
  constructor(context, output) {
    this.context = context;
    this.output = output;
    this.analyses = [];
    this.model = emptyModel();
    this.indexing = false;
    this.indexPromise = undefined;
    this.fullIndexBuilt = false;
    this.indexStatus = { cancelled: false, truncated: false, skipped: 0, discovered: 0, processed: 0 };
    this.dataflowWorker = new DataflowWorkerClient();
    this.modelGeneration = 0;
    this._changed = new vscode.EventEmitter();
    this.onDidChange = this._changed.event;
  }

  get snapshot() {
    const statuses = this.context.workspaceState.get("traceguard.audit.statuses", {});
    const evidence = this.context.workspaceState.get("traceguard.audit.evidence", []);
    const items = this.model.items.map(item => {
      const record = statuses[item.id] || item.legacyIds?.map(id => statuses[id]).find(Boolean);
      return { ...item, status: record?.status || "unreviewed", statusUpdatedAt: record?.updatedAt || "" };
    });
    const reviewed = items.filter(item => item.status === "reviewed").length;
    const inReview = items.filter(item => item.status === "in_review").length;
    return {
      ...this.model,
      items,
      evidence,
      coverage: items.length ? Math.round((reviewed / items.length) * 100) : 0,
      statusCounts: {
        unreviewed: items.length - reviewed - inReview - items.filter(item => item.status === "blocked").length,
        in_review: inReview,
        reviewed,
        blocked: items.filter(item => item.status === "blocked").length,
      },
    };
  }

  indexWorkspace(progress, token) {
    if (this.indexPromise) return this.indexPromise;
    this.indexing = true;
    const operation = this._indexWorkspace(progress, token);
    this.indexPromise = operation.finally(() => {
      this.indexing = false;
      this.indexPromise = undefined;
    });
    return this.indexPromise;
  }

  async _indexWorkspace(progress, token) {
    let discovered;
    try {
      discovered = await vscode.workspace.findFiles(SOURCE_GLOB, EXCLUDE_GLOB, MAX_SOURCE_FILES + 1, token);
    } catch (error) {
      if (!token?.isCancellationRequested) throw error;
      this.indexStatus = { cancelled: true, truncated: false, skipped: 0, discovered: 0, processed: 0 };
      this.output.info("Audit indexing cancelled before file discovery completed; the previous index was kept.");
      return this.snapshot;
    }
    const truncated = discovered.length > MAX_SOURCE_FILES;
    const uris = discovered.slice(0, MAX_SOURCE_FILES);
    const analyses = [];
    let skipped = 0;
    for (let index = 0; index < uris.length; index += 1) {
      if (token?.isCancellationRequested) {
        this.indexStatus = { cancelled: true, truncated, skipped, discovered: discovered.length, processed: analyses.length };
        this.output.info(`Audit indexing cancelled after ${analyses.length} files; the previous index was kept.`);
        return this.snapshot;
      }
      const uri = uris[index];
      if (index % 20 === 0) progress?.report({ message: `Indexing ${index + 1} / ${uris.length}`, increment: uris.length ? 2000 / uris.length : 0 });
      try {
        const stat = await vscode.workspace.fs.stat(uri);
        if (stat.size > MAX_FILE_SIZE) { skipped += 1; continue; }
        const bytes = await vscode.workspace.fs.readFile(uri);
        const text = Buffer.from(bytes).toString("utf8");
        const language = languageForPath(uri.fsPath);
        if (!language) continue;
        analyses.push(analyzeText(text, language, uri.fsPath, workspaceRelativePath(uri)));
      } catch (error) {
        skipped += 1;
        this.output.warn(`Audit index skipped ${uri.fsPath}: ${error.message}`);
      }
    }
    const previousAnalyses = this.analyses;
    this.analyses = analyses;
    try {
      await this._rebuildModel();
    } catch (error) {
      if (this.analyses === analyses) this.analyses = previousAnalyses;
      throw error;
    }
    this.fullIndexBuilt = true;
    this.model = {
      ...this.model,
      indexIncomplete: truncated || skipped > 0,
      indexTruncated: truncated,
      indexSkippedFiles: skipped,
      indexDiscoveredFiles: discovered.length,
      indexScope: "workspace",
    };
    this.indexStatus = { cancelled: false, truncated, skipped, discovered: discovered.length, processed: analyses.length };
    await this._reconcileReviewStatuses(true);
    this.output.info(`Audit index: ${this.model.files} files, ${this.model.functions} functions, ${this.model.entries.length} entry points, ${this.model.findings.length} findings, ${this.model.items.length} review targets${truncated || skipped ? ` (${truncated ? "file limit reached; " : ""}${skipped} skipped)` : ""}.`);
    this._changed.fire(this.snapshot);
    return this.snapshot;
  }

  async reindexFile(uri) {
    if (!languageForPath(uri.fsPath) || !vscode.workspace.getWorkspaceFolder(uri)) return;
    try {
      const stat = await vscode.workspace.fs.stat(uri);
      if (stat.size > MAX_FILE_SIZE) {
        await this.removeFiles([uri]);
        return;
      }
      const bytes = await vscode.workspace.fs.readFile(uri);
      await this._replaceAnalysis(uri, Buffer.from(bytes).toString("utf8"));
    } catch (error) {
      this.output.warn(`Audit re-index failed for ${uri.fsPath}: ${error.message}`);
    }
  }

  async reindexDocument(document) {
    if (!languageForPath(document.uri.fsPath) || !vscode.workspace.getWorkspaceFolder(document.uri)) return;
    try {
      const text = document.getText();
      if (Buffer.byteLength(text, "utf8") > MAX_FILE_SIZE) {
        await this.removeFiles([document.uri]);
        return;
      }
      await this._replaceAnalysis(document.uri, text);
    } catch (error) {
      this.output.warn(`Live audit index failed for ${document.uri.fsPath}: ${error.message}`);
    }
  }

  async _replaceAnalysis(uri, text) {
    const analysis = analyzeText(text, languageForPath(uri.fsPath), uri.fsPath, workspaceRelativePath(uri));
    const normalized = path.normalize(uri.fsPath).toLowerCase();
    const previousAnalyses = this.analyses;
    const analyses = [...previousAnalyses.filter(item => path.normalize(item.absolutePath).toLowerCase() !== normalized), analysis];
    this.analyses = analyses;
    let rebuilt;
    try {
      rebuilt = await this._rebuildModel();
    } catch (error) {
      if (this.analyses === analyses) this.analyses = previousAnalyses;
      throw error;
    }
    if (!rebuilt) return;
    if (!this.fullIndexBuilt) this.model = { ...this.model, indexIncomplete: true, indexScope: "current-files" };
    await this._reconcileReviewStatuses(this.fullIndexBuilt);
    this._changed.fire(this.snapshot);
  }

  async removeFiles(uris) {
    const removed = new Set(uris.map(uri => path.normalize(uri.fsPath).toLowerCase()));
    const analyses = this.analyses.filter(item => !removed.has(path.normalize(item.absolutePath).toLowerCase()));
    if (analyses.length === this.analyses.length) return false;
    const previousAnalyses = this.analyses;
    this.analyses = analyses;
    let rebuilt;
    try {
      rebuilt = await this._rebuildModel();
    } catch (error) {
      if (this.analyses === analyses) this.analyses = previousAnalyses;
      throw error;
    }
    if (!rebuilt) return true;
    if (!this.fullIndexBuilt) this.model = { ...this.model, indexIncomplete: true, indexScope: "current-files" };
    await this._reconcileReviewStatuses(this.fullIndexBuilt);
    this._changed.fire(this.snapshot);
    return true;
  }

  async _rebuildModel() {
    const generation = ++this.modelGeneration;
    const configuration = vscode.workspace.getConfiguration("traceguard");
    const maxDepth = configuration.get("flowMaxDepth", 6);
    const maxPaths = Math.min(400, Math.max(80, configuration.get("flowMaxPaths", 40) * 5));
    const analysisModel = buildAuditModel(this.analyses);
    const dataflow = await this.dataflowWorker.analyze(this.analyses, { maxDepth, maxPaths });
    if (generation !== this.modelGeneration) return false;
    const indexMetadata = {
      indexIncomplete: Boolean(this.model.indexIncomplete),
      indexTruncated: Boolean(this.model.indexTruncated),
      indexSkippedFiles: this.model.indexSkippedFiles || 0,
      indexDiscoveredFiles: this.model.indexDiscoveredFiles || 0,
      indexScope: this.model.indexScope || "none",
    };
    this.model = {
      ...analysisModel,
      findings: dataflow.findings,
      findingPathsTruncated: dataflow.metadata.truncated,
      findingPathCandidates: dataflow.metadata.totalCandidates,
      ...indexMetadata,
    };
    return true;
  }

  async rebuildModel() {
    const rebuilt = await this._rebuildModel();
    if (!rebuilt) return this.snapshot;
    this._changed.fire(this.snapshot);
    return this.snapshot;
  }

  async setStatus(itemId, status) {
    if (!["unreviewed", "in_review", "reviewed", "blocked"].includes(status)) return;
    const statuses = { ...this.context.workspaceState.get("traceguard.audit.statuses", {}) };
    const item = this.model.items.find(candidate => candidate.id === itemId);
    for (const legacyId of item?.legacyIds || []) delete statuses[legacyId];
    if (status === "unreviewed") delete statuses[itemId];
    else statuses[itemId] = { status, updatedAt: new Date().toISOString() };
    await this.context.workspaceState.update("traceguard.audit.statuses", statuses);
    this._changed.fire(this.snapshot);
  }

  async addEvidence(input) {
    const evidence = [...this.context.workspaceState.get("traceguard.audit.evidence", [])];
    const item = {
      id: shortHash(`${Date.now()}:${input.absolutePath}:${input.line}:${input.type}:${input.code}`),
      createdAt: new Date().toISOString(),
      ...input,
      note: String(input.note || "").slice(0, 10000),
      code: String(input.code || "").slice(0, 50000),
      relativePath: String(input.relativePath || "").slice(0, 2000),
    };
    evidence.unshift(item);
    await this.context.workspaceState.update("traceguard.audit.evidence", evidence.slice(0, 500));
    this._changed.fire(this.snapshot);
    return item;
  }

  async removeEvidence(evidenceId) {
    const evidence = this.context.workspaceState.get("traceguard.audit.evidence", []).filter(item => item.id !== evidenceId);
    await this.context.workspaceState.update("traceguard.audit.evidence", evidence);
    this._changed.fire(this.snapshot);
  }

  exportPortableState() {
    const statuses = this.context.workspaceState.get("traceguard.audit.statuses", {});
    const evidence = this.context.workspaceState.get("traceguard.audit.evidence", []).map(item => {
      const { absolutePath: _absolutePath, ...portable } = item;
      return portable;
    });
    return {
      schema: "traceguard-review-session",
      version: 1,
      exportedAt: new Date().toISOString(),
      statuses,
      evidence,
    };
  }

  async importPortableState(payload) {
    if (!payload || payload.schema !== "traceguard-review-session" || payload.version !== 1 || typeof payload.statuses !== "object" || !Array.isArray(payload.evidence)) {
      throw new Error("This file is not a supported TraceGuard review session.");
    }
    const allowedStatuses = new Set(["in_review", "reviewed", "blocked"]);
    const importedStatuses = Object.fromEntries(Object.entries(payload.statuses)
      .slice(0, 10000)
      .filter(([key, value]) => key.length <= 128 && allowedStatuses.has(value?.status)));
    const currentStatuses = this.context.workspaceState.get("traceguard.audit.statuses", {});
    const currentEvidence = this.context.workspaceState.get("traceguard.audit.evidence", []);
    const importedEvidence = payload.evidence
      .slice(0, 1000)
      .filter(item => item && typeof item.id === "string" && typeof item.relativePath === "string")
      .map(item => {
        const relativePath = item.relativePath.slice(0, 2000).replaceAll("\\", "/");
        return {
          id: item.id.slice(0, 128),
          type: ["Source", "Sink", "Authorization", "Validation", "Observation"].includes(item.type) ? item.type : "Observation",
          note: typeof item.note === "string" ? item.note.slice(0, 10000) : "",
          code: typeof item.code === "string" ? item.code.slice(0, 50000) : "",
          relativePath,
          absolutePath: resolveWorkspacePath(relativePath),
          line: Number.isInteger(item.line) && item.line > 0 ? item.line : 1,
          endLine: Number.isInteger(item.endLine) && item.endLine >= item.line ? item.endLine : (Number.isInteger(item.line) && item.line > 0 ? item.line : 1),
          createdAt: typeof item.createdAt === "string" ? item.createdAt : new Date().toISOString(),
          auditItemId: typeof item.auditItemId === "string" ? item.auditItemId.slice(0, 128) : undefined,
        };
      })
      .filter(item => item.absolutePath);
    const evidenceById = new Map(currentEvidence.map(item => [item.id, item]));
    for (const item of importedEvidence) evidenceById.set(item.id, item);
    await this.context.workspaceState.update("traceguard.audit.statuses", { ...currentStatuses, ...importedStatuses });
    await this.context.workspaceState.update("traceguard.audit.evidence", [...evidenceById.values()].slice(0, 500));
    this._changed.fire(this.snapshot);
    return { statuses: Object.keys(importedStatuses).length, evidence: importedEvidence.length };
  }

  itemAt(uri, zeroBasedLine) {
    const target = path.normalize(uri.fsPath).toLowerCase();
    return this.snapshot.items
      .filter(item => path.normalize(item.absolutePath).toLowerCase() === target && zeroBasedLine + 1 >= item.line && zeroBasedLine + 1 <= item.endLine)
      .sort((a, b) => (a.endLine - a.line) - (b.endLine - b.line))[0];
  }

  signalsAt(uri, zeroBasedLine) {
    const target = path.normalize(uri.fsPath).toLowerCase();
    const analysis = this.analyses.find(item => path.normalize(item.absolutePath).toLowerCase() === target);
    return analysis?.signals.filter(signal => signal.line === zeroBasedLine + 1) || [];
  }

  itemsForUri(uri) {
    const target = path.normalize(uri.fsPath).toLowerCase();
    return this.snapshot.items.filter(item => path.normalize(item.absolutePath).toLowerCase() === target);
  }

  analysisForUri(uri) {
    const target = path.normalize(uri.fsPath).toLowerCase();
    return this.analyses.find(item => path.normalize(item.absolutePath).toLowerCase() === target);
  }

  async sourceSinkPathsFrom(uri, zeroBasedLine, identifier, code) {
    const configuration = vscode.workspace.getConfiguration("traceguard", uri);
    const dataflow = await this.dataflowWorker.analyze(this.analyses, {
      absolutePath: uri.fsPath,
      line: zeroBasedLine + 1,
      identifier,
      code,
      maxDepth: configuration.get("flowMaxDepth", 6),
      maxPaths: configuration.get("flowMaxPaths", 40),
    });
    const paths = dataflow.paths;
    const findings = dataflow.findings;
    const findingByPath = new Map(findings.flatMap(finding => finding.pathIds.map(pathId => [pathId, finding])));
    const result = paths.map(flowPath => ({ ...flowPath, finding: findingByPath.get(flowPath.id) }));
    Object.defineProperties(result, {
      truncated: { value: dataflow.metadata.truncated, enumerable: false },
      totalCandidates: { value: dataflow.metadata.totalCandidates, enumerable: false },
    });
    return result;
  }

  async _reconcileReviewStatuses(complete) {
    const current = this.context.workspaceState.get("traceguard.audit.statuses", {});
    const result = reconcileReviewStatuses(current, this.model.items, { complete });
    if (!result.changed) return result;
    await this.context.workspaceState.update("traceguard.audit.statuses", result.statuses);
    if (result.migrated || result.removed) {
      this.output.info(`Review state: ${result.migrated} migrated, ${result.removed} expired orphan record(s).`);
    }
    return result;
  }

  dispose() {
    void this.dataflowWorker.dispose();
    this._changed.dispose();
  }
}

function emptyModel() {
  return {
    indexed_at: "",
    files: 0,
    lines: 0,
    functions: 0,
    entries: [],
    findings: [],
    findingPathsTruncated: false,
    findingPathCandidates: 0,
    indexIncomplete: false,
    indexTruncated: false,
    indexSkippedFiles: 0,
    indexDiscoveredFiles: 0,
    indexScope: "none",
    signals: [],
    items: [],
    languages: {},
  };
}

function resolveWorkspacePath(relativePath) {
  const folders = vscode.workspace.workspaceFolders || [];
  if (!folders.length) return undefined;
  let folder = folders[0];
  let localPath = relativePath;
  if (folders.length > 1) {
    const match = folders.find(candidate => relativePath === candidate.name || relativePath.startsWith(`${candidate.name}/`));
    if (!match) return undefined;
    folder = match;
    localPath = relativePath.slice(match.name.length).replace(/^\//, "");
  }
  const root = path.resolve(folder.uri.fsPath);
  const resolved = path.resolve(root, localPath);
  return resolved === root || resolved.startsWith(`${root}${path.sep}`) ? resolved : undefined;
}

function workspaceRelativePath(uri) {
  const folder = vscode.workspace.getWorkspaceFolder(uri);
  if (!folder) return path.basename(uri.fsPath).replaceAll("\\", "/");
  const localPath = path.relative(folder.uri.fsPath, uri.fsPath).replaceAll("\\", "/");
  return vscode.workspace.workspaceFolders?.length > 1 ? `${folder.name}/${localPath}` : localPath;
}

module.exports = { AuditSession, EXCLUDE_GLOB, MAX_FILE_SIZE, MAX_SOURCE_FILES, SOURCE_GLOB, workspaceRelativePath };
