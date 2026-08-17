const path = require("path");
const vscode = require("vscode");
const { analyzeText, buildAuditModel, shortHash } = require("./audit-analyzer");
const { languageForPath } = require("./language-support");

const SOURCE_GLOB = "**/*.{java,jsp,jspx,php,phtml,php3,php4,php5,inc,js,jsx,mjs,cjs,ts,tsx,py,cs,go}";
const EXCLUDE_GLOB = "**/{.git,.svn,node_modules,vendor,target,build,dist,coverage,.gradle,.mvn,.venv,venv,__pycache__,bin,obj,storage,cache,tmp,temp}/**";
const MAX_FILE_SIZE = 2 * 1024 * 1024;

class AuditSession {
  constructor(context, output) {
    this.context = context;
    this.output = output;
    this.analyses = [];
    this.model = emptyModel();
    this.indexing = false;
    this._changed = new vscode.EventEmitter();
    this.onDidChange = this._changed.event;
  }

  get snapshot() {
    const statuses = this.context.workspaceState.get("traceguard.audit.statuses", {});
    const evidence = this.context.workspaceState.get("traceguard.audit.evidence", []);
    const items = this.model.items.map(item => ({ ...item, status: statuses[item.id]?.status || "unreviewed", statusUpdatedAt: statuses[item.id]?.updatedAt || "" }));
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

  async indexWorkspace(progress, token) {
    if (this.indexing) return this.snapshot;
    this.indexing = true;
    try {
      const uris = await vscode.workspace.findFiles(SOURCE_GLOB, EXCLUDE_GLOB, 8000, token);
      const analyses = [];
      for (let index = 0; index < uris.length; index += 1) {
        if (token?.isCancellationRequested) break;
        const uri = uris[index];
        if (index % 20 === 0) progress?.report({ message: `Indexing ${index + 1} / ${uris.length}`, increment: uris.length ? 2000 / uris.length : 0 });
        try {
          const stat = await vscode.workspace.fs.stat(uri);
          if (stat.size > MAX_FILE_SIZE) continue;
          const bytes = await vscode.workspace.fs.readFile(uri);
          const text = Buffer.from(bytes).toString("utf8");
          const language = languageForPath(uri.fsPath);
          if (!language) continue;
          const folder = vscode.workspace.getWorkspaceFolder(uri);
          const localPath = folder ? path.relative(folder.uri.fsPath, uri.fsPath) : path.basename(uri.fsPath);
          const relativePath = vscode.workspace.workspaceFolders?.length > 1 && folder ? `${folder.name}/${localPath}` : localPath;
          analyses.push(analyzeText(text, language, uri.fsPath, relativePath.replaceAll("\\", "/")));
        } catch (error) {
          this.output.warn(`Audit index skipped ${uri.fsPath}: ${error.message}`);
        }
      }
      this.analyses = analyses;
      this.model = buildAuditModel(analyses);
      this.output.info(`Audit index: ${this.model.files} files, ${this.model.functions} functions, ${this.model.entries.length} entry points, ${this.model.items.length} review targets.`);
      this._changed.fire(this.snapshot);
      return this.snapshot;
    } finally {
      this.indexing = false;
    }
  }

  async reindexFile(uri) {
    if (!languageForPath(uri.fsPath)) return;
    try {
      const bytes = await vscode.workspace.fs.readFile(uri);
      await this._replaceAnalysis(uri, Buffer.from(bytes).toString("utf8"));
    } catch (error) {
      this.output.warn(`Audit re-index failed for ${uri.fsPath}: ${error.message}`);
    }
  }

  async reindexDocument(document) {
    if (!languageForPath(document.uri.fsPath)) return;
    try {
      await this._replaceAnalysis(document.uri, document.getText());
    } catch (error) {
      this.output.warn(`Live audit index failed for ${document.uri.fsPath}: ${error.message}`);
    }
  }

  async _replaceAnalysis(uri, text) {
    const folder = vscode.workspace.getWorkspaceFolder(uri);
    const localPath = folder ? path.relative(folder.uri.fsPath, uri.fsPath) : path.basename(uri.fsPath);
    const relativePath = vscode.workspace.workspaceFolders?.length > 1 && folder ? `${folder.name}/${localPath}` : localPath;
    const analysis = analyzeText(text, languageForPath(uri.fsPath), uri.fsPath, relativePath.replaceAll("\\", "/"));
    const normalized = path.normalize(uri.fsPath).toLowerCase();
    this.analyses = [...this.analyses.filter(item => path.normalize(item.absolutePath).toLowerCase() !== normalized), analysis];
    this.model = buildAuditModel(this.analyses);
    this._changed.fire(this.snapshot);
  }

  async setStatus(itemId, status) {
    if (!["unreviewed", "in_review", "reviewed", "blocked"].includes(status)) return;
    const statuses = { ...this.context.workspaceState.get("traceguard.audit.statuses", {}) };
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
    const importedStatuses = Object.fromEntries(Object.entries(payload.statuses).filter(([, value]) => allowedStatuses.has(value?.status)));
    const currentStatuses = this.context.workspaceState.get("traceguard.audit.statuses", {});
    const currentEvidence = this.context.workspaceState.get("traceguard.audit.evidence", []);
    const importedEvidence = payload.evidence
      .filter(item => item && typeof item.id === "string" && typeof item.relativePath === "string")
      .map(item => ({
        id: item.id.slice(0, 128),
        type: ["Source", "Sink", "Authorization", "Validation", "Observation"].includes(item.type) ? item.type : "Observation",
        note: typeof item.note === "string" ? item.note.slice(0, 10000) : "",
        code: typeof item.code === "string" ? item.code.slice(0, 50000) : "",
        relativePath: item.relativePath,
        absolutePath: resolveWorkspacePath(item.relativePath),
        line: Number.isInteger(item.line) && item.line > 0 ? item.line : 1,
        endLine: Number.isInteger(item.endLine) && item.endLine >= item.line ? item.endLine : (Number.isInteger(item.line) && item.line > 0 ? item.line : 1),
        createdAt: typeof item.createdAt === "string" ? item.createdAt : new Date().toISOString(),
        auditItemId: typeof item.auditItemId === "string" ? item.auditItemId : undefined,
      }))
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

  dispose() {
    this._changed.dispose();
  }
}

function emptyModel() {
  return { indexed_at: "", files: 0, lines: 0, functions: 0, entries: [], signals: [], items: [], languages: {} };
}

function resolveWorkspacePath(relativePath) {
  const folders = vscode.workspace.workspaceFolders || [];
  if (!folders.length) return undefined;
  let folder = folders[0];
  let localPath = relativePath;
  if (folders.length > 1) {
    const match = folders.find(candidate => relativePath === candidate.name || relativePath.startsWith(`${candidate.name}/`));
    if (match) {
      folder = match;
      localPath = relativePath.slice(match.name.length).replace(/^\//, "");
    }
  }
  const root = path.resolve(folder.uri.fsPath);
  const resolved = path.resolve(root, localPath);
  return resolved === root || resolved.startsWith(`${root}${path.sep}`) ? resolved : undefined;
}

module.exports = { AuditSession, EXCLUDE_GLOB, MAX_FILE_SIZE, SOURCE_GLOB };
