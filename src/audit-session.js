const path = require("path");
const vscode = require("vscode");
const { buildAuditModel, shortHash } = require("./audit-analyzer");
const {
  MAX_PROJECT_CONFIG_BYTES,
  PROJECT_CONFIG_FILENAME,
  combinedExcludeGlob,
  emptyProjectConfiguration,
  matchesExcludedPath,
  mergeProjectConfigurations,
  parseProjectConfigurationText,
} = require("./config/project-config");
const { DataflowWorkerClient } = require("./dataflow/worker-client");
const { normalizePath, stableHash } = require("./identity");
const { languageForPath } = require("./language-support");
const { reconcileReviewStatuses } = require("./review/status-store");

const SOURCE_GLOB = "**/*.{java,jsp,jspx,php,phtml,php3,php4,php5,inc,js,jsx,mjs,cjs,ts,tsx,py,cs,go}";
const EXCLUDE_GLOB = "**/{.git,.svn,node_modules,vendor,target,build,dist,coverage,.gradle,.mvn,.venv,venv,__pycache__,bin,obj,storage,cache,tmp,temp}/**";
const MAX_FILE_SIZE = 2 * 1024 * 1024;
const DEFAULT_MAX_SOURCE_FILES = 1000;
const HARD_MAX_SOURCE_FILES = 8000;

class AuditSession {
  constructor(context, output) {
    this.context = context;
    this.output = output;
    this.analyses = [];
    this.model = emptyModel();
    this.indexing = false;
    this.indexPromise = undefined;
    this.indexStage = { phase: "idle", message: "Review queue not built", processed: 0, total: 0 };
    this.indexError = undefined;
    this.workspaceIndexBuilt = false;
    this.workspaceCoverageComplete = false;
    this.indexStatus = { cancelled: false, truncated: false, skipped: 0, discovered: 0, processed: 0 };
    this.dataflowWorker = new DataflowWorkerClient();
    this.modelGeneration = 0;
    this.projectConfiguration = emptyProjectConfiguration();
    this.projectConfigurationIssues = [];
    this.projectConfigurationInitialized = false;
    this._changed = new vscode.EventEmitter();
    this.onDidChange = this._changed.event;
  }

  get snapshot() {
    const statuses = this.context.workspaceState.get("traceguard.audit.statuses", {});
    const findingStatuses = this.context.workspaceState.get("traceguard.audit.findingStatuses", {});
    const evidence = this.context.workspaceState.get("traceguard.audit.evidence", []);
    const items = this.model.items.map(item => {
      const record = statuses[item.id] || item.legacyIds?.map(id => statuses[id]).find(Boolean);
      return { ...item, status: record?.status || "unreviewed", statusUpdatedAt: record?.updatedAt || "" };
    });
    const reviewed = items.filter(item => item.status === "reviewed").length;
    const inReview = items.filter(item => item.status === "in_review").length;
    const findings = this.model.findings.map(finding => ({
      ...finding,
      status: findingStatuses[finding.id]?.status || "open",
      statusUpdatedAt: findingStatuses[finding.id]?.updatedAt || "",
    }));
    return {
      ...this.model,
      indexing: this.indexing,
      indexStage: { ...this.indexStage },
      indexError: this.indexError,
      items,
      findings,
      evidence,
      coverage: items.length ? Math.round((reviewed / items.length) * 100) : 0,
      statusCounts: {
        unreviewed: items.length - reviewed - inReview - items.filter(item => item.status === "blocked").length,
        in_review: inReview,
        reviewed,
        blocked: items.filter(item => item.status === "blocked").length,
      },
      findingStatusCounts: {
        open: findings.filter(item => item.status === "open").length,
        reviewed: findings.filter(item => item.status === "reviewed").length,
        false_positive: findings.filter(item => item.status === "false_positive").length,
        accepted_risk: findings.filter(item => item.status === "accepted_risk").length,
        suppressed: findings.filter(item => item.status === "suppressed").length,
      },
      projectConfiguration: {
        loaded: this.projectConfiguration.sources.length > 0,
        sources: this.projectConfiguration.sources,
        semanticModels: this.projectConfiguration.semanticModels.length,
        excludedPatterns: this.projectConfiguration.excludePaths.length,
        issues: this.projectConfigurationIssues,
      },
    };
  }

  async reloadProjectConfiguration(options = {}) {
    const configurations = [];
    const issues = [];
    for (const folder of vscode.workspace.workspaceFolders || []) {
      const uri = vscode.Uri.joinPath(folder.uri, PROJECT_CONFIG_FILENAME);
      try {
        const stat = await vscode.workspace.fs.stat(uri);
        if (stat.size > MAX_PROJECT_CONFIG_BYTES) {
          issues.push({ source: uri.fsPath, path: "$", message: `Configuration exceeds the ${MAX_PROJECT_CONFIG_BYTES} byte limit.`, severity: "error", line: 1, column: 1 });
          continue;
        }
        const bytes = await vscode.workspace.fs.readFile(uri);
        const parsed = parseProjectConfigurationText(Buffer.from(bytes).toString("utf8"), uri.fsPath);
        issues.push(...parsed.issues);
        if (parsed.valid) configurations.push(parsed.config);
      } catch (error) {
        if (!isFileNotFound(error)) issues.push({ source: uri.fsPath, path: "$", message: String(error.message || error), severity: "error", line: 1, column: 1 });
      }
    }
    this.projectConfigurationInitialized = true;
    this.projectConfigurationIssues = issues;
    const valid = !issues.some(item => item.severity === "error");
    if (!valid) {
      this.output.warn(`TraceGuard kept the last valid project configuration because ${issues.filter(item => item.severity === "error").length} configuration error(s) were found.`);
      this._changed.fire(this.snapshot);
      return { valid: false, changed: false, config: this.projectConfiguration, issues };
    }
    const next = mergeProjectConfigurations(configurations);
    const changed = next.fingerprint !== this.projectConfiguration.fingerprint;
    this.projectConfiguration = next;
    if (changed && options.rebuild !== false) await this._rebuildModel();
    if (changed && !options.silent) this.output.info(`Project audit semantics: ${next.semanticModels.length} custom models, ${Object.keys(next.rules).length} rule controls, ${next.excludePaths.length} exclude patterns.`);
    this._changed.fire(this.snapshot);
    return { valid: true, changed, config: next, issues };
  }

  async _ensureProjectConfiguration() {
    if (!this.projectConfigurationInitialized) await this.reloadProjectConfiguration({ rebuild: false, silent: true });
  }

  indexWorkspace(progress, token) {
    if (this.indexPromise) return this.indexPromise;
    this.indexing = true;
    this.indexError = undefined;
    this._setIndexStage("discovering", "Discovering supported source files");
    const operation = this._indexWorkspace(progress, token);
    this.indexPromise = operation.catch(error => {
      this.indexError = firstLine(error?.message || error);
      this.indexStage = { phase: "failed", message: this.indexError, processed: 0, total: 0 };
      throw error;
    }).finally(() => {
      this.indexing = false;
      this.indexPromise = undefined;
      this._changed.fire(this.snapshot);
    });
    return this.indexPromise;
  }

  async _indexWorkspace(progress, token) {
    await this._ensureProjectConfiguration();
    let discovered;
    const configuredLimit = vscode.workspace.getConfiguration("traceguard").get("maxWorkspaceFiles", DEFAULT_MAX_SOURCE_FILES);
    const maxSourceFiles = Math.min(HARD_MAX_SOURCE_FILES, Math.max(100, configuredLimit));
    try {
      discovered = await vscode.workspace.findFiles(
        SOURCE_GLOB,
        combinedExcludeGlob(EXCLUDE_GLOB, this.projectConfiguration.excludePaths),
        maxSourceFiles + 1,
        token,
      );
    } catch (error) {
      if (!token?.isCancellationRequested) throw error;
      this.indexStatus = { cancelled: true, truncated: false, skipped: 0, discovered: 0, processed: 0 };
      this._setIndexStage("cancelled", "Indexing cancelled");
      this.output.info("Audit indexing cancelled before file discovery completed; the previous index was kept.");
      return this.snapshot;
    }
    const eligible = discovered.filter(uri => !this._isExcludedUri(uri));
    const truncated = eligible.length > maxSourceFiles;
    const uris = eligible.slice(0, maxSourceFiles);
    this._setIndexStage("reading", `Reading 0 / ${uris.length} files`, 0, uris.length);
    const files = [];
    let skipped = 0;
    const skippedDetails = [];
    for (let index = 0; index < uris.length; index += 1) {
      if (token?.isCancellationRequested) {
        this.indexStatus = { cancelled: true, truncated, skipped, discovered: eligible.length, processed: files.length };
        this._setIndexStage("cancelled", `Indexing cancelled after ${files.length} files`, files.length, uris.length);
        this.output.info(`Audit indexing cancelled after ${files.length} files; the previous index was kept.`);
        return this.snapshot;
      }
      const uri = uris[index];
      if (index % 20 === 0) {
        const message = `Reading ${index + 1} / ${uris.length} files`;
        progress?.report({ message, increment: uris.length ? 2000 / uris.length : 0 });
        this._setIndexStage("reading", message, index + 1, uris.length);
      }
      try {
        const stat = await vscode.workspace.fs.stat(uri);
        if (stat.size > MAX_FILE_SIZE) {
          skipped += 1;
          skippedDetails.push({ absolutePath: uri.fsPath, relativePath: workspaceRelativePath(uri), reason: `File exceeds ${MAX_FILE_SIZE} byte limit`, size: stat.size });
          continue;
        }
        const bytes = await vscode.workspace.fs.readFile(uri);
        const text = Buffer.from(bytes).toString("utf8");
        const language = languageForPath(uri.fsPath);
        if (!language) continue;
        files.push({
          absolutePath: uri.fsPath,
          relativePath: workspaceRelativePath(uri),
          language,
          text,
          version: stableHash(text),
        });
      } catch (error) {
        skipped += 1;
        skippedDetails.push({ absolutePath: uri.fsPath, relativePath: workspaceRelativePath(uri), reason: String(error.message || error) });
        this.output.warn(`Audit index skipped ${uri.fsPath}: ${error.message}`);
      }
    }
    const previousAnalyses = this.analyses;
    let workerResult;
    this._setIndexStage("analyzing", `Analyzing ${files.length} files`, files.length, files.length);
    progress?.report({ message: `Analyzing ${files.length} files` });
    const cancellation = typeof token?.onCancellationRequested === "function"
      ? token.onCancellationRequested(() => this.dataflowWorker.cancelActive("TraceGuard workspace indexing was cancelled."))
      : undefined;
    try {
      workerResult = await this.dataflowWorker.initializeWorkspace(files, this._flowOptions());
      this.analyses = workerResult.analyses;
      this._applyWorkerResult(workerResult, true);
    } catch (error) {
      this.analyses = previousAnalyses;
      if (token?.isCancellationRequested || error?.code === "WORKER_CANCELLED") {
        this.indexStatus = { cancelled: true, truncated, skipped, discovered: eligible.length, processed: files.length };
        this._setIndexStage("cancelled", "Indexing cancelled", files.length, files.length);
        this.output.info("Audit indexing cancelled during analysis; the previous index was kept.");
        return this.snapshot;
      }
      throw error;
    } finally {
      cancellation?.dispose();
    }
    const coverageComplete = !truncated && skipped === 0;
    this.workspaceIndexBuilt = true;
    this.workspaceCoverageComplete = coverageComplete;
    this.model = {
      ...this.model,
      indexIncomplete: truncated || skipped > 0,
      indexTruncated: truncated,
      indexSkippedFiles: skipped,
      indexDiscoveredFiles: eligible.length,
      indexSkippedDetails: skippedDetails,
      indexScope: "workspace",
    };
    this.indexStatus = { cancelled: false, truncated, skipped, discovered: eligible.length, processed: files.length };
    this._setIndexStage("ready", `Indexed ${files.length} files`, files.length, files.length);
    await this._reconcileReviewStatuses(coverageComplete);
    this.output.info(`Audit index: ${this.model.files} files, ${this.model.functions} functions, ${this.model.entries.length} entry points, ${this.model.findings.length} findings, ${this.model.items.length} review targets${truncated || skipped ? ` (${truncated ? "file limit reached; " : ""}${skipped} skipped)` : ""}.`);
    this._changed.fire(this.snapshot);
    return this.snapshot;
  }

  _setIndexStage(phase, message, processed = 0, total = 0) {
    this.indexStage = { phase, message, processed, total };
    this._changed.fire(this.snapshot);
  }

  async reindexFile(uri) {
    if (!languageForPath(uri.fsPath) || !vscode.workspace.getWorkspaceFolder(uri)) return;
    await this._ensureProjectConfiguration();
    if (this._isExcludedUri(uri)) {
      await this.removeFiles([uri]);
      return;
    }
    try {
      const stat = await vscode.workspace.fs.stat(uri);
      if (stat.size > MAX_FILE_SIZE) {
        this._markWorkspaceCoverageIncomplete(1, { absolutePath: uri.fsPath, relativePath: workspaceRelativePath(uri), reason: `File exceeds ${MAX_FILE_SIZE} byte limit`, size: stat.size });
        await this.removeFiles([uri], { coverageLost: true });
        return;
      }
      const bytes = await vscode.workspace.fs.readFile(uri);
      await this._replaceAnalysis(uri, Buffer.from(bytes).toString("utf8"));
    } catch (error) {
      this._markWorkspaceCoverageIncomplete(1, { absolutePath: uri.fsPath, relativePath: workspaceRelativePath(uri), reason: String(error.message || error) });
      this.output.warn(`Audit re-index failed for ${uri.fsPath}: ${error.message}`);
    }
  }

  async reindexDocument(document) {
    if (!languageForPath(document.uri.fsPath) || !vscode.workspace.getWorkspaceFolder(document.uri)) return;
    await this._ensureProjectConfiguration();
    if (this._isExcludedUri(document.uri)) {
      await this.removeFiles([document.uri]);
      return;
    }
    try {
      const text = document.getText();
      if (Buffer.byteLength(text, "utf8") > MAX_FILE_SIZE) {
        this._markWorkspaceCoverageIncomplete(1, { absolutePath: document.uri.fsPath, relativePath: workspaceRelativePath(document.uri), reason: `Document exceeds ${MAX_FILE_SIZE} byte limit` });
        await this.removeFiles([document.uri], { coverageLost: true });
        return;
      }
      await this._replaceAnalysis(document.uri, text);
    } catch (error) {
      this.output.warn(`Live audit index failed for ${document.uri.fsPath}: ${error.message}`);
    }
  }

  async _replaceAnalysis(uri, text) {
    const result = await this.dataflowWorker.updateFile({
      absolutePath: uri.fsPath,
      relativePath: workspaceRelativePath(uri),
      language: languageForPath(uri.fsPath),
      text,
      version: stableHash(text),
    }, this._flowOptions());
    const analysis = result.analysis;
    const normalized = normalizePath(uri.fsPath);
    const previousAnalyses = this.analyses;
    const analyses = [...previousAnalyses.filter(item => normalizePath(item.absolutePath) !== normalized), analysis];
    this.analyses = analyses;
    try {
      this._applyWorkerResult(result);
    } catch (error) {
      if (this.analyses === analyses) this.analyses = previousAnalyses;
      throw error;
    }
    if (!this.workspaceIndexBuilt) this.model = { ...this.model, indexIncomplete: true, indexScope: "current-files" };
    await this._reconcileReviewStatuses(this.workspaceCoverageComplete);
    this._changed.fire(this.snapshot);
  }

  async removeFiles(uris, options = {}) {
    if (options.coverageLost) this.workspaceCoverageComplete = false;
    const removed = new Set(uris.map(uri => normalizePath(uri.fsPath)));
    const analyses = this.analyses.filter(item => !removed.has(normalizePath(item.absolutePath)));
    if (analyses.length === this.analyses.length) {
      if (options.coverageLost) this._changed.fire(this.snapshot);
      return false;
    }
    const previousAnalyses = this.analyses;
    try {
      for (const uri of uris) await this.dataflowWorker.removeFile(uri.fsPath, { reanalyze: false });
      const result = await this.dataflowWorker.reanalyzeAffectedFunctions(this._flowOptions());
      this.analyses = analyses;
      this._applyWorkerResult(result);
    } catch (error) {
      this.analyses = previousAnalyses;
      throw error;
    }
    if (!this.workspaceIndexBuilt) this.model = { ...this.model, indexIncomplete: true, indexScope: "current-files" };
    await this._reconcileReviewStatuses(this.workspaceCoverageComplete);
    this._changed.fire(this.snapshot);
    return true;
  }

  async _rebuildModel() {
    const generation = ++this.modelGeneration;
    const dataflow = await this.dataflowWorker.configure(this._flowOptions());
    if (generation !== this.modelGeneration) return false;
    if (dataflow.analyses) this.analyses = dataflow.analyses;
    this._applyWorkerResult(dataflow);
    return true;
  }

  _applyWorkerResult(dataflow, resetFindings = false) {
    const analysisModel = buildAuditModel(this.analyses);
    const indexMetadata = {
      indexIncomplete: Boolean(this.model.indexIncomplete),
      indexTruncated: Boolean(this.model.indexTruncated),
      indexSkippedFiles: this.model.indexSkippedFiles || 0,
      indexDiscoveredFiles: this.model.indexDiscoveredFiles || 0,
      indexSkippedDetails: this.model.indexSkippedDetails || [],
      indexScope: this.model.indexScope || "none",
    };
    this.model = {
      ...analysisModel,
      findings: applyDelta(resetFindings ? [] : this.model.findings, dataflow.findingDelta),
      findingPathsTruncated: Boolean(dataflow.metadata?.truncated),
      findingPathCandidates: dataflow.metadata?.totalCandidates || 0,
      incrementallyInvalidatedFiles: dataflow.metadata?.incrementallyInvalidatedFiles || 0,
      ...indexMetadata,
    };
  }

  _flowOptions(uri) {
    const configuration = vscode.workspace.getConfiguration("traceguard", uri);
    return {
      maxDepth: configuration.get("flowMaxDepth", 6),
      maxPaths: Math.min(400, Math.max(80, configuration.get("flowMaxPaths", 40) * 5)),
      astDifferential: configuration.get("astDifferentialMode", false),
      projectConfiguration: this.projectConfiguration,
    };
  }

  _isExcludedUri(uri) {
    const patterns = this.projectConfiguration.excludePaths || [];
    if (!patterns.length) return false;
    const folder = vscode.workspace.getWorkspaceFolder(uri);
    const localPath = folder ? path.relative(folder.uri.fsPath, uri.fsPath).replaceAll("\\", "/") : workspaceRelativePath(uri);
    return matchesExcludedPath(localPath, patterns) || matchesExcludedPath(workspaceRelativePath(uri), patterns);
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

  async setFindingStatus(findingId, status) {
    if (!["open", "reviewed", "false_positive", "accepted_risk", "suppressed"].includes(status)) return false;
    if (!this.model.findings.some(finding => finding.id === findingId)) return false;
    const statuses = { ...this.context.workspaceState.get("traceguard.audit.findingStatuses", {}) };
    if (status === "open") delete statuses[findingId];
    else statuses[findingId] = { status, updatedAt: new Date().toISOString() };
    await this.context.workspaceState.update("traceguard.audit.findingStatuses", statuses);
    this._changed.fire(this.snapshot);
    return true;
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
    const findingStatuses = this.context.workspaceState.get("traceguard.audit.findingStatuses", {});
    const evidence = this.context.workspaceState.get("traceguard.audit.evidence", []).map(item => {
      const { absolutePath: _absolutePath, ...portable } = item;
      return portable;
    });
    return {
      schema: "traceguard-review-session",
      version: 1,
      exportedAt: new Date().toISOString(),
      statuses,
      findingStatuses,
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
    const allowedFindingStatuses = new Set(["reviewed", "false_positive", "accepted_risk", "suppressed"]);
    const importedFindingStatuses = Object.fromEntries(Object.entries(payload.findingStatuses || {})
      .slice(0, 10000)
      .filter(([key, value]) => key.length <= 128 && allowedFindingStatuses.has(value?.status)));
    const currentStatuses = this.context.workspaceState.get("traceguard.audit.statuses", {});
    const currentFindingStatuses = this.context.workspaceState.get("traceguard.audit.findingStatuses", {});
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
    await this.context.workspaceState.update("traceguard.audit.findingStatuses", { ...currentFindingStatuses, ...importedFindingStatuses });
    await this.context.workspaceState.update("traceguard.audit.evidence", [...evidenceById.values()].slice(0, 500));
    this._changed.fire(this.snapshot);
    return { statuses: Object.keys(importedStatuses).length, findingStatuses: Object.keys(importedFindingStatuses).length, evidence: importedEvidence.length };
  }

  itemAt(uri, zeroBasedLine) {
    const target = normalizePath(uri.fsPath);
    return this.snapshot.items
      .filter(item => normalizePath(item.absolutePath) === target && zeroBasedLine + 1 >= item.line && zeroBasedLine + 1 <= item.endLine)
      .sort((a, b) => (a.endLine - a.line) - (b.endLine - b.line))[0];
  }

  signalsAt(uri, zeroBasedLine) {
    const target = normalizePath(uri.fsPath);
    const analysis = this.analyses.find(item => normalizePath(item.absolutePath) === target);
    return analysis?.signals.filter(signal => signal.line === zeroBasedLine + 1) || [];
  }

  itemsForUri(uri) {
    const target = normalizePath(uri.fsPath);
    return this.snapshot.items.filter(item => normalizePath(item.absolutePath) === target);
  }

  analysisForUri(uri) {
    const target = normalizePath(uri.fsPath);
    return this.analyses.find(item => normalizePath(item.absolutePath) === target);
  }

  async sourceSinkPathsFrom(uri, zeroBasedLine, identifier, code) {
    const configuration = vscode.workspace.getConfiguration("traceguard", uri);
    const dataflow = await this.dataflowWorker.queryPaths({
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

  async queryAudit(uri, zeroBasedLine, kind, identifier) {
    const configuration = vscode.workspace.getConfiguration("traceguard", uri);
    return this.dataflowWorker.queryAudit({
      kind,
      absolutePath: uri.fsPath,
      line: zeroBasedLine + 1,
      identifier,
      maxDepth: configuration.get("flowMaxDepth", 6),
      maxNodes: configuration.get("queryMaxNodes", 250),
    });
  }

  debugAnalysisForUri(uri, query) {
    const analysis = this.analysisForUri(uri);
    if (!analysis) return undefined;
    const findings = this.snapshot.findings.filter(item => normalizePath(item.absolutePath) === normalizePath(uri.fsPath));
    return {
      schema: "traceguard-analysis-debug",
      version: 1,
      generatedAt: new Date().toISOString(),
      analysis,
      findings,
      query,
      index: {
        scope: this.model.indexScope,
        incomplete: this.model.indexIncomplete,
        skippedFiles: this.model.indexSkippedFiles,
        generation: this.modelGeneration,
      },
    };
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

  _markWorkspaceCoverageIncomplete(skipped = 0, detail) {
    if (!this.workspaceIndexBuilt) return;
    this.workspaceCoverageComplete = false;
    this.model = {
      ...this.model,
      indexIncomplete: true,
      indexSkippedFiles: Math.max(this.model.indexSkippedFiles || 0, skipped),
      indexSkippedDetails: detail
        ? [...(this.model.indexSkippedDetails || []).filter(item => item.absolutePath !== detail.absolutePath), detail]
        : (this.model.indexSkippedDetails || []),
      indexScope: "workspace",
    };
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
    incrementallyInvalidatedFiles: 0,
    indexIncomplete: false,
    indexTruncated: false,
    indexSkippedFiles: 0,
    indexDiscoveredFiles: 0,
    indexSkippedDetails: [],
    indexScope: "none",
    signals: [],
    items: [],
    languages: {},
    languageCapabilities: {},
  };
}

function applyDelta(current, delta) {
  if (!delta) return current || [];
  const values = new Map((current || []).map(item => [item.id, item]));
  for (const id of delta.removedIds || []) values.delete(id);
  for (const item of delta.upsert || []) values.set(item.id, item);
  return [...values.values()];
}

function isFileNotFound(error) {
  return error?.code === "FileNotFound" || error?.name === "EntryNotFound (FileSystemError)" || /(?:file|entry).?not.?found/i.test(String(error?.message || ""));
}

function firstLine(value) {
  return String(value || "Unknown indexing error").split(/\r?\n/)[0].slice(0, 280);
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

module.exports = {
  AuditSession,
  DEFAULT_MAX_SOURCE_FILES,
  EXCLUDE_GLOB,
  HARD_MAX_SOURCE_FILES,
  MAX_FILE_SIZE,
  MAX_SOURCE_FILES: DEFAULT_MAX_SOURCE_FILES,
  SOURCE_GLOB,
  workspaceRelativePath,
};
