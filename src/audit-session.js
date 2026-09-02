const path = require("path");
const vscode = require("vscode");
const { buildAuditModel, shortHash } = require("./audit-analyzer");
const {
  MAX_PROJECT_CONFIG_BYTES,
  PROJECT_CONFIG_FILENAME,
  emptyProjectConfiguration,
  matchesExcludedPath,
  mergeProjectConfigurations,
  parseProjectConfigurationText,
} = require("./config/project-config");
const {
  COMPOSER_FILENAME,
  MAX_COMPOSER_BYTES,
  emptyProjectIdentity,
  parseComposerConfigurationText,
  projectIdentityFingerprint,
} = require("./config/project-identity");
const { DataflowWorkerClient } = require("./dataflow/worker-client");
const { inspectSourceFile } = require("./analysis/source-admission");
const { normalizePath, stableHash } = require("./identity");
const { languageForPath } = require("./language-support");
const { calibrateReviewTargets } = require("./review/targets");
const { reconcileFindingStatuses, reconcileReviewStatuses } = require("./review/status-store");

const SOURCE_GLOB = "**/*.{java,jsp,jspx,php,phtml,php3,php4,php5,inc,js,jsx,mjs,cjs,ts,tsx,py,cs,go}";
const EXCLUDE_GLOB = "**/{.git,.svn,node_modules,vendor,target,build,dist,coverage,.gradle,.mvn,.venv,venv,__pycache__,bin,obj,storage,cache,tmp,temp}/**";
const HARD_MAX_SOURCE_BYTES = 2 * 1024 * 1024;
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
    this.activeIndexDirtyQueue = undefined;
    this.indexStage = { phase: "idle", message: "Review queue not built", processed: 0, total: 0 };
    this.indexError = undefined;
    this.workspaceIndexBuilt = false;
    this.workspaceCoverageComplete = false;
    this.indexStatus = { cancelled: false, truncated: false, skipped: 0, discovered: 0, processed: 0 };
    this.dataflowWorker = new DataflowWorkerClient({ fileLoader: metadata => this._loadWorkerReplayFile(metadata) });
    this.modelGeneration = 0;
    this.projectConfiguration = emptyProjectConfiguration();
    this.projectConfigurationsByRoot = [];
    this.temporaryModelConfigurationsByRoot = new Map();
    this.projectConfigurationIssues = [];
    this.projectConfigurationInitialized = false;
    this.projectIdentitiesByRoot = [];
    this.projectIdentityIssues = [];
    this.performanceReport = { incrementalSamplesMs: [] };
    this.languageAssetCacheRoot = context.globalStorageUri?.fsPath
      ? path.join(context.globalStorageUri.fsPath, "language-assets")
      : undefined;
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
    const indexedFiles = Number(this.model.files) || this.analyses.length;
    const skippedFiles = Number(this.model.indexSkippedFiles) || 0;
    const discoveredFiles = Math.max(Number(this.model.indexDiscoveredFiles) || 0, indexedFiles + skippedFiles);
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
      analysisCoverage: {
        indexed: indexedFiles,
        discovered: discoveredFiles,
        skipped: skippedFiles,
        complete: !this.model.indexIncomplete,
        partialPaths: Number(this.model.findingPartialPaths) || 0,
      },
      manualReviewCoverage: { reviewed, total: items.length },
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
        temporarySemanticModels: this._temporarySemanticModelCount(),
        excludedPatterns: this.projectConfiguration.excludePaths.length,
        issues: this.projectConfigurationIssues,
      },
      performance: { ...this.performanceReport, incrementalSamplesMs: undefined },
    };
  }

  async reloadProjectConfiguration(options = {}) {
    const configurations = [];
    const configurationsByRoot = [];
    const issues = [];
    const previousByRoot = new Map(this.projectConfigurationsByRoot.map(item => [normalizePath(item.root), item.configuration]));
    let frozenRoots = 0;
    for (const folder of vscode.workspace.workspaceFolders || []) {
      const uri = vscode.Uri.joinPath(folder.uri, PROJECT_CONFIG_FILENAME);
      const workspaceRoot = folder.uri.fsPath;
      const previous = previousByRoot.get(normalizePath(workspaceRoot));
      let configuration = previous || emptyProjectConfiguration();
      let rootValid = true;
      try {
        const stat = await vscode.workspace.fs.stat(uri);
        if (stat.size > MAX_PROJECT_CONFIG_BYTES) {
          issues.push({ source: uri.fsPath, workspaceRoot, path: "$", message: `Configuration exceeds the ${MAX_PROJECT_CONFIG_BYTES} byte limit.`, severity: "error", line: 1, column: 1 });
          rootValid = false;
        } else {
          const bytes = await vscode.workspace.fs.readFile(uri);
          const parsed = parseProjectConfigurationText(Buffer.from(bytes).toString("utf8"), uri.fsPath);
          issues.push(...parsed.issues.map(item => ({ ...item, workspaceRoot })));
          if (parsed.valid) configuration = parsed.config;
          else rootValid = false;
        }
      } catch (error) {
        if (isFileNotFound(error)) configuration = emptyProjectConfiguration();
        else {
          rootValid = false;
          issues.push({ source: uri.fsPath, workspaceRoot, path: "$", message: String(error.message || error), severity: "error", line: 1, column: 1 });
        }
      }
      if (!rootValid) frozenRoots += 1;
      configurations.push(configuration);
      configurationsByRoot.push({ root: workspaceRoot, configuration });
    }
    this.projectConfigurationInitialized = true;
    this.projectConfigurationIssues = issues;
    const valid = !issues.some(item => item.severity === "error");
    const next = mergeProjectConfigurations(configurations);
    const scopedFingerprint = stableHash(JSON.stringify(configurationsByRoot.map(item => [normalizePath(item.root), item.configuration.fingerprint])));
    const previousScopedFingerprint = stableHash(JSON.stringify(this.projectConfigurationsByRoot.map(item => [normalizePath(item.root), item.configuration.fingerprint])));
    const changed = next.fingerprint !== this.projectConfiguration.fingerprint || scopedFingerprint !== previousScopedFingerprint;
    this.projectConfiguration = next;
    this.projectConfigurationsByRoot = configurationsByRoot;
    if (changed && options.rebuild !== false) await this._rebuildModel();
    if (frozenRoots) this.output.warn(`TraceGuard kept the last valid project configuration for ${frozenRoots} workspace root(s); valid roots were updated independently.`);
    if (changed && !options.silent) this.output.info(`Project audit semantics: ${next.semanticModels.length} custom models, ${Object.keys(next.rules).length} rule controls, ${next.excludePaths.length} exclude patterns.`);
    this._changed.fire(this.snapshot);
    return { valid, changed, config: next, issues };
  }

  async _ensureProjectConfiguration() {
    if (!this.projectConfigurationInitialized) await this.reloadProjectConfiguration({ rebuild: false, silent: true });
  }

  async addTemporarySemanticModel(uri, role, model) {
    await this._ensureProjectConfiguration();
    const folder = vscode.workspace.getWorkspaceFolder(uri);
    if (!folder) throw new Error("The selected code is not inside an open workspace folder.");
    const collection = role === "source" ? "sources" : role === "sink" ? "sinks" : role === "sanitizer" ? "sanitizers" : undefined;
    if (!collection) throw new Error(`Unsupported temporary semantic model role: ${role}`);
    const parsed = parseProjectConfigurationText(JSON.stringify({ version: 1, [collection]: [model] }), "TraceGuard temporary session model");
    if (!parsed.valid || !parsed.config.semanticModels.length) {
      throw new Error(parsed.issues?.find(issue => issue.severity === "error")?.message || "The temporary semantic model is invalid.");
    }
    const root = normalizePath(folder.uri.fsPath);
    const records = this.temporaryModelConfigurationsByRoot.get(root) || new Map();
    const key = `${role}:${model.language}:${model.function}`;
    const previous = records.get(key);
    if (previous && previous.semanticFingerprint === parsed.config.semanticFingerprint) return { changed: false, count: this._temporarySemanticModelCount() };
    records.set(key, parsed.config);
    this.temporaryModelConfigurationsByRoot.set(root, records);
    try {
      if (this.analyses.length) await this._rebuildModel();
    } catch (error) {
      if (previous) records.set(key, previous);
      else records.delete(key);
      if (!records.size) this.temporaryModelConfigurationsByRoot.delete(root);
      throw error;
    }
    this._changed.fire(this.snapshot);
    return { changed: true, count: this._temporarySemanticModelCount() };
  }

  async clearTemporarySemanticModels() {
    if (!this.temporaryModelConfigurationsByRoot.size) return false;
    const previous = new Map([...this.temporaryModelConfigurationsByRoot].map(([root, records]) => [root, new Map(records)]));
    this.temporaryModelConfigurationsByRoot.clear();
    try {
      if (this.analyses.length) await this._rebuildModel();
    } catch (error) {
      this.temporaryModelConfigurationsByRoot = previous;
      throw error;
    }
    this._changed.fire(this.snapshot);
    return true;
  }

  _temporarySemanticModelCount() {
    return [...this.temporaryModelConfigurationsByRoot.values()].reduce((count, records) => count + records.size, 0);
  }

  _effectiveProjectConfigurations() {
    const roots = new Set([
      ...this.projectConfigurationsByRoot.map(item => normalizePath(item.root)),
      ...this.temporaryModelConfigurationsByRoot.keys(),
    ]);
    const byRoot = [...roots].map(root => {
      const base = this.projectConfigurationsByRoot.find(item => normalizePath(item.root) === root)?.configuration ||
        (this.projectConfigurationsByRoot.length ? emptyProjectConfiguration() : this.projectConfiguration);
      const temporary = [...(this.temporaryModelConfigurationsByRoot.get(root)?.values() || [])];
      return { root, configuration: mergeProjectConfigurations([base, ...temporary]) };
    });
    return {
      projectConfiguration: mergeProjectConfigurations(byRoot.length ? byRoot.map(item => item.configuration) : [this.projectConfiguration]),
      projectConfigurationsByRoot: byRoot,
    };
  }

  async reloadProjectIdentities(options = {}) {
    const previousByRoot = new Map(this.projectIdentitiesByRoot.map(item => [normalizePath(item.root), item.identity]));
    const identitiesByRoot = [];
    const issues = [];
    let frozenRoots = 0;
    for (const folder of vscode.workspace.workspaceFolders || []) {
      const workspaceRoot = folder.uri.fsPath;
      const uri = vscode.Uri.joinPath(folder.uri, COMPOSER_FILENAME);
      let identity = previousByRoot.get(normalizePath(workspaceRoot)) || emptyProjectIdentity(workspaceRoot);
      let rootValid = true;
      try {
        const stat = await vscode.workspace.fs.stat(uri);
        if (stat.size > MAX_COMPOSER_BYTES) {
          issues.push({ source: uri.fsPath, workspaceRoot, path: "$", message: `composer.json exceeds the ${MAX_COMPOSER_BYTES} byte limit.`, severity: "error", line: 1, column: 1 });
          rootValid = false;
        } else {
          const bytes = await vscode.workspace.fs.readFile(uri);
          const parsed = parseComposerConfigurationText(Buffer.from(bytes).toString("utf8"), workspaceRoot, uri.fsPath);
          issues.push(...parsed.issues.map(item => ({ ...item, workspaceRoot })));
          if (parsed.valid) identity = parsed.identity;
          else rootValid = false;
        }
      } catch (error) {
        if (isFileNotFound(error)) identity = emptyProjectIdentity(workspaceRoot);
        else {
          rootValid = false;
          issues.push({ source: uri.fsPath, workspaceRoot, path: "$", message: String(error.message || error), severity: "error", line: 1, column: 1 });
        }
      }
      if (!rootValid) frozenRoots += 1;
      identitiesByRoot.push({ root: workspaceRoot, identity });
    }
    const changed = projectIdentityFingerprint(identitiesByRoot) !== projectIdentityFingerprint(this.projectIdentitiesByRoot);
    this.projectIdentitiesByRoot = identitiesByRoot;
    this.projectIdentityIssues = issues;
    if (frozenRoots && !options.silent) this.output.warn(`TraceGuard kept the last valid Composer identity for ${frozenRoots} workspace root(s).`);
    this._changed.fire(this.snapshot);
    return { valid: !issues.some(item => item.severity === "error"), changed, identitiesByRoot, issues };
  }

  indexWorkspace(progress, token) {
    if (this.indexPromise) return this.indexPromise;
    this.indexing = true;
    const dirtyQueue = new Map();
    this.activeIndexDirtyQueue = dirtyQueue;
    this.indexError = undefined;
    this._setIndexStage("discovering", "Discovering supported source files");
    const operation = this._indexWorkspace(progress, token, dirtyQueue);
    this.indexPromise = operation.catch(error => {
      this.indexError = firstLine(error?.message || error);
      this.indexStage = { phase: "failed", message: this.indexError, processed: 0, total: 0 };
      throw error;
    }).finally(() => {
      this.indexing = false;
      if (this.activeIndexDirtyQueue === dirtyQueue) this.activeIndexDirtyQueue = undefined;
      this.indexPromise = undefined;
      this._changed.fire(this.snapshot);
    });
    return this.indexPromise;
  }

  async _indexWorkspace(progress, token, dirtyQueue) {
    const initializationStartedAt = performance.now();
    await this._ensureProjectConfiguration();
    await this.reloadProjectIdentities({ silent: true });
    let discovered;
    const configuredLimit = vscode.workspace.getConfiguration("traceguard").get("maxWorkspaceFiles", DEFAULT_MAX_SOURCE_FILES);
    const maxSourceFiles = Math.min(HARD_MAX_SOURCE_FILES, Math.max(100, configuredLimit));
    try {
      discovered = await vscode.workspace.findFiles(
        SOURCE_GLOB,
        EXCLUDE_GLOB,
        undefined,
        token,
      );
    } catch (error) {
      if (!token?.isCancellationRequested) throw error;
      this.indexStatus = { cancelled: true, truncated: false, skipped: 0, discovered: 0, processed: 0 };
      this._setIndexStage("cancelled", "Indexing cancelled");
      this.output.info("Audit indexing cancelled before file discovery completed; the previous index was kept.");
      return this.snapshot;
    }
    const configuredEligible = discovered.filter(uri => !this._isExcludedUri(uri));
    const eligible = configuredEligible;
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
      const maxSourceBytes = this._maxSourceBytes(uri);
      if (index % 20 === 0) {
        const message = `Reading ${index + 1} / ${uris.length} files`;
        progress?.report({ message, increment: uris.length ? 2000 / uris.length : 0 });
        this._setIndexStage("reading", message, index + 1, uris.length);
      }
      try {
        const stat = await vscode.workspace.fs.stat(uri);
        if (stat.size > maxSourceBytes) {
          skipped += 1;
          skippedDetails.push({
            absolutePath: uri.fsPath,
            relativePath: workspaceRelativePath(uri),
            reason: `Source exceeds the configured ${Math.round(maxSourceBytes / 1024)} KiB per-file parsing budget`,
            code: "source-size-budget",
            size: stat.size,
            limit: maxSourceBytes,
          });
          continue;
        }
        const openDocument = (vscode.workspace.textDocuments || []).find(document => normalizePath(document.uri.fsPath) === normalizePath(uri.fsPath));
        const text = openDocument?.isDirty
          ? openDocument.getText()
          : Buffer.from(await vscode.workspace.fs.readFile(uri)).toString("utf8");
        const language = languageForPath(uri.fsPath);
        if (!language) continue;
        const file = {
          absolutePath: uri.fsPath,
          relativePath: workspaceRelativePath(uri),
          language,
          text,
          version: stableHash(text),
          unsaved: Boolean(openDocument?.isDirty),
        };
        const admission = inspectSourceFile(file, { maxSourceBytes });
        if (!admission.accepted) {
          skipped += 1;
          skippedDetails.push(admission.detail);
          this.output.warn(`Audit index skipped ${uri.fsPath}: ${admission.detail.reason}`);
          continue;
        }
        files.push(file);
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
      const timeoutSeconds = vscode.workspace.getConfiguration("traceguard").get("indexTimeoutSeconds", 300);
      this.dataflowWorker.setIndexTimeoutMs?.(timeoutSeconds === 0 ? 0 : Math.max(1, timeoutSeconds) * 1000);
      workerResult = await this.dataflowWorker.initializeWorkspace(files, this._flowOptions());
      for (const detail of workerResult.metadata?.sourceAdmissionSkippedDetails || []) {
        if (skippedDetails.some(item => normalizePath(item.absolutePath) === normalizePath(detail.absolutePath))) continue;
        skipped += 1;
        skippedDetails.push(detail);
      }
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
    let coverageComplete = !truncated && skipped === 0;
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
    this._queueOpenDirtyDocuments(dirtyQueue);
    const replay = await this._replayIndexDirtyQueue(dirtyQueue);
    if (replay.failed) {
      skipped += replay.failed;
      coverageComplete = false;
      this.workspaceCoverageComplete = false;
      this.model = {
        ...this.model,
        indexIncomplete: true,
        indexSkippedFiles: skipped,
        indexSkippedDetails: [...(this.model.indexSkippedDetails || []), ...replay.skippedDetails],
      };
    }
    this.indexStatus = { cancelled: false, truncated, skipped, discovered: eligible.length, processed: files.length };
    this.performanceReport = {
      ...this.performanceReport,
      initializationMs: roundMetric(performance.now() - initializationStartedAt),
      extensionHostRssBytes: process.memoryUsage().rss,
      replayedDirtyUpdates: replay.applied,
      dirtyUpdateReplayMs: replay.durationMs,
    };
    this._setIndexStage("ready", `Indexed ${files.length} files${replay.applied ? `; replayed ${replay.applied} live update(s)` : ""}`, files.length, files.length);
    await this._reconcileReviewStatuses(coverageComplete);
    this.output.info(`Audit index: ${this.model.files} files, ${this.model.entries.length} entry points, ${this.model.findings.length} findings, ${this.model.items.length} review targets${truncated || skipped ? ` (${truncated ? "file limit reached; " : ""}${skipped} skipped)` : ""}.`);
    this._changed.fire(this.snapshot);
    return this.snapshot;
  }

  _setIndexStage(phase, message, processed = 0, total = 0) {
    this.indexStage = { phase, message, processed, total };
    this._changed.fire(this.snapshot);
  }

  async reindexFile(uri, options = {}) {
    if (!languageForPath(uri.fsPath) || !vscode.workspace.getWorkspaceFolder(uri)) return;
    if (!options.bypassIndexQueue && this._queueIndexChange({ kind: "file", uri })) return;
    await this._ensureProjectConfiguration();
    if (this._isExcludedUri(uri)) {
      await this.removeFiles([uri]);
      return;
    }
    try {
      const stat = await vscode.workspace.fs.stat(uri);
      const maxSourceBytes = this._maxSourceBytes(uri);
      if (stat.size > maxSourceBytes) {
        this._markWorkspaceCoverageIncomplete(1, {
          absolutePath: uri.fsPath,
          relativePath: workspaceRelativePath(uri),
          reason: `Source exceeds the configured ${Math.round(maxSourceBytes / 1024)} KiB per-file parsing budget`,
          code: "source-size-budget",
          size: stat.size,
          limit: maxSourceBytes,
        });
        await this.removeFiles([uri], { coverageLost: true });
        return;
      }
      const bytes = await vscode.workspace.fs.readFile(uri);
      await this._replaceAnalysis(uri, Buffer.from(bytes).toString("utf8"), { unsaved: false });
    } catch (error) {
      this._markWorkspaceCoverageIncomplete(1, { absolutePath: uri.fsPath, relativePath: workspaceRelativePath(uri), reason: String(error.message || error) });
      this.output.warn(`Audit re-index failed for ${uri.fsPath}: ${error.message}`);
    }
  }

  async reindexDocument(document, options = {}) {
    if (!languageForPath(document.uri.fsPath) || !vscode.workspace.getWorkspaceFolder(document.uri)) return;
    const text = document.getText();
    const unsaved = Boolean(document.isDirty);
    if (!options.bypassIndexQueue && this._queueIndexChange({ kind: "document", uri: document.uri, text, unsaved })) return;
    await this._ensureProjectConfiguration();
    if (this._isExcludedUri(document.uri)) {
      await this.removeFiles([document.uri]);
      return;
    }
    try {
      const maxSourceBytes = this._maxSourceBytes(document.uri);
      if (Buffer.byteLength(text, "utf8") > maxSourceBytes) {
        this._markWorkspaceCoverageIncomplete(1, {
          absolutePath: document.uri.fsPath,
          relativePath: workspaceRelativePath(document.uri),
          reason: `Document exceeds the configured ${Math.round(maxSourceBytes / 1024)} KiB per-file parsing budget`,
          code: "source-size-budget",
          limit: maxSourceBytes,
        });
        await this.removeFiles([document.uri], { coverageLost: true });
        return;
      }
      await this._replaceAnalysis(document.uri, text, { unsaved });
    } catch (error) {
      this.output.warn(`Live audit index failed for ${document.uri.fsPath}: ${error.message}`);
    }
  }

  async _replaceAnalysis(uri, text, options = {}) {
    const startedAt = performance.now();
    const result = await this.dataflowWorker.updateFile({
      absolutePath: uri.fsPath,
      relativePath: workspaceRelativePath(uri),
      language: languageForPath(uri.fsPath),
      text,
      version: stableHash(text),
      unsaved: Boolean(options.unsaved),
    }, this._flowOptions(uri));
    const analysis = result.analysis;
    const normalized = normalizePath(uri.fsPath);
    const previousAnalyses = this.analyses;
    const analyses = [
      ...previousAnalyses.filter(item => normalizePath(item.absolutePath) !== normalized),
      ...(analysis ? [analysis] : []),
    ];
    this.analyses = analyses;
    try {
      this._applyWorkerResult(result);
    } catch (error) {
      if (this.analyses === analyses) this.analyses = previousAnalyses;
      throw error;
    }
    if (!this.workspaceIndexBuilt) this.model = { ...this.model, indexIncomplete: true, indexScope: "current-files" };
    if (result.skippedFile) {
      this._markWorkspaceCoverageIncomplete(1, result.skippedFile);
      this.output.warn(`Live audit index skipped ${uri.fsPath}: ${result.skippedFile.reason}`);
    }
    await this._reconcileReviewStatuses(this.workspaceCoverageComplete);
    this._recordIncrementalTiming(performance.now() - startedAt);
    this._changed.fire(this.snapshot);
  }

  async removeFiles(uris, options = {}) {
    if (!options.bypassIndexQueue && this.activeIndexDirtyQueue) {
      for (const uri of uris) this._queueIndexChange({ kind: "delete", uri });
      return true;
    }
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

  _queueIndexChange(change) {
    if (!this.activeIndexDirtyQueue) return false;
    this.activeIndexDirtyQueue.set(normalizePath(change.uri.fsPath), change);
    return true;
  }

  _queueOpenDirtyDocuments(dirtyQueue) {
    for (const document of vscode.workspace.textDocuments || []) {
      if (!document.isDirty || !languageForPath(document.uri.fsPath) || !vscode.workspace.getWorkspaceFolder(document.uri)) continue;
      dirtyQueue.set(normalizePath(document.uri.fsPath), { kind: "document", uri: document.uri, text: document.getText() });
    }
  }

  async _replayIndexDirtyQueue(dirtyQueue) {
    const startedAt = performance.now();
    let applied = 0;
    const skippedDetails = [];
    while (dirtyQueue.size) {
      const batch = [...dirtyQueue.values()];
      dirtyQueue.clear();
      for (const change of batch) {
        try {
          if (change.kind === "delete") await this.removeFiles([change.uri], { bypassIndexQueue: true });
          else if (change.kind === "document") {
            await this.reindexDocument({ uri: change.uri, getText: () => change.text, isDirty: change.unsaved }, { bypassIndexQueue: true });
          } else await this.reindexFile(change.uri, { bypassIndexQueue: true });
          applied += 1;
        } catch (error) {
          skippedDetails.push({
            absolutePath: change.uri.fsPath,
            relativePath: workspaceRelativePath(change.uri),
            reason: `Dirty update replay failed: ${String(error.message || error)}`,
          });
          this.output.warn(`Audit dirty-update replay failed for ${change.uri.fsPath}: ${error.message}`);
        }
      }
    }
    return { applied, failed: skippedDetails.length, skippedDetails, durationMs: roundMetric(performance.now() - startedAt) };
  }

  async _loadWorkerReplayFile(metadata) {
    const openDocument = (vscode.workspace.textDocuments || []).find(document =>
      normalizePath(document.uri.fsPath) === normalizePath(metadata.absolutePath));
    if (openDocument?.isDirty) {
      const text = openDocument.getText();
      return { ...metadata, text, version: stableHash(text), unsaved: true };
    }
    const uri = vscode.Uri.file ? vscode.Uri.file(metadata.absolutePath) : { fsPath: metadata.absolutePath };
    try {
      const bytes = await vscode.workspace.fs.readFile(uri);
      const text = Buffer.from(bytes).toString("utf8");
      return { ...metadata, text, version: stableHash(text), unsaved: false };
    } catch (error) {
      if (isFileNotFound(error)) return undefined;
      throw error;
    }
  }

  _applyWorkerResult(dataflow, resetFindings = false) {
    this._recordWorkerMetrics(dataflow.metadata);
    const analysisModel = dataflow.auditModel || buildAuditModel(this.analyses);
    const findings = applyDelta(resetFindings ? [] : this.model.findings, dataflow.findingDelta);
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
      items: calibrateReviewTargets(analysisModel.items, findings),
      findings,
      findingPathsTruncated: Boolean(dataflow.metadata?.truncated),
      findingPathCandidates: dataflow.metadata?.totalCandidates || 0,
      findingPartialPaths: dataflow.metadata?.partialPaths || 0,
      findingPathTruncationReasons: dataflow.metadata?.truncationReasons || [],
      incrementallyInvalidatedFiles: dataflow.metadata?.incrementallyInvalidatedFiles || 0,
      ...indexMetadata,
    };
  }

  _recordWorkerMetrics(metadata = {}) {
    if (!metadata || typeof metadata !== "object") return;
    this.performanceReport = {
      ...this.performanceReport,
      workerRequestMs: metadata.workerRequestMs ?? this.performanceReport.workerRequestMs,
      workerRssBytes: metadata.workerRssBytes ?? this.performanceReport.workerRssBytes,
      workerPeakRssBytes: metadata.workerPeakRssBytes ?? this.performanceReport.workerPeakRssBytes,
      workerHeapUsedBytes: metadata.workerHeapUsedBytes ?? this.performanceReport.workerHeapUsedBytes,
      invalidatedFiles: metadata.incrementallyInvalidatedFiles ?? this.performanceReport.invalidatedFiles,
      invalidatedFunctions: metadata.incrementallyInvalidatedFunctions ?? this.performanceReport.invalidatedFunctions,
      frontendMs: metadata.frontendMs ?? this.performanceReport.frontendMs,
      entryBindingMs: metadata.entryBindingMs ?? this.performanceReport.entryBindingMs,
      callGraphMs: metadata.callGraphMs ?? this.performanceReport.callGraphMs,
      dataflowMs: metadata.dataflowMs ?? this.performanceReport.dataflowMs,
      flowRankingMs: metadata.flowRankingMs ?? this.performanceReport.flowRankingMs,
      flowExplorationMs: metadata.flowExplorationMs ?? this.performanceReport.flowExplorationMs,
      exploredFlowStates: metadata.exploredFlowStates ?? this.performanceReport.exploredFlowStates,
      visitedFlowEvents: metadata.visitedFlowEvents ?? this.performanceReport.visitedFlowEvents,
      findingPathDiffMs: metadata.findingPathDiffMs ?? this.performanceReport.findingPathDiffMs,
      workerReplayMs: metadata.workerReplayMs ?? this.performanceReport.workerReplayMs,
      workerReplayFiles: metadata.workerReplayFiles ?? this.performanceReport.workerReplayFiles,
      workerReplayRssBytes: metadata.workerReplayRssBytes ?? this.performanceReport.workerReplayRssBytes,
      workerReplayPeakRssBytes: metadata.workerReplayPeakRssBytes ?? this.performanceReport.workerReplayPeakRssBytes,
    };
  }

  _recordIncrementalTiming(durationMs) {
    const samples = [...(this.performanceReport.incrementalSamplesMs || []), roundMetric(durationMs)].slice(-100);
    const sorted = [...samples].sort((left, right) => left - right);
    const p95 = sorted[Math.max(0, Math.ceil(sorted.length * 0.95) - 1)];
    this.performanceReport = {
      ...this.performanceReport,
      incrementalSamplesMs: samples,
      lastIncrementalMs: roundMetric(durationMs),
      incrementalP95Ms: p95,
      extensionHostRssBytes: process.memoryUsage().rss,
    };
  }

  _flowOptions(uri) {
    const configuration = vscode.workspace.getConfiguration("traceguard", uri);
    const effective = this._effectiveProjectConfigurations();
    const settingsFor = resource => {
      const scoped = vscode.workspace.getConfiguration("traceguard", resource);
      return {
        maxDepth: scoped.get("flowMaxDepth", 6),
        maxHigherOrderDepth: scoped.get("flowMaxHigherOrderDepth", 8),
        maxAsyncDepth: scoped.get("flowMaxAsyncDepth", 8),
        maxTraceSteps: scoped.get("flowMaxSteps", 30),
        maxAnalysisMs: scoped.get("flowTimeoutMs", 3000),
        maxPaths: Math.min(400, Math.max(80, scoped.get("flowMaxPaths", 40) * 5)),
        maxSourceBytes: this._maxSourceBytes(resource),
      };
    };
    const selectedSettings = settingsFor(uri);
    return {
      ...selectedSettings,
      compactResult: true,
      astDifferential: configuration.get("astDifferentialMode", false),
      analysisSettingsByRoot: (vscode.workspace.workspaceFolders || []).map(folder => ({
        root: folder.uri.fsPath,
        settings: settingsFor(folder.uri),
      })),
      projectConfiguration: effective.projectConfiguration,
      projectConfigurationsByRoot: effective.projectConfigurationsByRoot,
      projectIdentitiesByRoot: this.projectIdentitiesByRoot,
      languageAssets: {
        assetCacheRoot: this.languageAssetCacheRoot,
        assetBaseUrl: configuration.get("languageAssetBaseUrl", "") || undefined,
        allowAssetDownloads: configuration.get("languageAssetDownloads", true),
      },
    };
  }

  _maxSourceBytes(uri) {
    const configuredKiB = vscode.workspace.getConfiguration("traceguard", uri).get("maxSourceFileKiB", 256);
    return Math.min(HARD_MAX_SOURCE_BYTES, Math.max(64 * 1024, Number(configuredKiB || 256) * 1024));
  }

  _isExcludedUri(uri) {
    const patterns = this._projectConfigurationForUri(uri).excludePaths || [];
    if (!patterns.length) return false;
    const folder = vscode.workspace.getWorkspaceFolder(uri);
    const localPath = folder ? path.relative(folder.uri.fsPath, uri.fsPath).replaceAll("\\", "/") : workspaceRelativePath(uri);
    return matchesExcludedPath(localPath, patterns) || matchesExcludedPath(workspaceRelativePath(uri), patterns);
  }

  _projectConfigurationForUri(uri) {
    const folder = vscode.workspace.getWorkspaceFolder(uri);
    if (!folder) return this.projectConfiguration;
    const root = normalizePath(folder.uri.fsPath);
    return this.projectConfigurationsByRoot.find(item => normalizePath(item.root) === root)?.configuration || emptyProjectConfiguration();
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

  async migrateEvidencePaths(renames) {
    const mappings = (renames || []).map(item => ({ oldPath: item.oldUri.fsPath, newPath: item.newUri.fsPath }));
    if (!mappings.length) return 0;
    const evidence = this.context.workspaceState.get("traceguard.audit.evidence", []);
    let migrated = 0;
    const next = evidence.map(item => {
      if (!item.absolutePath) return item;
      const absolutePath = remapRenamedPath(item.absolutePath, mappings);
      if (!absolutePath) return item;
      migrated += 1;
      return {
        ...item,
        absolutePath,
        relativePath: workspaceRelativePath({ fsPath: absolutePath }),
      };
    });
    if (!migrated) return 0;
    await this.context.workspaceState.update("traceguard.audit.evidence", next);
    this._changed.fire(this.snapshot);
    return migrated;
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

  async semanticCallAt(uri, zeroBasedLine, zeroBasedCharacter) {
    const analysis = await this.dataflowWorker.getAnalysis(uri.fsPath);
    if (!analysis?.ir?.functions) return undefined;
    const line = zeroBasedLine + 1;
    const column = zeroBasedCharacter + 1;
    const calls = analysis.ir.functions.flatMap(fn => (fn.operations || [])
      .filter(item => item.call && locationContainsPosition(item.location, line, column))
      .map(item => ({
        functionName: item.call.function,
        receiver: item.call.receiver,
        arguments: item.call.arguments || [],
        symbol: item.call.symbol,
        semanticVerification: item.metadata?.semanticVerification,
        location: item.location,
      })));
    return calls.sort((left, right) => locationSpan(left.location) - locationSpan(right.location))[0];
  }

  async sourceSinkPathsFrom(uri, zeroBasedLine, identifier, code) {
    const configuration = vscode.workspace.getConfiguration("traceguard", uri);
    const dataflow = await this.dataflowWorker.queryPaths({
      absolutePath: uri.fsPath,
      line: zeroBasedLine + 1,
      identifier,
      code,
      maxDepth: configuration.get("flowMaxDepth", 6),
      maxHigherOrderDepth: configuration.get("flowMaxHigherOrderDepth", 8),
      maxAsyncDepth: configuration.get("flowMaxAsyncDepth", 8),
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
      indexIncomplete: Boolean(this.model.indexIncomplete),
      indexScope: this.model.indexScope,
      indexSkippedFiles: this.model.indexSkippedFiles || 0,
    });
  }

  async debugAnalysisForUri(uri, query) {
    const analysis = await this.dataflowWorker.getAnalysis(uri.fsPath);
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
    const currentFindingStatuses = this.context.workspaceState.get("traceguard.audit.findingStatuses", {});
    const findingResult = reconcileFindingStatuses(currentFindingStatuses, this.model.findings, { complete });
    if (result.changed) await this.context.workspaceState.update("traceguard.audit.statuses", result.statuses);
    if (findingResult.changed) await this.context.workspaceState.update("traceguard.audit.findingStatuses", findingResult.statuses);
    if (result.migrated || result.removed) {
      this.output.info(`Review state: ${result.migrated} migrated, ${result.removed} expired orphan record(s).`);
    }
    if (findingResult.removed) this.output.info(`Finding state: ${findingResult.removed} expired orphan record(s).`);
    return { ...result, findingStatuses: findingResult };
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
    findingPartialPaths: 0,
    findingPathTruncationReasons: [],
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

function locationContainsPosition(location, line, column) {
  if (!location) return false;
  if (line < location.line || line > (location.endLine || location.line)) return false;
  if (line === location.line && Number.isFinite(location.startColumn) && column < location.startColumn) return false;
  if (line === (location.endLine || location.line) && Number.isFinite(location.endColumn) && column > location.endColumn) return false;
  return true;
}

function locationSpan(location = {}) {
  if (Number.isFinite(location.startOffset) && Number.isFinite(location.endOffset)) return location.endOffset - location.startOffset;
  return ((location.endLine || location.line || 1) - (location.line || 1)) * 10000 +
    Math.max(0, (location.endColumn || 0) - (location.startColumn || 0));
}

function firstLine(value) {
  return String(value || "Unknown indexing error").split(/\r?\n/)[0].slice(0, 280);
}

function roundMetric(value) {
  return Math.round(Math.max(0, Number(value) || 0) * 100) / 100;
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

function remapRenamedPath(absolutePath, mappings) {
  const current = path.resolve(absolutePath);
  const normalizedCurrent = normalizePath(current);
  for (const mapping of mappings) {
    const oldPath = path.resolve(mapping.oldPath);
    const normalizedOld = normalizePath(oldPath);
    if (normalizedCurrent !== normalizedOld && !normalizedCurrent.startsWith(`${normalizedOld}/`)) continue;
    const suffix = path.relative(oldPath, current);
    return suffix ? path.resolve(mapping.newPath, suffix) : path.resolve(mapping.newPath);
  }
  return undefined;
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
  MAX_FILE_SIZE: HARD_MAX_SOURCE_BYTES,
  MAX_SOURCE_FILES: DEFAULT_MAX_SOURCE_FILES,
  SOURCE_GLOB,
  workspaceRelativePath,
};
