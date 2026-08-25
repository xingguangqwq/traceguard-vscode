"use strict";

const { analyzeTextAsync } = require("../audit-analyzer");
const { normalizePath, stableHash } = require("../identity");
const { buildFunctionIndex, resolveCandidates } = require("../dataflow/call-resolver");
const { summarizeFileIR } = require("../dataflow/function-summary");
const { functionsFromAnalyses } = require("../dataflow/ir-adapter");
const { runDataflowAnalysis } = require("../dataflow/pipeline");
const { evaluateFlowPaths } = require("../rules/rule-engine");
const { runAuditQuery } = require("../query/audit-query-engine");
const { runtime } = require("../frontends/tree-sitter-runtime");
const { TypeScriptProject, createCompilerModel } = require("../frontends/typescript-compiler");
const { IncrementalAnalysisCache, fileKey } = require("./incremental-cache");
const { analysisContentDigest } = require("./content-digest");
const { configurationForAbsolutePath, scopedConfigurationFingerprint } = require("../config/configuration-scope");
const { workspaceRootForAbsolutePath } = require("../config/configuration-scope");
const { composerPathsForType, projectIdentityFingerprint, projectIdentityForAbsolutePath } = require("../config/project-identity");
const { frameworkParameterRoles } = require("../frontends/framework-entries");

class WorkspaceAnalysisEngine {
  constructor() {
    this.files = new Map();
    this.cache = new IncrementalAnalysisCache();
    this.options = {};
    this.pendingAffectedFiles = new Set();
    this.pendingAffectedFunctionIds = new Set();
    this.dataflow = emptyDataflow();
    this.generation = 0;
    this.typescriptProject = new TypeScriptProject();
    this.entryBindingFingerprints = new Map();
    this.flowFunctions = [];
    this.functionIndex = new Map();
  }

  async initializeWorkspace(files, options = {}) {
    for (const record of this.files.values()) runtime.remove(record.analysis.absolutePath);
    this.files.clear();
    this.cache.clear();
    this.dataflow = emptyDataflow();
    this.generation = 0;
    this.entryBindingFingerprints.clear();
    this.options = { ...options };
    this.typescriptProject.initialize(files || []);
    for (const file of files || []) {
      const record = await this._analyzeFile(file);
      this.files.set(fileKey(record.analysis.absolutePath), record);
      this.cache.updateFile({
        absolutePath: record.analysis.absolutePath,
        version: record.version,
        analysis: record.analysis,
        functionSummaries: record.summaries,
      });
    }
    this._applyProjectEntryBindings();
    this._rebuildDependencies();
    this.pendingAffectedFiles = new Set(this.files.keys());
    this.pendingAffectedFunctionIds = new Set(this.analyses().flatMap(analysis => analysis.ir.functions.map(fn => fn.id)));
    const analysis = this.reanalyzeAffectedFunctions({ forceAll: true });
    return {
      analyses: this.analyses(),
      ...analysis,
      cache: this.cache.snapshot(),
    };
  }

  async updateFile(file, options = {}) {
    const key = fileKey(file.absolutePath);
    const previous = this.files.get(key);
    const typeAware = ["javascript", "typescript"].includes(file.language) ||
      ["javascript", "typescript"].includes(previous?.analysis?.language);
    const isolatedCompilerUpdate = typeAware && this.typescriptProject.canAnalyzeIsolated(file.absolutePath, file.text);
    const previousTypeDependents = typeAware && !isolatedCompilerUpdate ? this.typescriptProject.dependentsOf(file.absolutePath) : [];
    this.typescriptProject.update(file);
    const record = await this._analyzeFile(file, { isolatedCompiler: isolatedCompilerUpdate });
    if (previous?.version === record.version) {
      return {
        analysis: previous.analysis,
        cacheHit: true,
        affectedFiles: [],
        ...(options.reanalyze === false ? {} : this.reanalyzeAffectedFunctions()),
      };
    }
    if (previous?.irFingerprint === record.irFingerprint) {
      record.dependencyFunctionIds = [...(previous.dependencyFunctionIds || [])];
      this.files.set(key, record);
      this.cache.updateFile({
        absolutePath: record.analysis.absolutePath,
        version: record.version,
        analysis: record.analysis,
        functionSummaries: record.summaries,
        dependencyFunctionIds: record.dependencyFunctionIds,
      });
      return {
        analysis: record.analysis,
        cacheHit: false,
        semanticNoop: true,
        changedFunctionIds: [],
        reparsedTypeDependents: [],
        affectedFiles: [],
        findingDelta: { upsert: [], removedIds: [] },
        pathDelta: { upsert: [], removedIds: [] },
        metadata: {
          ...this.dataflow.metadata,
          generation: this.generation,
          incrementallyInvalidatedFiles: 0,
          incrementallyInvalidatedFunctions: 0,
          dataflowMs: 0,
          findingPathDiffMs: 0,
          semanticNoop: true,
        },
      };
    }

    const changedNames = new Set([
      ...(previous?.analysis.ir.functions || []).map(fn => fn.name.toLowerCase()),
      ...record.analysis.ir.functions.map(fn => fn.name.toLowerCase()),
    ]);
    const invalidation = this.cache.updateFile({
      absolutePath: record.analysis.absolutePath,
      version: record.version,
      analysis: record.analysis,
      functionSummaries: record.summaries,
      dependencyFunctionIds: previous?.dependencyFunctionIds || [],
    });
    this.files.set(key, record);
    const changedFunctionIds = new Set(invalidation.changedFunctionIds);
    const invalidatedFiles = new Set(invalidation.invalidatedFiles);
    const nextTypeDependents = typeAware && !isolatedCompilerUpdate ? this.typescriptProject.dependentsOf(file.absolutePath) : [];
    const reparsedTypeDependents = new Set([...previousTypeDependents, ...nextTypeDependents]);
    reparsedTypeDependents.delete(key);
    for (const dependentKey of reparsedTypeDependents) {
      const dependentPrevious = this.files.get(dependentKey);
      if (!dependentPrevious?.source || typeof dependentPrevious.source.text !== "string") continue;
      const dependentRecord = await this._analyzeFile(dependentPrevious.source);
      for (const fn of dependentPrevious.analysis.ir.functions) changedNames.add(fn.name.toLowerCase());
      for (const fn of dependentRecord.analysis.ir.functions) changedNames.add(fn.name.toLowerCase());
      const dependentInvalidation = this.cache.updateFile({
        absolutePath: dependentRecord.analysis.absolutePath,
        version: dependentRecord.version,
        analysis: dependentRecord.analysis,
        functionSummaries: dependentRecord.summaries,
        dependencyFunctionIds: dependentPrevious.dependencyFunctionIds || [],
        force: true,
      });
      this.files.set(dependentKey, dependentRecord);
      this.pendingAffectedFiles.add(dependentKey);
      for (const affected of dependentInvalidation.invalidatedFiles) invalidatedFiles.add(affected);
      for (const functionId of dependentInvalidation.changedFunctionIds) changedFunctionIds.add(functionId);
    }
    for (const affected of invalidatedFiles) this.pendingAffectedFiles.add(affected);
    this.pendingAffectedFiles.add(key);
    for (const caller of this._filesCallingAny(changedNames)) this.pendingAffectedFiles.add(caller);
    for (const functionId of this._applyProjectEntryBindings()) changedFunctionIds.add(functionId);
    this._rebuildDependencies(this.pendingAffectedFiles);
    this._queueAffectedFunctions([...changedFunctionIds]);

    const base = {
      analysis: record.analysis,
      cacheHit: false,
      changedFunctionIds: [...changedFunctionIds],
      reparsedTypeDependents: [...reparsedTypeDependents],
    };
    return options.reanalyze === false ? {
      ...base,
      affectedFiles: [...this.pendingAffectedFiles],
    } : {
      ...base,
      ...this.reanalyzeAffectedFunctions(),
    };
  }

  async removeFile(absolutePath, options = {}) {
    const key = fileKey(absolutePath);
    const previous = this.files.get(key);
    if (!previous) return { removed: false, affectedFiles: [] };
    const typeAware = ["javascript", "typescript"].includes(previous.analysis.language);
    const previousTypeDependents = typeAware ? this.typescriptProject.dependentsOf(absolutePath) : [];
    const changedNames = new Set(previous.analysis.ir.functions.map(fn => fn.name.toLowerCase()));
    const invalidation = this.cache.removeFile(absolutePath);
    this.files.delete(key);
    this.typescriptProject.remove(absolutePath);
    runtime.remove(absolutePath);
    const changedFunctionIds = new Set(invalidation.changedFunctionIds);
    const invalidatedFiles = new Set(invalidation.invalidatedFiles);
    const reparsedTypeDependents = new Set(previousTypeDependents);
    reparsedTypeDependents.delete(key);
    for (const dependentKey of reparsedTypeDependents) {
      const dependentPrevious = this.files.get(dependentKey);
      if (!dependentPrevious?.source || typeof dependentPrevious.source.text !== "string") continue;
      const dependentRecord = await this._analyzeFile(dependentPrevious.source);
      for (const fn of dependentPrevious.analysis.ir.functions) changedNames.add(fn.name.toLowerCase());
      for (const fn of dependentRecord.analysis.ir.functions) changedNames.add(fn.name.toLowerCase());
      const dependentInvalidation = this.cache.updateFile({
        absolutePath: dependentRecord.analysis.absolutePath,
        version: dependentRecord.version,
        analysis: dependentRecord.analysis,
        functionSummaries: dependentRecord.summaries,
        dependencyFunctionIds: dependentPrevious.dependencyFunctionIds || [],
        force: true,
      });
      this.files.set(dependentKey, dependentRecord);
      for (const affected of dependentInvalidation.invalidatedFiles) invalidatedFiles.add(affected);
      for (const functionId of dependentInvalidation.changedFunctionIds) changedFunctionIds.add(functionId);
    }
    for (const affected of invalidatedFiles) this.pendingAffectedFiles.add(affected);
    for (const caller of this._filesCallingAny(changedNames)) this.pendingAffectedFiles.add(caller);
    this.pendingAffectedFiles.delete(key);
    for (const functionId of this._applyProjectEntryBindings()) changedFunctionIds.add(functionId);
    this._rebuildDependencies(this.pendingAffectedFiles);
    this._queueAffectedFunctions([...changedFunctionIds]);
    const base = {
      removed: true,
      absolutePath,
      changedFunctionIds: [...changedFunctionIds],
      reparsedTypeDependents: [...reparsedTypeDependents],
    };
    return options.reanalyze === false ? {
      ...base,
      affectedFiles: [...this.pendingAffectedFiles],
    } : {
      ...base,
      ...this.reanalyzeAffectedFunctions(),
    };
  }

  reanalyzeAffectedFunctions(options = {}) {
    const analysisStartedAt = performance.now();
    const { forceAll = false, ...analysisOptions } = options;
    this.options = { ...this.options, ...analysisOptions };
    const affectedFiles = forceAll ? [...this.files.keys()] : [...this.pendingAffectedFiles];
    const affectedFunctionIds = forceAll
      ? this.analyses().flatMap(analysis => analysis.ir.functions.map(fn => fn.id))
      : [...this.pendingAffectedFunctionIds];
    if (!affectedFiles.length && !affectedFunctionIds.length && !forceAll) {
      return {
        affectedFiles: [],
        findingDelta: { upsert: [], removedIds: [] },
        pathDelta: { upsert: [], removedIds: [] },
        metadata: this.dataflow.metadata,
      };
    }
    const previous = this.dataflow;
    let next;
    const runtimeOptions = {
      ...this.options,
      _flowFunctions: this.flowFunctions,
      _functionIndex: this.functionIndex,
    };
    if (forceAll || !previous.paths.length) {
      next = runDataflowAnalysis(this.analyses(), runtimeOptions);
    } else {
      const partial = runDataflowAnalysis(this.analyses(), { ...runtimeOptions, rootFunctionIds: affectedFunctionIds });
      const invalidated = new Set(affectedFunctionIds);
      const retained = previous.paths.filter(flow => !invalidated.has(flow.rootFunctionId) &&
        !(flow.touchedFunctionIds || []).some(functionId => invalidated.has(functionId)));
      const paths = [...new Map([...retained, ...partial.paths].map(flow => [flow.id, flow])).values()];
      next = {
        paths,
        findings: evaluateFlowPaths(paths, undefined, this.options),
        metadata: {
          truncated: Boolean(partial.metadata.truncated || previous.metadata.truncated),
          explorationTruncated: Boolean(partial.metadata.explorationTruncated),
          totalCandidates: retained.length + partial.metadata.totalCandidates,
        },
      };
    }
    this.dataflow = next;
    this.pendingAffectedFiles.clear();
    this.pendingAffectedFunctionIds.clear();
    this.generation += 1;
    const diffStartedAt = performance.now();
    const findingDelta = diffById(previous.findings, next.findings);
    const pathDelta = diffById(previous.paths, next.paths);
    const diffMs = performance.now() - diffStartedAt;
    return {
      affectedFiles,
      findingDelta,
      pathDelta,
      metadata: {
        ...next.metadata,
        generation: this.generation,
        incrementallyInvalidatedFiles: affectedFiles.length,
        incrementallyInvalidatedFunctions: affectedFunctionIds.length,
        dataflowMs: roundMetric(performance.now() - analysisStartedAt - diffMs),
        findingPathDiffMs: roundMetric(diffMs),
      },
    };
  }

  async configure(options = {}) {
    const previousOptions = this.options;
    const changed = JSON.stringify(previousOptions) !== JSON.stringify({ ...previousOptions, ...options });
    const nextOptions = { ...previousOptions, ...options };
    const frontendChanged = previousOptions.astDifferential !== nextOptions.astDifferential ||
      previousOptions.projectConfiguration?.semanticFingerprint !== nextOptions.projectConfiguration?.semanticFingerprint ||
      scopedConfigurationFingerprint(previousOptions.projectConfigurationsByRoot) !== scopedConfigurationFingerprint(nextOptions.projectConfigurationsByRoot) ||
      projectIdentityFingerprint(previousOptions.projectIdentitiesByRoot) !== projectIdentityFingerprint(nextOptions.projectIdentitiesByRoot);
    this.options = nextOptions;
    if (!changed) return {
      affectedFiles: [],
      findingDelta: { upsert: [], removedIds: [] },
      pathDelta: { upsert: [], removedIds: [] },
      metadata: this.dataflow.metadata,
    };
    if (frontendChanged) return this._reparseWorkspace();
    this.pendingAffectedFiles = new Set(this.files.keys());
    this.pendingAffectedFunctionIds = new Set(this.analyses().flatMap(analysis => analysis.ir.functions.map(fn => fn.id)));
    return this.reanalyzeAffectedFunctions({ forceAll: true });
  }

  queryPaths(options = {}) {
    return runDataflowAnalysis(this.analyses(), {
      ...this.options,
      ...options,
      _flowFunctions: this.flowFunctions,
      _functionIndex: this.functionIndex,
    });
  }

  queryAudit(options = {}) {
    return runAuditQuery(this.analyses(), { ...this.options, ...options });
  }

  analyses() {
    return [...this.files.values()].map(record => record.analysis);
  }

  async _analyzeFile(file, options = {}) {
    if (file.analysis?.ir) {
      return {
        analysis: file.analysis,
        version: file.version || stableHash(JSON.stringify(file.analysis.ir)),
        summaries: summarizeFileIR(file.analysis.ir),
        irFingerprint: semanticIrFingerprint(file.analysis.ir),
        dependencyFunctionIds: [],
        source: file,
      };
    }
    const compilerModel = ["javascript", "typescript"].includes(file.language)
      ? options.isolatedCompiler
        ? createCompilerModel(file.text, file.absolutePath, file.language)
        : this.typescriptProject.modelFor(file.absolutePath)
      : undefined;
    const projectConfiguration = configurationForAbsolutePath(this.options, file.absolutePath);
    const analysis = await analyzeTextAsync(file.text, file.language, file.absolutePath, file.relativePath, {
      differential: Boolean(this.options.astDifferential),
      compilerModel,
      semanticModels: projectConfiguration?.semanticModels || [],
    });
    return {
      analysis,
      version: file.version || stableHash(file.text),
      summaries: summarizeFileIR(analysis.ir),
      irFingerprint: semanticIrFingerprint(analysis.ir),
      dependencyFunctionIds: [],
      source: { ...file },
    };
  }

  _rebuildDependencies(affectedFiles) {
    const analyses = this.analyses();
    const functions = functionsFromAnalyses(analyses, this.options);
    const index = buildFunctionIndex(functions);
    this.flowFunctions = functions;
    this.functionIndex = index;
    const affected = affectedFiles ? new Set([...affectedFiles].map(fileKey)) : undefined;
    const byFile = new Map();
    for (const caller of functions) {
      if (affected && !affected.has(fileKey(caller.absolutePath))) continue;
      const dependencies = byFile.get(fileKey(caller.absolutePath)) || new Set();
      for (const event of caller.events.filter(event => event.type === "call" && event.callee)) {
        for (const resolution of resolveCandidates(index, event, caller)) dependencies.add(resolution.fn.id);
      }
      byFile.set(fileKey(caller.absolutePath), dependencies);
    }
    for (const [key, record] of this.files) {
      if (affected && !affected.has(key)) continue;
      record.dependencyFunctionIds = [...(byFile.get(key) || [])];
      this.cache.replaceDependencies(record.analysis.absolutePath, record.dependencyFunctionIds);
    }
  }

  _applyProjectEntryBindings() {
    const functions = new Map(this.analyses().flatMap(analysis => analysis.ir.functions.map(fn => [fn.id, fn])));
    for (const fn of functions.values()) {
      fn.entryPoint = undefined;
      fn.entryPoints = [];
      for (const parameter of fn.parameters) delete parameter.role;
    }
    for (const analysis of this.analyses()) {
      for (const entry of analysis.ir.entryPoints || []) {
        if (!entry.handler) continue;
        entry.functionId = undefined;
        entry.symbolKey = undefined;
        entry.bindingStatus = "unresolved";
      }
    }
    const flowFunctions = functionsFromAnalyses(this.analyses(), this.options);
    for (const analysis of this.analyses()) {
      for (const entry of analysis.ir.entryPoints || []) {
        if (entry.handler && !entry.functionId) {
          const projectIdentity = projectIdentityForAbsolutePath(this.options, analysis.absolutePath);
          const workspaceRoot = workspaceRootForAbsolutePath(this.options, analysis.absolutePath) || projectIdentity?.workspaceRoot;
          const candidates = resolveProjectEntryHandler(entry.handler, flowFunctions, workspaceRoot, projectIdentity);
          if (candidates.length === 1) {
            entry.functionId = candidates[0].id;
            entry.symbolKey = candidates[0].symbolKey;
            entry.bindingStatus = "verified";
            if (!entry.parameterRoles?.length) {
              entry.parameterRoles = frameworkParameterRoles(entry, candidates[0].parameterDetails || []);
            }
          } else entry.bindingStatus = candidates.length ? "ambiguous" : "unresolved";
        }
        const fn = functions.get(entry.functionId);
        if (!fn) continue;
        const binding = {
          title: entry.title,
          method: entry.method,
          route: entry.route,
          parameterRoles: entry.parameterRoles || [],
          framework: entry.framework,
        };
        fn.entryPoints.push(binding);
        fn.entryPoint ||= binding;
        fn.parameters.forEach((parameter, index) => {
          if (binding.parameterRoles[index]) parameter.role = binding.parameterRoles[index];
        });
      }
    }
    const next = new Map([...functions.values()].map(fn => [fn.id, JSON.stringify(fn.entryPoints)]));
    const changed = new Set([...this.entryBindingFingerprints.keys(), ...next.keys()]);
    for (const functionId of [...changed]) {
      if (this.entryBindingFingerprints.get(functionId) === next.get(functionId)) changed.delete(functionId);
    }
    this.entryBindingFingerprints = next;
    return [...changed];
  }

  _filesCallingAny(names) {
    if (!names.size) return [];
    const matches = new Set();
    for (const [key, record] of this.files) {
      if (record.summaries.some(summary => summary.callees.some(callee => names.has(String(callee.function || "").toLowerCase())))) matches.add(key);
    }
    return [...matches];
  }

  async _reparseWorkspace() {
    const sources = [...this.files.values()].map(record => record.source).filter(source => source?.text !== undefined);
    const preserved = [...this.files.values()].filter(record => record.source?.text === undefined);
    this.files.clear();
    this.cache.clear();
    this.typescriptProject.initialize(sources);
    for (const record of preserved) {
      this.files.set(fileKey(record.analysis.absolutePath), record);
      this.cache.updateFile({
        absolutePath: record.analysis.absolutePath,
        version: record.version,
        analysis: record.analysis,
        functionSummaries: record.summaries,
      });
    }
    for (const source of sources) {
      const record = await this._analyzeFile(source);
      this.files.set(fileKey(record.analysis.absolutePath), record);
      this.cache.updateFile({
        absolutePath: record.analysis.absolutePath,
        version: record.version,
        analysis: record.analysis,
        functionSummaries: record.summaries,
      });
    }
    this._applyProjectEntryBindings();
    this._rebuildDependencies();
    this.pendingAffectedFiles = new Set(this.files.keys());
    this.pendingAffectedFunctionIds = new Set(this.analyses().flatMap(analysis => analysis.ir.functions.map(fn => fn.id)));
    return { analyses: this.analyses(), ...this.reanalyzeAffectedFunctions({ forceAll: true }) };
  }

  _queueAffectedFunctions(changedFunctionIds = []) {
    for (const functionId of changedFunctionIds) this.pendingAffectedFunctionIds.add(functionId);
    for (const key of this.pendingAffectedFiles) {
      for (const summary of this.files.get(key)?.summaries || []) this.pendingAffectedFunctionIds.add(summary.id);
    }
  }
}

function resolveProjectEntryHandler(handler, functions, workspaceRoot, projectIdentity) {
  const candidates = functions.filter(fn =>
    fn.language === handler.language &&
    fn.name.toLowerCase() === String(handler.functionName || "").toLowerCase() &&
    (!workspaceRoot || !fn.workspaceRoot || normalizePath(fn.workspaceRoot) === normalizePath(workspaceRoot)));
  if (handler.language === "php") {
    const target = normalizePhpHandlerType(handler.targetType || handler.className);
    const mappedPaths = composerPathsForType(projectIdentity, handler.targetType);
    const precise = candidates.filter(fn => {
      if (mappedPaths.length && mappedPaths.includes(normalizePath(fn.absolutePath))) return true;
      return normalizePhpHandlerType(fn.qualifiedEnclosingScope) === target;
    });
    if (precise.length) return precise;
    if (mappedPaths.length || String(handler.targetType || "").includes("\\")) return [];
    return candidates.filter(fn => normalizePhpHandlerType(fn.enclosingScope) === normalizePhpHandlerType(handler.className));
  }
  if (handler.language === "python") {
    const expectedModule = String(handler.moduleName || "").replaceAll(".", "/").replace(/^\/+|\/+$/g, "").toLowerCase();
    if (!expectedModule) return [];
    return candidates.filter(fn => {
      const modulePath = String(fn.relativePath || "").replaceAll("\\", "/").replace(/\.py$/i, "").replace(/\/__init__$/i, "").toLowerCase();
      return modulePath === expectedModule || modulePath.endsWith(`/${expectedModule}`);
    });
  }
  return [];
}

function normalizePhpHandlerType(value) {
  return String(value || "").replace(/^\\+/, "").replace(/[\\/]+/g, ".").toLowerCase();
}

function diffById(previous, current) {
  const before = new Map((previous || []).map(item => [item.id, analysisContentDigest(item)]));
  const after = new Map((current || []).map(item => [item.id, analysisContentDigest(item)]));
  return {
    upsert: (current || []).filter(item => before.get(item.id) !== after.get(item.id)),
    removedIds: [...before.keys()].filter(id => !after.has(id)),
  };
}

function emptyDataflow() {
  return { paths: [], findings: [], metadata: { truncated: false, explorationTruncated: false, totalCandidates: 0 } };
}

function roundMetric(value) {
  return Math.round(Math.max(0, value) * 100) / 100;
}

function semanticIrFingerprint(ir = {}) {
  const { lines: _sourceLines, frontend = {}, ...semanticIr } = ir;
  const { incremental: _incrementalParse, ...frontendCapability } = frontend;
  return stableHash(JSON.stringify({ ...semanticIr, frontend: frontendCapability }), 32);
}

module.exports = { WorkspaceAnalysisEngine, diffById };
