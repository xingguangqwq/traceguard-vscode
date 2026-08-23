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
const { TypeScriptProject } = require("../frontends/typescript-compiler");
const { IncrementalAnalysisCache, fileKey } = require("./incremental-cache");

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
    const previousTypeDependents = typeAware ? this.typescriptProject.dependentsOf(file.absolutePath) : [];
    this.typescriptProject.update(file);
    const record = await this._analyzeFile(file);
    if (previous?.version === record.version) {
      return {
        analysis: previous.analysis,
        cacheHit: true,
        affectedFiles: [],
        ...(options.reanalyze === false ? {} : this.reanalyzeAffectedFunctions()),
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
    const nextTypeDependents = typeAware ? this.typescriptProject.dependentsOf(file.absolutePath) : [];
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
    this._rebuildDependencies();
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
    this._rebuildDependencies();
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
    if (forceAll || !previous.paths.length) {
      next = runDataflowAnalysis(this.analyses(), this.options);
    } else {
      const partial = runDataflowAnalysis(this.analyses(), { ...this.options, rootFunctionIds: affectedFunctionIds });
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
    return {
      affectedFiles,
      findingDelta: diffById(previous.findings, next.findings),
      pathDelta: diffById(previous.paths, next.paths),
      metadata: {
        ...next.metadata,
        generation: this.generation,
        incrementallyInvalidatedFiles: affectedFiles.length,
        incrementallyInvalidatedFunctions: affectedFunctionIds.length,
      },
    };
  }

  async configure(options = {}) {
    const previousOptions = this.options;
    const changed = JSON.stringify(previousOptions) !== JSON.stringify({ ...previousOptions, ...options });
    const nextOptions = { ...previousOptions, ...options };
    const frontendChanged = previousOptions.astDifferential !== nextOptions.astDifferential ||
      previousOptions.projectConfiguration?.semanticFingerprint !== nextOptions.projectConfiguration?.semanticFingerprint;
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
    return runDataflowAnalysis(this.analyses(), { ...this.options, ...options });
  }

  queryAudit(options = {}) {
    return runAuditQuery(this.analyses(), options);
  }

  analyses() {
    return [...this.files.values()].map(record => record.analysis);
  }

  async _analyzeFile(file) {
    if (file.analysis?.ir) {
      return {
        analysis: file.analysis,
        version: file.version || stableHash(JSON.stringify(file.analysis.ir)),
        summaries: summarizeFileIR(file.analysis.ir),
        dependencyFunctionIds: [],
        source: file,
      };
    }
    const compilerModel = ["javascript", "typescript"].includes(file.language)
      ? this.typescriptProject.modelFor(file.absolutePath)
      : undefined;
    const analysis = await analyzeTextAsync(file.text, file.language, file.absolutePath, file.relativePath, {
      differential: Boolean(this.options.astDifferential),
      compilerModel,
      semanticModels: this.options.projectConfiguration?.semanticModels || [],
    });
    return {
      analysis,
      version: file.version || stableHash(file.text),
      summaries: summarizeFileIR(analysis.ir),
      dependencyFunctionIds: [],
      source: { ...file },
    };
  }

  _rebuildDependencies() {
    const analyses = this.analyses();
    const functions = functionsFromAnalyses(analyses);
    const index = buildFunctionIndex(functions);
    const byFile = new Map();
    for (const caller of functions) {
      const dependencies = byFile.get(fileKey(caller.absolutePath)) || new Set();
      for (const event of caller.events.filter(event => event.type === "call" && event.callee)) {
        for (const resolution of resolveCandidates(index, event, caller)) dependencies.add(resolution.fn.id);
      }
      byFile.set(fileKey(caller.absolutePath), dependencies);
    }
    for (const [key, record] of this.files) {
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

function diffById(previous, current) {
  const before = new Map((previous || []).map(item => [item.id, JSON.stringify(item)]));
  const after = new Map((current || []).map(item => [item.id, JSON.stringify(item)]));
  return {
    upsert: (current || []).filter(item => before.get(item.id) !== after.get(item.id)),
    removedIds: [...before.keys()].filter(id => !after.has(id)),
  };
}

function emptyDataflow() {
  return { paths: [], findings: [], metadata: { truncated: false, explorationTruncated: false, totalCandidates: 0 } };
}

module.exports = { WorkspaceAnalysisEngine, diffById };
