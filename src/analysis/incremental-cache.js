"use strict";

const { normalizePath } = require("../identity");

class IncrementalAnalysisCache {
  constructor() {
    this.files = new Map();
    this.dependentsByFunction = new Map();
  }

  getFile(absolutePath, version) {
    const record = this.files.get(fileKey(absolutePath));
    return record && (version === undefined || record.version === version) ? record : undefined;
  }

  updateFile(input) {
    const key = fileKey(input.absolutePath);
    const previous = this.files.get(key);
    if (previous?.version === input.version && !input.force) return { cacheHit: true, changedFunctionIds: [], invalidatedFiles: [] };

    if (previous) this._removeReverseDependencies(key, previous.dependencyFunctionIds);
    const summaries = [...(input.functionSummaries || [])];
    const dependencyFunctionIds = [...new Set(input.dependencyFunctionIds || [])];
    const record = {
      absolutePath: input.absolutePath,
      version: input.version,
      analysis: input.analysis,
      functionSummaries: summaries,
      dependencyFunctionIds,
    };
    this.files.set(key, record);
    this._addReverseDependencies(key, dependencyFunctionIds);

    const changedFunctionIds = changedFunctions(previous?.functionSummaries || [], summaries);
    return {
      cacheHit: false,
      changedFunctionIds,
      invalidatedFiles: this.affectedFiles(key, changedFunctionIds),
    };
  }

  removeFile(absolutePath) {
    const key = fileKey(absolutePath);
    const previous = this.files.get(key);
    if (!previous) return { changedFunctionIds: [], invalidatedFiles: [] };
    this.files.delete(key);
    this._removeReverseDependencies(key, previous.dependencyFunctionIds);
    const changedFunctionIds = previous.functionSummaries.map(summary => summary.id);
    return { changedFunctionIds, invalidatedFiles: this.affectedFiles(key, changedFunctionIds) };
  }

  replaceDependencies(absolutePath, dependencyFunctionIds) {
    const key = fileKey(absolutePath);
    const record = this.files.get(key);
    if (!record) return false;
    const next = [...new Set(dependencyFunctionIds || [])];
    this._removeReverseDependencies(key, record.dependencyFunctionIds);
    record.dependencyFunctionIds = next;
    this._addReverseDependencies(key, next);
    return true;
  }

  affectedFiles(changedFile, changedFunctionIds) {
    const affected = new Set([fileKey(changedFile)]);
    const queuedFunctions = [...changedFunctionIds];
    const visitedFunctions = new Set();
    while (queuedFunctions.length) {
      const functionId = queuedFunctions.shift();
      if (!functionId || visitedFunctions.has(functionId)) continue;
      visitedFunctions.add(functionId);
      for (const dependentFile of this.dependentsByFunction.get(functionId) || []) {
        if (affected.has(dependentFile)) continue;
        affected.add(dependentFile);
        for (const summary of this.files.get(dependentFile)?.functionSummaries || []) queuedFunctions.push(summary.id);
      }
    }
    return [...affected];
  }

  clear() {
    this.files.clear();
    this.dependentsByFunction.clear();
  }

  snapshot() {
    return [...this.files.entries()].map(([key, record]) => ({
      key,
      version: record.version,
      functions: record.functionSummaries.length,
      dependencies: record.dependencyFunctionIds.length,
    }));
  }

  _addReverseDependencies(file, functionIds) {
    for (const functionId of functionIds) {
      if (!this.dependentsByFunction.has(functionId)) this.dependentsByFunction.set(functionId, new Set());
      this.dependentsByFunction.get(functionId).add(file);
    }
  }

  _removeReverseDependencies(file, functionIds) {
    for (const functionId of functionIds) {
      const dependents = this.dependentsByFunction.get(functionId);
      dependents?.delete(file);
      if (!dependents?.size) this.dependentsByFunction.delete(functionId);
    }
  }
}

function changedFunctions(previous, current) {
  const before = new Map(previous.map(summary => [summary.id, fingerprint(summary)]));
  const after = new Map(current.map(summary => [summary.id, fingerprint(summary)]));
  return [...new Set([...before.keys(), ...after.keys()])].filter(id => before.get(id) !== after.get(id));
}

function fileKey(value) {
  return normalizePath(value);
}

function fingerprint(value) {
  return JSON.stringify(value);
}

module.exports = { IncrementalAnalysisCache, changedFunctions, fileKey };
