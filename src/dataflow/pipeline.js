"use strict";

const { findSourceSinkPaths } = require("./path-engine");
const { evaluateFlowPaths } = require("../rules/rule-engine");
const { analysisSettingsForAbsolutePath } = require("../config/configuration-scope");
const { normalizePath } = require("../identity");

function runDataflowAnalysis(analyses, options = {}) {
  const results = scopedPathResults(analyses, options);
  const paths = results.flatMap(result => [...result]);
  return {
    paths,
    findings: evaluateFlowPaths(paths, undefined, options),
    metadata: mergePathMetadata(results, paths.length),
  };
}

function scopedPathResults(analyses, options) {
  if (!(options.analysisSettingsByRoot || []).length || options._scopedAnalysis) {
    return [findSourceSinkPaths(analyses, options)];
  }
  const functions = options._flowFunctions;
  const roots = new Map();
  const rootFor = absolutePath => {
    const target = normalizePath(absolutePath);
    return (options.analysisSettingsByRoot || [])
      .map(item => normalizePath(item.root))
      .filter(root => target === root || target.startsWith(`${root}/`))
      .sort((left, right) => right.length - left.length)[0] || "<unscoped>";
  };
  for (const analysis of analyses || []) {
    const root = rootFor(analysis.absolutePath || analysis.ir?.absolutePath);
    if (!roots.has(root)) roots.set(root, { analyses: [], functions: [] });
    roots.get(root).analyses.push(analysis);
  }
  for (const fn of functions || []) {
    const root = normalizePath(fn.workspaceRoot) || rootFor(fn.absolutePath);
    if (!roots.has(root)) roots.set(root, { analyses: [], functions: [] });
    roots.get(root).functions.push(fn);
  }
  return [...roots.values()].map(group => {
    const representative = group.functions[0]?.absolutePath || group.analyses[0]?.absolutePath;
    const settings = analysisSettingsForAbsolutePath(options, representative);
    const selectedIds = Array.isArray(options.rootFunctionIds)
      ? options.rootFunctionIds.filter(id => group.functions.some(fn => fn.id === id))
      : undefined;
    return findSourceSinkPaths(group.analyses, {
      ...options,
      ...settings,
      _scopedAnalysis: true,
      _flowFunctions: functions ? group.functions : undefined,
      _functionIndex: undefined,
      rootFunctionIds: selectedIds,
    });
  });
}

function mergePathMetadata(results, pathCount) {
  const explorations = results.map(result => result.exploration || {});
  const partialRoots = [...new Map(explorations.flatMap(item => item.partialRoots || [])
    .map(root => [root.key, root])).values()];
  return {
    truncated: results.some(result => result.truncated),
    explorationTruncated: results.some(result => result.explorationTruncated),
    totalCandidates: results.reduce((sum, result) => sum + (result.totalCandidates || result.length), 0) || pathCount,
    exploredFlowStates: explorations.reduce((sum, item) => sum + (item.exploredStates || 0), 0),
    visitedFlowEvents: explorations.reduce((sum, item) => sum + (item.visitedEvents || 0), 0),
    flowStateBudget: explorations.reduce((sum, item) => sum + (item.maxExploredStates || 0), 0),
    flowEventBudget: explorations.reduce((sum, item) => sum + (item.maxVisitedEvents || 0), 0),
    flowStepBudget: Math.max(0, ...explorations.map(item => item.maxTraceSteps || 0)),
    flowHigherOrderDepthBudget: Math.max(0, ...explorations.map(item => item.maxHigherOrderDepth || 0)),
    flowAsyncDepthBudget: Math.max(0, ...explorations.map(item => item.maxAsyncDepth || 0)),
    flowTimeoutMs: Math.max(0, ...explorations.map(item => item.maxAnalysisMs || 0)),
    flowTimedOut: explorations.some(item => item.timedOut),
    totalFlowRoots: explorations.reduce((sum, item) => sum + (item.totalRoots || 0), 0),
    processedFlowRoots: explorations.reduce((sum, item) => sum + (item.processedRoots || 0), 0),
    partialPaths: partialRoots.length,
    partialRoots,
    flowRankingMs: explorations.reduce((sum, item) => sum + (item.rankingMs || 0), 0),
    flowExplorationMs: explorations.reduce((sum, item) => sum + (item.explorationMs || 0), 0),
    truncationReasons: [...new Set(explorations.flatMap(item => item.truncationReasons || []))],
  };
}

module.exports = { mergePathMetadata, runDataflowAnalysis, scopedPathResults };
