"use strict";

const path = require("path");
const { stableHash } = require("./identity");
const { projectAnalysis } = require("./frontends/ir-projection");
const {
  SIGNAL_PATTERNS,
  collectSignals,
  findEntries,
  findFunctions,
  parseSourceStructure,
  traceIdentifier,
} = require("./frontends/pattern-parser");
const { frontendForLanguage, parseWithBestFrontend } = require("./frontends/registry");
const { buildReviewTargets, compareTargets } = require("./review/targets");

function analyzeText(text, language, absolutePath, relativePath = path.basename(absolutePath)) {
  const frontend = frontendForLanguage(language);
  if (!frontend) throw new Error(`No TraceGuard frontend is registered for ${language}.`);
  return projectAnalysis(frontend.parse({ text, absolutePath, relativePath }));
}

function buildAuditModel(analyses) {
  const items = analyses.flatMap(analysis => buildReviewTargets(analysis)).sort(compareTargets);
  const entries = analyses.flatMap(analysis => analysis.entries.map(item => ({
    ...item,
    absolutePath: analysis.absolutePath,
    relativePath: analysis.relativePath,
    language: analysis.language,
  })));
  const signals = analyses.flatMap(analysis => analysis.signals);
  return {
    indexed_at: new Date().toISOString(),
    files: analyses.length,
    lines: analyses.reduce((total, analysis) => total + analysis.lines, 0),
    functions: analyses.reduce((total, analysis) => total + analysis.functions.length, 0),
    entries,
    signals,
    items,
    languages: analyses.reduce((counts, analysis) => ({
      ...counts,
      [analysis.language]: (counts[analysis.language] || 0) + 1,
    }), {}),
    languageCapabilities: buildLanguageCapabilities(analyses),
  };
}

function buildLanguageCapabilities(analyses) {
  const result = {};
  for (const analysis of analyses) {
    const current = result[analysis.language] || { files: 0, astFiles: 0, fallbackFiles: 0, degradedFiles: 0, reasons: [] };
    current.files += 1;
    if (analysis.frontend?.mode === "ast") current.astFiles += 1;
    else current.fallbackFiles += 1;
    if (analysis.frontend?.degraded) current.degradedFiles += 1;
    if (analysis.frontend?.degradedReason && !current.reasons.includes(analysis.frontend.degradedReason)) current.reasons.push(analysis.frontend.degradedReason);
    current.capability = analysis.frontend?.capability || "fallback";
    result[analysis.language] = current;
  }
  return result;
}

function shortHash(value) {
  return stableHash(value, 16);
}

async function analyzeTextAsync(text, language, absolutePath, relativePath = path.basename(absolutePath), options = {}) {
  const ir = await parseWithBestFrontend({ text, language, absolutePath, relativePath, options });
  return projectAnalysis(ir);
}

module.exports = {
  SIGNAL_PATTERNS,
  analyzeText,
  analyzeTextAsync,
  buildAuditModel,
  buildLanguageCapabilities,
  collectSignals,
  findEntries,
  findFunctions,
  parseSourceStructure,
  shortHash,
  traceIdentifier,
};
