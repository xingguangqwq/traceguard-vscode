"use strict";

const crypto = require("crypto");
const path = require("path");
const { projectAnalysis } = require("./frontends/ir-projection");
const {
  SIGNAL_PATTERNS,
  collectSignals,
  findEntries,
  findFunctions,
  parseSourceStructure,
  traceIdentifier,
} = require("./frontends/pattern-parser");
const { frontendForLanguage } = require("./frontends/registry");
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
  };
}

function shortHash(value) {
  return crypto.createHash("sha1").update(value).digest("hex").slice(0, 16);
}

module.exports = {
  SIGNAL_PATTERNS,
  analyzeText,
  buildAuditModel,
  collectSignals,
  findEntries,
  findFunctions,
  parseSourceStructure,
  shortHash,
  traceIdentifier,
};
