"use strict";

const { findSourceSinkPaths } = require("./path-engine");
const { evaluateFlowPaths } = require("../rules/rule-engine");

function runDataflowAnalysis(analyses, options = {}) {
  const result = findSourceSinkPaths(analyses, options);
  const paths = [...result];
  return {
    paths,
    findings: evaluateFlowPaths(paths, undefined, options),
    metadata: {
      truncated: Boolean(result.truncated),
      explorationTruncated: Boolean(result.explorationTruncated),
      totalCandidates: result.totalCandidates || paths.length,
    },
  };
}

module.exports = { runDataflowAnalysis };
