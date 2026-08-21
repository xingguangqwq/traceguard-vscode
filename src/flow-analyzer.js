"use strict";

// Compatibility facade. New code should import from frontends/ or dataflow/ directly.
const { buildFunctionFlows } = require("./frontends/operation-extractor");
const { extractCalls, extractIdentifiers, parseParameterNames, splitArguments } = require("./frontends/syntax-tools");
const { SOURCE_TOKEN, findSourceSinkPaths } = require("./dataflow/path-engine");

module.exports = {
  SOURCE_TOKEN,
  buildFunctionFlows,
  extractCalls,
  extractIdentifiers,
  findSourceSinkPaths,
  parseParameterNames,
  splitArguments,
};
