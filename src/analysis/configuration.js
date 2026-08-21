"use strict";

const MODEL_CONFIGURATION_KEYS = Object.freeze([
  "traceguard.flowMaxDepth",
  "traceguard.flowMaxPaths",
]);

function affectsAnalysisModel(event) {
  return MODEL_CONFIGURATION_KEYS.some(key => event.affectsConfiguration(key));
}

module.exports = { MODEL_CONFIGURATION_KEYS, affectsAnalysisModel };
