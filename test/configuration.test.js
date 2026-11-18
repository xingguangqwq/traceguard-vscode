"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { affectsAnalysisModel, MODEL_CONFIGURATION_KEYS } = require("../src/analysis/configuration");

test("dataflow settings invalidate the analysis model", () => {
  for (const changed of MODEL_CONFIGURATION_KEYS) {
    assert.equal(affectsAnalysisModel({ affectsConfiguration: key => key === changed }), true);
  }
  assert.equal(affectsAnalysisModel({ affectsConfiguration: key => key === "traceguard.showFlowCodeLens" }), false);
});

test("every contributed flow budget invalidates cached analysis", () => {
  const properties = require("../package.json").contributes.configuration.properties;
  for (const key of Object.keys(properties).filter(key => key.startsWith("traceguard.flow"))) {
    assert.ok(MODEL_CONFIGURATION_KEYS.includes(key), `${key} must invalidate stale flow results`);
  }
});
