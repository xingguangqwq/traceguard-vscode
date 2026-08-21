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
