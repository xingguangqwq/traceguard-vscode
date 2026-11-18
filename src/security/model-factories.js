"use strict";

const { sourceExposureForKind } = require("./semantics");

const SemanticRole = Object.freeze({
  SOURCE: "source",
  SINK: "sink",
  PROPAGATOR: "propagator",
  GUARD: "guard",
});

function sinkModel(input) {
  return Object.freeze({
    role: SemanticRole.SINK,
    returnsTaint: false,
    receiverTypes: [],
    taintReceiver: false,
    ...input,
  });
}

function sourceModel(input) {
  return Object.freeze({
    role: SemanticRole.SOURCE,
    returnsTaint: true,
    receiverTypes: [],
    taintReceiver: false,
    exposure: sourceExposureForKind(input.sourceKind),
    ...input,
  });
}

function guardModel(input) {
  return Object.freeze({
    role: SemanticRole.GUARD,
    returnsTaint: false,
    receiverTypes: [],
    taintReceiver: false,
    ...input,
  });
}

function propagatorModel(input) {
  return Object.freeze({
    role: SemanticRole.PROPAGATOR,
    returnsTaint: true,
    receiverTypes: [],
    taintReceiver: false,
    taintArguments: [],
    ...input,
  });
}

module.exports = { SemanticRole, sinkModel, sourceModel, guardModel, propagatorModel };
