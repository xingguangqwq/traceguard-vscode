"use strict";

const { GuardCapability, SinkKind, SourceKind } = require("../semantics");
const { sinkModel, sourceModel, guardModel, propagatorModel } = require("../model-factories");

const GO_MODELS = Object.freeze([
  sinkModel({
    id: "go.os_exec.Command",
    languages: ["go"],
    moduleNames: ["os/exec"],
    qualifiedNames: ["os/exec.Command", "exec.Command"],
    callNames: ["Command"],
    taintArguments: [],
    taintRestFrom: 0,
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["package-function"],
  }),
  sinkModel({
    id: "go.os_exec.CommandContext",
    languages: ["go"],
    moduleNames: ["os/exec"],
    qualifiedNames: ["os/exec.CommandContext", "exec.CommandContext"],
    callNames: ["CommandContext"],
    taintArguments: [],
    taintRestFrom: 1,
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["package-function"],
  }),
]);

module.exports = { GO_MODELS };
