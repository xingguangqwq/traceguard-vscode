"use strict";

const { GuardCapability, SinkKind, SourceKind } = require("../semantics");
const { sinkModel, sourceModel, guardModel, propagatorModel } = require("../model-factories");

const CSHARP_MODELS = Object.freeze([
  sinkModel({
    id: "dotnet.System.Diagnostics.Process.Start",
    languages: ["csharp"],
    moduleNames: ["System.Diagnostics"],
    qualifiedNames: ["System.Diagnostics.Process.Start", "Process.Start"],
    receiverTypes: ["System.Diagnostics.Process", "Process"],
    callNames: ["Start"],
    taintArguments: [0, 1],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["static-method"],
  }),
]);

module.exports = { CSHARP_MODELS };
