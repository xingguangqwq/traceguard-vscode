"use strict";

const { OperationKind } = require("../ir/schema");
const { GuardCapability } = require("../security/semantics");
const { workspaceRootForAbsolutePath } = require("../config/configuration-scope");
const { projectIdentityForAbsolutePath } = require("../config/project-identity");

function functionsFromAnalyses(analyses, options = {}) {
  const entriesByFunction = new Map();
  for (const analysis of analyses) {
    for (const entry of analysis.ir?.entryPoints || []) {
      if (!entry.functionId) continue;
      if (!entriesByFunction.has(entry.functionId)) entriesByFunction.set(entry.functionId, []);
      entriesByFunction.get(entry.functionId).push(entry);
    }
  }
  // Keep one shared relation table per workspace root. The previous implementation
  // filtered the full table once per file, which produced O(files * relations)
  // arrays even though every function in a root sees the same type graph.
  const typeRelationsByRoot = new Map();
  for (const analysis of analyses) {
    const workspaceRoot = workspaceRootForAbsolutePath(options, analysis.absolutePath || analysis.ir?.absolutePath);
    const key = workspaceRelationKey(workspaceRoot);
    if (!typeRelationsByRoot.has(key)) typeRelationsByRoot.set(key, []);
    const scoped = typeRelationsByRoot.get(key);
    for (const relation of analysis.ir?.typeRelations || []) scoped.push({ ...relation, workspaceRoot });
  }
  return analyses.flatMap(analysis => {
    const workspaceRoot = workspaceRootForAbsolutePath(options, analysis.absolutePath || analysis.ir?.absolutePath);
    const projectIdentity = projectIdentityForAbsolutePath(options, analysis.absolutePath || analysis.ir?.absolutePath);
    const scopedRelations = typeRelationsByRoot.get(workspaceRelationKey(workspaceRoot)) || [];
    return (analysis.ir?.functions || []).map(fn => flowFunctionFromIR(fn, entriesByFunction.get(fn.id), {
      workspaceRoot,
      projectIdentity,
      typeRelations: scopedRelations,
    }));
  });
}

function workspaceRelationKey(workspaceRoot) {
  return workspaceRoot ? `root:${workspaceRoot}` : "<unscoped-workspace>";
}

function flowFunctionFromIR(fn, projectEntries = [], context = {}) {
  const entryPoints = projectEntries.length ? projectEntries : fn.entryPoints || (fn.entryPoint ? [fn.entryPoint] : []);
  return {
    id: fn.id,
    symbolKey: fn.symbolKey,
    name: fn.name,
    enclosingScope: fn.enclosingScope,
    packageName: fn.packageName,
    namespaceName: fn.namespaceName,
    qualifiedEnclosingScope: fn.qualifiedEnclosingScope || fn.enclosingScope,
    implementedTypes: fn.implementedTypes || [],
    declarationKind: fn.declarationKind || "function",
    executable: fn.executable !== false,
    parameters: fn.parameters.map(value => value.name),
    parameterDetails: fn.parameters.map((value, index) => ({
      name: value.name,
      type: value.type,
      role: value.role,
      parameterIndex: value.parameterIndex ?? index,
      bindings: value.bindings || [],
      captured: Boolean(value.captured),
      annotations: value.annotations || [],
      cascadedValidation: Boolean(value.cascadedValidation),
    })),
    line: fn.location.line,
    endLine: fn.location.endLine,
    language: fn.language,
    absolutePath: fn.location.absolutePath,
    relativePath: fn.location.relativePath,
    isEntry: entryPoints.length > 0,
    entryTitle: entryPoints[0]?.title || fn.entryPoint?.title,
    entryPoints,
    isGlobal: fn.isGlobal,
    references: fn.references || [],
    workspaceRoot: context.workspaceRoot,
    projectIdentity: context.projectIdentity,
    typeRelations: context.typeRelations || [],
    cfg: fn.cfg,
    events: fn.operations.map(operationFromIR),
  };
}

function operationFromIR(operation) {
  const capabilities = operation.semantic.guardCapabilities || [];
  const isAuthorization = capabilities.includes(GuardCapability.AUTHENTICATION) || capabilities.includes(GuardCapability.AUTHORIZATION);
  return {
    id: operation.id,
    type: operation.kind === OperationKind.GUARD ? "control" : operation.kind,
    line: operation.location.line,
    startOffset: operation.location.startOffset,
    endOffset: operation.location.endOffset,
    code: operation.location.code,
    variables: operation.inputs.length ? operation.inputs.map(value => value.name) :
      operation.kind === OperationKind.SOURCE && operation.output?.name ? [operation.output.name] : [],
    target: operation.output?.name,
    label: operation.semantic.label,
    category: operation.semantic.category || operation.metadata.category,
    sourceKind: operation.semantic.sourceKind,
    sourceExposure: operation.semantic.exposure,
    sinkKind: operation.semantic.sinkKind,
    guardCapabilities: capabilities,
    controlKind: operation.kind === OperationKind.GUARD ? (isAuthorization ? "auth" : "sanitizer") : undefined,
    callee: operation.call?.function,
    targetFunctionId: operation.call?.targetFunctionId,
    closure: Boolean(operation.call?.closure || operation.metadata.closure),
    asyncBoundary: Boolean(operation.metadata.asyncBoundary),
    receiver: operation.call?.receiver,
    receiverVariables: (operation.call?.receiverInputs || []).map(value => value.name),
    receiverType: operation.call?.symbol?.receiverType,
    arguments: operation.call?.arguments || [],
    argumentVariables: (operation.call?.argumentInputs || []).map(group => group.map(value => value.name)),
    argumentTypes: operation.call?.argumentTypes || [],
    certainty: operation.certainty,
    semanticModelId: operation.semantic.modelId,
    semanticVerification: operation.metadata.semanticVerification,
    candidateStatus: operation.metadata.candidateStatus,
    taintArgumentIndexes: operation.metadata.taintArguments,
    assignmentMode: operation.metadata.assignmentMode,
    propagationReason: operation.metadata.propagationReason,
    propagationStatus: operation.metadata.propagationStatus,
    receiverPropagation: operation.metadata.receiverPropagation,
    blockId: operation.metadata.blockId,
    reachable: operation.metadata.reachable,
    guardAppliesToBlocks: operation.metadata.guardAppliesToBlocks,
    guardDominance: operation.metadata.guardDominance,
    guardBinding: operation.metadata.guardBinding,
    functionAnnotation: Boolean(operation.metadata.functionAnnotation),
  };
}

module.exports = { flowFunctionFromIR, functionsFromAnalyses, operationFromIR };
