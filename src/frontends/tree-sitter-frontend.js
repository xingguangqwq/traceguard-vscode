"use strict";

const { buildSymbolKey, parameterDescriptors, splitParameters, stableHash, symbolId } = require("../identity");
const { normalizeAccessPath } = require("../ir/access-path");
const { Certainty, OperationKind, fileIR, functionIR, location, operation, symbol } = require("../ir/schema");
const { GuardCapability, SinkKind, guardAssociation, semanticForSignal } = require("../security/semantics");
const { buildOperationCFG, compareOperations } = require("../dataflow/cfg");
const { collectSignals, findEntries } = require("./pattern-parser");
const { extractFileReferences, extractIdentifiers, splitArguments } = require("./syntax-tools");
const { runtime } = require("./tree-sitter-runtime");
const { classifyFrameworkCall, dedupeFrameworkEntries, frameworkEntry, frameworkParameterRoles, inferParameterRoles, mergeFrameworkEntries, stringLiterals } = require("./framework-entries");
const { resolveSemanticCall, SemanticRole } = require("../security/semantic-models");

const FUNCTION_TYPES = Object.freeze({
  java: new Set(["method_declaration", "constructor_declaration", "lambda_expression"]),
  python: new Set(["function_definition", "lambda"]),
  php: new Set(["function_definition", "method_declaration", "anonymous_function", "arrow_function"]),
  csharp: new Set(["method_declaration", "constructor_declaration", "local_function_statement", "lambda_expression", "anonymous_method_expression"]),
  go: new Set(["function_declaration", "method_declaration", "func_literal"]),
});

const TYPE_TYPES = new Set([
  "class_declaration", "interface_declaration", "enum_declaration", "record_declaration", "struct_declaration", "namespace_declaration",
]);
const CALL_TYPES = new Set([
  "call", "call_expression", "function_call_expression", "member_call_expression", "scoped_call_expression", "method_invocation", "invocation_expression", "object_creation_expression",
]);
const ASSIGNMENT_TYPES = new Set([
  "assignment", "assignment_expression", "augmented_assignment", "short_var_declaration", "variable_declarator",
]);
const LOOP_TYPES = new Set([
  "while_statement", "do_statement", "for_statement", "foreach_statement", "enhanced_for_statement",
]);
const BRANCH_TYPES = new Set(["if_statement", "switch_statement", "conditional_expression", ...LOOP_TYPES]);
const TRY_TYPES = new Set(["try_statement", "try_expression"]);
const THROW_TYPES = new Set(["throw_statement", "throw_expression", "raise_statement"]);

class TreeSitterLanguageFrontend {
  constructor(language, capability) {
    this.language = language;
    this.capability = capability;
    this.id = `tree-sitter-${language}`;
  }

  async parse(input) {
    const text = String(input.text || "");
    const lines = text.split(/\r?\n/);
    const parsed = await runtime.parse({ ...input, text, language: this.language });
    const root = parsed.tree.rootNode;
    const signals = collectSignals(lines, this.language);
    const records = collectFunctions(root, this.language, text, input);
    stabilizeDuplicateSymbols(records);
    assignSignals(records, signals, lines);
    const references = extractFileReferences(lines, this.language);
    const functions = records.map(record => buildFunction(record, input, lines, references, text));
    const covered = new Set(records.flatMap(record => record.signals.map(signalKey)));
    const globalSignals = signals.filter(signal => !covered.has(signalKey(signal)));
    if (globalSignals.length) functions.push(buildGlobal(globalSignals, input, lines, references, root));
    const compatibility = records.map(record => ({
      name: record.name,
      parameters: record.parametersText,
      parameterDescriptors: record.parameterDescriptors,
      enclosingScope: record.enclosingScope,
      id: record.id,
      symbolKey: record.symbolKey,
      line: record.line,
      endLine: record.endLine,
      signals: record.signals,
    }));
    const astEntries = dedupeFrameworkEntries([
      ...treeFrameworkEntries(root, records, this.language, text),
      ...(this.language === "java" ? javaFrameworkEntries(records, text) : []),
    ]);
    const entries = mergeFrameworkEntries(
      astEntries,
      findEntries(lines, compatibility, signals, this.language, input.relativePath),
    );
    for (const entry of entries) {
      const record = records.find(candidate => candidate.id === entry.functionId || candidate.symbolKey === entry.symbolKey);
      if (!entry.parameterRoles?.length && record) {
        const roles = frameworkParameterRoles(entry, record.parameterDescriptors);
        entry.parameterRoles = roles.length ? roles : inferParameterRoles(input.language, record.parameterDescriptors);
      }
      const fn = entryFunction(functions, entry);
      if (fn) applyEntryToFunction(fn, entry);
    }
    const recovered = Boolean(root.hasError);
    return fileIR({
      language: this.language,
      absolutePath: input.absolutePath,
      relativePath: input.relativePath,
      lines: lines.length,
      frontend: {
        id: this.id,
        mode: "ast",
        capability: this.capability,
        parser: "tree-sitter-wasm",
        incremental: parsed.incremental,
        treeHasErrors: recovered,
        degraded: recovered,
        degradedReason: recovered ? "Tree-sitter recovered from syntax errors; affected operations use lower confidence." : undefined,
      },
      functions,
      entryPoints: entries.map(entry => {
        const fn = entryFunction(functions, entry);
        return {
          id: stableHash(`${input.relativePath}:entry:${entry.method}:${entry.route}:${fn?.symbolKey || entry.symbolKey || entry.functionId || "global"}`),
          title: entry.title,
          method: entry.method,
          route: entry.route,
          functionId: fn?.id || entry.functionId,
          symbolKey: fn?.symbolKey || entry.symbolKey,
          parameterRoles: entry.parameterRoles || fn?.parameters.map(parameter => parameter.role || "unknown") || [],
          framework: entry.framework,
          handlerIndex: entry.handlerIndex,
          location: location({ ...input, ...entry, code: lines[entry.line - 1] }),
        };
      }),
    });
  }
}

function treeFrameworkEntries(root, records, language, text) {
  const constants = stringConstants(text);
  const entries = [];
  const visit = node => {
    if (CALL_TYPES.has(node.type)) {
      const call = resolveConstantArguments(genericCall(node, text), constants);
      const classification = classifyFrameworkCall(language, call);
      if (classification) {
        const handlerCallNode = classification.chained ? call.receiverCallNode : node;
        const handlerCall = classification.chained ? call.receiverCall : call;
        const argumentsNode = handlerCallNode?.childForFieldName("arguments") || handlerCallNode?.namedChildren?.find(child => /argument/.test(child.type));
        for (const handlerIndex of classification.handlerIndexes) {
          const argumentNode = argumentsNode?.namedChildren?.[handlerIndex];
          for (const target of handlerTargets(argumentNode, handlerCall?.arguments?.[handlerIndex])) {
            const record = treeHandlerRecord(records, target.node, target.text);
            if (!record && !target.node) continue;
            entries.push(frameworkEntry({ ...classification, handlerIndex }, record, treeSourceLocation(target.node || node)));
          }
        }
      }
    }
    for (const child of node.namedChildren || []) visit(child);
  };
  visit(root);
  return dedupeFrameworkEntries(entries);
}

function handlerTargets(argumentNode, argumentText) {
  if (argumentNode && /array/.test(argumentNode.type)) {
    const elementTexts = splitArguments(String(argumentText || "").replace(/^\[/, "").replace(/\]$/, ""));
    return (argumentNode.namedChildren || []).map((element, index) => ({
      node: element,
      text: elementTexts[index] ?? nodeText(element),
    }));
  }
  return [{ node: argumentNode, text: argumentText }];
}

function stringConstants(text) {
  const constants = new Map();
  for (const match of String(text || "").matchAll(/\b(?:const|let|var|final)\s+([A-Za-z_$][\w$]*)\s*[:=]\s*(["'`])((?:\\.|(?!\2)[^\n\\])*)\2/g)) {
    constants.set(match[1], `${match[2]}${match[3]}${match[2]}`);
  }
  return constants;
}

function resolveConstantArguments(call, constants) {
  if (!constants.size || !call) return call;
  const resolve = value => constants.get(String(value || "").trim()) ?? value;
  return {
    ...call,
    arguments: call.arguments?.map(resolve),
    receiverCall: call.receiverCall
      ? { ...call.receiverCall, arguments: call.receiverCall.arguments?.map(resolve) }
      : call.receiverCall,
  };
}

function treeHandlerRecord(records, argumentNode, argumentText) {
  const inline = argumentNode && records
    .filter(record => containsTreeNode(argumentNode, record.node))
    .sort((left, right) => (left.node.endIndex - left.node.startIndex) - (right.node.endIndex - right.node.startIndex))[0];
  if (inline) return inline;
  const name = String(argumentText || "").trim().match(/[A-Za-z_$][\w$]*$/)?.[0];
  return name ? records.find(record => record.name === name) : undefined;
}

function treeSourceLocation(node) {
  return {
    line: node.startPosition.row + 1,
    endLine: node.endPosition.row + 1,
    startColumn: node.startPosition.column + 1,
    endColumn: node.endPosition.column + 1,
    startOffset: node.startIndex,
    endOffset: node.endIndex,
  };
}

function collectFunctions(root, language, text, input) {
  const result = [];
  const visit = node => {
    if (FUNCTION_TYPES[language]?.has(node.type)) result.push(describeFunction(node, language, text, input));
    for (const child of node.namedChildren || []) visit(child);
  };
  visit(root);
  return result;
}

function describeFunction(node, language, text, input) {
  const nameNode = node.childForFieldName("name");
  const parametersNode = node.childForFieldName("parameters");
  const parametersText = stripParens(nodeText(parametersNode, text));
  const rawParameters = splitParameters(parametersText);
  const descriptors = parameterDescriptors(parametersText, language).map((descriptor, index) => ({ ...descriptor, raw: rawParameters[index] || "" }));
  const name = nodeText(nameNode, text) || anonymousName(node, text);
  const enclosingScope = enclosingScopeFor(node, language, text);
  const discriminator = anonymousDiscriminator(node, language, text);
  const typeInfo = language === "java" ? javaEnclosingTypeInfo(node, text) : {};
  const symbolKey = buildSymbolKey({
    language,
    absolutePath: input.absolutePath,
    relativePath: input.relativePath,
    kind: "function",
    enclosingScope,
    name,
    parameterDescriptors: descriptors,
    discriminator,
  });
  return {
    node,
    id: symbolId(symbolKey),
    symbolKey,
    name,
    parametersText,
    parameterDescriptors: descriptors,
    enclosingScope,
    line: node.startPosition.row + 1,
    endLine: node.endPosition.row + 1,
    signals: [],
    discriminator,
    ...typeInfo,
    executable: Boolean(node.childForFieldName("body")) || node.type === "lambda_expression",
  };
}

function buildFunction(record, input, lines, references, text) {
  const operations = buildOperations(record, input, lines, text, references);
  return functionIR({
    id: record.id,
    symbolKey: record.symbolKey,
    name: record.name,
    language: input.language,
    enclosingScope: record.enclosingScope,
    implementedTypes: record.implementedTypes || [],
    declarationKind: record.declarationKind,
    executable: record.executable,
    signature: `${record.name}(${record.parameterDescriptors.map(parameter => parameter.type).join(",")})`,
    location: location({ ...input, ...treeSourceLocation(record.node), code: lines[record.line - 1] }),
    parameters: record.parameterDescriptors.map(parameter => symbol(parameter.name, parameter.type, parameter.role)),
    operations,
    cfg: buildOperationCFG(operations),
    references,
  });
}

function buildOperations(record, input, lines, text, references = []) {
  const operations = signalOperations(record, input, lines, text, references);
  const seen = new Set(operations.map(item => `${item.kind}:${item.location.startOffset ?? item.location.line}:${item.output?.name || item.call?.function || ""}`));
  const add = (kind, node, fields = {}) => {
    const line = node.startPosition.row + 1;
    const code = lines[line - 1]?.trim() || nodeText(node, text);
    const sourceLocation = treeSourceLocation(node);
    const key = `${kind}:${sourceLocation.startOffset}:${fields.output?.name || fields.call?.function || ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    operations.push(operation({
      id: stableHash(`${record.symbolKey}:${key}:${stableHash(nodeText(node, text), 12)}`),
      kind,
      functionId: record.id,
      location: location({ ...input, ...sourceLocation, code }),
      inputs: fields.inputs || [],
      output: fields.output,
      call: fields.call,
      semantic: fields.semantic || {},
      certainty: fields.certainty || Certainty.HIGH,
      metadata: { frontend: "tree-sitter-wasm", ...(fields.metadata || {}) },
    }));
  };
  if (input.language === "java") {
    for (const annotation of javaSecurityAnnotations(record, text)) {
      add(OperationKind.SINK, annotation.node, {
        inputs: annotation.inputs.map(name => symbol(name)),
        semantic: {
          modelId: annotation.modelId,
          modelRole: SemanticRole.SINK,
          sinkKind: annotation.sinkKind,
          category: annotation.category,
          label: annotation.label,
        },
        certainty: Certainty.HIGH,
        metadata: {
          semanticVerification: "syntax",
          functionAnnotation: true,
          annotationKind: annotation.kind,
        },
      });
    }
  }
  const visit = node => {
    if (node !== record.node && FUNCTION_TYPES[input.language]?.has(node.type)) return;
    if (ASSIGNMENT_TYPES.has(node.type)) {
      const left = node.childForFieldName("left") || node.childForFieldName("name") || node.namedChildren?.[0];
      const right = node.childForFieldName("right") || node.childForFieldName("value") || node.namedChildren?.at(-1);
      const target = assignmentTarget(nodeText(left, text));
      if (target && right && right !== left) add(OperationKind.ASSIGNMENT, node, {
        inputs: expressionInputs(nodeText(right, text), input.language).map(symbol),
        output: symbol(target),
        metadata: { assignmentMode: normalizeAccessPath(nodeText(right, text)) ? "alias" : "aggregate" },
      });
    }
    if (CALL_TYPES.has(node.type)) {
      const call = genericCall(node, text);
      call.argumentInputs = call.arguments.map(argument => expressionInputs(argument, input.language).map(symbol));
      call.argumentTypes = call.arguments.map(argument => inferExpressionType(argument, record, references));
      call.symbol = genericCallIdentity(call, record, references);
      const output = enclosingCallOutput(node, text, input.language);
      const modeled = genericModeledCall(call, input.language, output, input.options?.semanticModels);
      if (call.function) add(OperationKind.CALL, node, {
        inputs: modeled?.kind === OperationKind.CALL ? modeled.inputs : call.argumentInputs.flat(),
        output,
        call,
        semantic: modeled?.kind === OperationKind.CALL ? modeled.semantic : undefined,
        certainty: modeled?.kind === OperationKind.CALL ? modeled.certainty : undefined,
        metadata: modeled?.kind === OperationKind.CALL ? modeled.metadata : undefined,
      });
      if (modeled && modeled.kind !== OperationKind.CALL) add(modeled.kind, node, {
        inputs: modeled.inputs,
        output: modeled.output,
        call,
        semantic: modeled.semantic,
        certainty: modeled.certainty,
        metadata: modeled.metadata,
      });
    }
    if (node.type === "return_statement") add(OperationKind.RETURN, node, {
      inputs: normalizedIdentifiers(nodeText(node, text).replace(/^\s*return\b/, "")).map(symbol),
    });
    if (THROW_TYPES.has(node.type)) add(OperationKind.THROW, node, {
      inputs: normalizedIdentifiers(nodeText(node, text).replace(/^\s*(?:throw|raise)\b/, "")).map(symbol),
    });
    if (node.type === "break_statement") add(OperationKind.BREAK, node);
    if (node.type === "continue_statement") add(OperationKind.CONTINUE, node);
    if (BRANCH_TYPES.has(node.type)) {
      const branch = genericBranchMetadata(node, text, LOOP_TYPES.has(node.type) ? "loop" : "branch");
      add(OperationKind.BRANCH, node, {
        inputs: normalizedIdentifiers(branch.condition).map(symbol),
        metadata: { branch },
      });
    }
    if (TRY_TYPES.has(node.type)) {
      const branch = genericTryMetadata(node, text);
      add(OperationKind.BRANCH, node, {
        inputs: [],
        metadata: { branch },
      });
    }
    for (const child of node.namedChildren || []) visit(child);
  };
  visit(record.node.childForFieldName("body") || record.node);
  const modeledSinks = operations.filter(item => item.kind === OperationKind.SINK && item.semantic.modelId);
  return operations.filter(item => {
    if (item.kind !== OperationKind.SINK || item.semantic.modelId) return true;
    return !modeledSinks.some(modeled => modeled.location.line === item.location.line && modeled.semantic.sinkKind === item.semantic.sinkKind);
  }).sort(compareOperations);
}

function signalOperations(record, input, lines, text, references = []) {
  const occurrences = new Map();
  return record.signals.flatMap(signal => {
    const code = signal.code || lines[signal.line - 1]?.trim() || "";
    const kind = signal.kind === "source" ? OperationKind.SOURCE : signal.kind === "sink" ? OperationKind.SINK : OperationKind.GUARD;
    const semantic = genericSemanticValues(signal, record.node, text, input.language);
    if (!semantic.resolved && hasNestedFunctionOnLine(record.node, input.language, signal.line)) return [];
    const assignment = semantic.output ? undefined : assignmentFromLine(code, input.language);
    const names = semantic.resolved
      ? semantic.inputs
      : signal.kind === "source" && assignment?.target ? [assignment.target] : normalizedIdentifiers(code);
    const fingerprint = `${kind}:${signal.category}:${signal.label}:${stableHash(code, 12)}`;
    const occurrence = occurrences.get(fingerprint) || 0;
    occurrences.set(fingerprint, occurrence + 1);
    const signalSemantic = semanticForSignal(signal);
    const call = semantic.node && CALL_TYPES.has(semantic.node.type) ? genericCall(semantic.node, text) : undefined;
    if (call) call.symbol = genericCallIdentity(call, record, references);
    const expectedRole = signal.kind === "sink" ? SemanticRole.SINK :
      ["sanitizer", "auth"].includes(signal.kind) ? SemanticRole.GUARD : undefined;
    const modelResolution = expectedRole && call ? resolveSemanticCall(input.language, call, input.options?.semanticModels) : { status: "none" };
    const matchingModel = Boolean(expectedRole && modelResolution.model?.role === expectedRole);
    if (modelResolution.status === "rejected" && signal.kind === "sink") return [];
    if (matchingModel && ["verified", "syntax"].includes(modelResolution.status)) {
      const model = modelResolution.model;
      signalSemantic.modelId = model.id;
      signalSemantic.modelRole = model.role;
      signalSemantic.sinkKind = model.sinkKind;
      signalSemantic.category = model.category;
      signalSemantic.guardCapabilities = model.guardCapabilities || signalSemantic.guardCapabilities;
    }
    const taintArguments = matchingModel ? genericTaintArguments(modelResolution.model, call) : undefined;
    const operationInputs = matchingModel
      ? taintArguments.flatMap(index => call.argumentInputs[index] || []).map(value => value.name)
      : names;
    const guardVerification = matchingModel ? modelResolution.status :
      modelResolution.status === "rejected" ? "rejected" :
        structurallyParameterizedGuard(signalSemantic.guardCapabilities, call) ? "structural" : undefined;
    const guardBinding = kind === OperationKind.GUARD
      ? buildGenericGuardBinding(signalSemantic.guardCapabilities, semantic, call, guardVerification)
      : undefined;
    return [operation({
      id: stableHash(`${record.symbolKey}:${fingerprint}:${occurrence}`),
      kind,
      functionId: record.id,
      location: location({
        ...input,
        ...(semantic.node ? treeSourceLocation(semantic.node) : { line: signal.line }),
        code,
      }),
      inputs: operationInputs.map(symbol),
      output: semantic.output ? symbol(semantic.output) : signal.kind === "source" && assignment?.target ? symbol(assignment.target) : undefined,
      call,
      semantic: signalSemantic,
      certainty: ["verified", "syntax"].includes(modelResolution.status) ? Certainty.MEDIUM :
        signal.kind === "sink" ? Certainty.LOW : semantic.resolved ? Certainty.MEDIUM : Certainty.LOW,
      metadata: {
        category: signal.category,
        controlKind: signal.kind,
        frontend: "tree-sitter-pattern-candidate",
        candidateStatus: ["verified", "syntax"].includes(modelResolution.status) ? "symbol-verified" :
          semantic.resolved ? "ast-validated-symbol-unverified" : "unverified",
        semanticVerification: modelResolution.status === "none" ? undefined : modelResolution.status,
        modelCandidates: modelResolution.candidates || [],
        taintArguments,
        guardBinding,
      },
    })];
  });
}

function hasNestedFunctionOnLine(rootNode, language, line) {
  const visit = node => {
    if (node !== rootNode && FUNCTION_TYPES[language]?.has(node.type)) {
      return node.startPosition.row + 1 <= line && node.endPosition.row + 1 >= line;
    }
    return (node.namedChildren || []).some(visit);
  };
  return visit(rootNode);
}

function buildGlobal(signals, input, lines, references, rootNode) {
  const symbolKey = buildSymbolKey({ language: input.language, absolutePath: input.absolutePath, relativePath: input.relativePath, kind: "global", enclosingScope: "<file>", name: "global scope", parameterDescriptors: [] });
  const record = { id: symbolId(symbolKey), symbolKey, signals, node: rootNode, parameterDescriptors: [] };
  const operations = signalOperations(record, input, lines, lines.join("\n"), references);
  return functionIR({
    id: record.id,
    symbolKey,
    name: "global scope",
    language: input.language,
    enclosingScope: "<file>",
    location: location({ ...input, line: 1, endLine: lines.length }),
    parameters: [],
    operations,
    cfg: buildOperationCFG(operations),
    references,
    isGlobal: true,
  });
}

function genericCall(node, text) {
  const functionNode = node.childForFieldName("function");
  const nameNode = node.childForFieldName("name");
  const callableNode = functionNode || nameNode || node.namedChildren?.[0];
  const objectNode = node.childForFieldName("object") || node.childForFieldName("scope") ||
    callableNode?.childForFieldName?.("expression") || callableNode?.childForFieldName?.("operand") || callableNode?.childForFieldName?.("object");
  const callable = nodeText(callableNode, text);
  const parts = callable.split(/(?:\.|->|::)/).filter(Boolean);
  const argumentNode = node.childForFieldName("arguments") || node.namedChildren?.find(child => /argument/.test(child.type));
  const rawArguments = stripParens(nodeText(argumentNode, text));
  const args = splitArguments(rawArguments);
  return {
    function: nodeText(nameNode, text) || parts.at(-1) || callable,
    form: node.type === "object_creation_expression" ? "constructor" : callFormFromReceiver(objectNode),
    receiver: nodeText(objectNode, text) || (parts.length > 1 ? parts.slice(0, -1).join(".") : undefined),
    arguments: args,
    argumentInputs: args.map(argument => normalizedIdentifiers(argument).map(symbol)),
    argumentTypes: args.map(inferExpressionType),
    receiverCall: objectNode && CALL_TYPES.has(objectNode.type) ? genericCall(objectNode, text) : undefined,
    receiverCallNode: objectNode && CALL_TYPES.has(objectNode.type) ? objectNode : undefined,
  };
}

function genericCallIdentity(call, record, references = []) {
  const receiverRoot = String(call.receiver || "").match(/^[A-Za-z_$][\w$]*/)?.[0];
  const receiverType = receiverRoot
    ? record.parameterDescriptors?.find(parameter => parameter.name === receiverRoot)?.type
    : undefined;
  const imported = references.find(reference => reference.local === receiverRoot || (!call.receiver && reference.local === call.function));
  return {
    kind: imported ? "import" : "syntax",
    moduleName: imported?.target,
    exportName: call.function,
    qualifiedName: imported ? `${imported.target}.${call.function}` : call.receiver ? `${call.receiver}.${call.function}` : call.function,
    receiverType: receiverType || (imported?.kind === "type" ? imported.target : undefined) ||
      (call.form === "constructor" ? call.function : undefined) || call.receiver,
    shadowed: false,
    verified: Boolean(imported || (receiverType && receiverType !== "?")),
  };
}

function callFormFromReceiver(receiverNode) {
  return receiverNode ? "instance-method" : "function";
}

function genericModeledCall(call, language, output, semanticModels) {
  const resolution = resolveSemanticCall(language, call, semanticModels);
  if (!["verified", "syntax"].includes(resolution.status)) return undefined;
  const model = resolution.model;
  const kind = {
    [SemanticRole.SOURCE]: OperationKind.SOURCE,
    [SemanticRole.SINK]: OperationKind.SINK,
    [SemanticRole.PROPAGATOR]: OperationKind.CALL,
    [SemanticRole.GUARD]: OperationKind.GUARD,
  }[model.role];
  if (!kind) return undefined;
  const taintArguments = genericTaintArguments(model, call);
  const inputs = taintArguments.flatMap(index => call.argumentInputs[index] || []);
  const guardBinding = model.role === SemanticRole.GUARD ? {
    capabilities: model.guardCapabilities || [],
    inputs: inputs.map(value => value.name),
    output: output?.name,
    receiver: call.receiver,
    trustedOperands: (call.arguments || []).map((expression, index) => ({ expression, index }))
      .filter(item => /^\s*(?:["'`].*["'`]|\d+)\s*$/.test(item.expression)),
    semanticVerification: resolution.status,
    ...guardAssociation(model.guardCapabilities || []),
  } : undefined;
  return {
    kind,
    inputs,
    output: model.returnsTaint || model.role === SemanticRole.GUARD ? output : undefined,
    semantic: {
      modelId: model.id,
      modelRole: model.role,
      sourceKind: model.sourceKind,
      sinkKind: model.sinkKind,
      category: model.category,
      guardCapabilities: model.guardCapabilities || [],
      label: model.id,
    },
    certainty: Certainty.MEDIUM,
    metadata: {
      frontend: "tree-sitter-semantic-registry",
      semanticVerification: resolution.status,
      taintArguments,
      guardBinding,
    },
  };
}

function genericTaintArguments(model, call) {
  const result = [...model.taintArguments];
  if (Number.isInteger(model.taintRestFrom)) {
    for (let index = model.taintRestFrom; index < call.argumentInputs.length; index += 1) result.push(index);
  }
  return [...new Set(result)];
}

function enclosingCallOutput(node, text, language) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (ASSIGNMENT_TYPES.has(parent.type)) {
      const left = parent.childForFieldName("left") || parent.childForFieldName("name") || parent.namedChildren?.[0];
      const target = assignmentTarget(nodeText(left, text));
      return target ? symbol(target) : undefined;
    }
    if (/statement|declaration/.test(parent.type) || FUNCTION_TYPES[language]?.has(parent.type)) break;
  }
  return undefined;
}

function genericSemanticValues(signal, rootNode, text, language) {
  if (!rootNode) return { inputs: [], resolved: false };
  const candidates = [];
  const visit = node => {
    if (node !== rootNode && FUNCTION_TYPES[language]?.has(node.type)) return;
    if (node.startPosition?.row + 1 === signal.line && isSemanticExpression(node)) {
      const matches = collectSignals([semanticCandidateText(node, text)], language).some(candidate =>
        candidate.kind === signal.kind && candidate.category === signal.category,
      );
      if (matches) candidates.push(node);
    }
    for (const child of node.namedChildren || []) visit(child);
  };
  visit(rootNode);
  const node = candidates.sort((left, right) =>
    Number(CALL_TYPES.has(right.type)) - Number(CALL_TYPES.has(left.type)) ||
      (left.endIndex - left.startIndex) - (right.endIndex - right.startIndex),
  )[0];
  if (!node) return { inputs: [], resolved: false };
  if (signal.kind === "sink" || signal.kind === "sanitizer" || signal.kind === "auth") {
    if (CALL_TYPES.has(node.type)) {
      const call = genericCall(node, text);
      const receiverInputs = call.receiver ? normalizedIdentifiers(call.receiver) : [];
      return {
        inputs: [...new Set([...receiverInputs, ...call.argumentInputs.flat().map(item => item.name)])],
        output: signal.kind === "sanitizer" ? enclosingCallOutput(node, text, language)?.name : undefined,
        resolved: true,
        node,
      };
    }
    return { inputs: normalizedIdentifiers(nodeText(node, text)), resolved: true, node };
  }
  const output = enclosingCallOutput(node, text, language)?.name;
  return {
    inputs: output ? [output] : normalizedIdentifiers(nodeText(node, text)),
    output,
    resolved: true,
    node,
  };
}

function semanticCandidateText(node, text) {
  if (!CALL_TYPES.has(node.type)) return nodeText(node, text);
  const call = genericCall(node, text);
  const directArguments = call.arguments.filter(argument => !/(?:=>|\bfunction\s*\(|\bfunc\s*\()/i.test(argument));
  return `${call.receiver ? `${call.receiver}.` : ""}${call.function}(${directArguments.join(", ")})`;
}

function buildGenericGuardBinding(capabilities = [], semantic = {}, call, semanticVerification) {
  return {
    capabilities,
    inputs: semantic.inputs || [],
    output: semantic.output,
    receiver: call?.receiver,
    trustedOperands: (call?.arguments || []).map((expression, index) => ({ expression, index }))
      .filter(item => /^\s*(?:["'`].*["'`]|\d+)\s*$/.test(item.expression)),
    semanticVerification,
    allowsBoundParameters: semanticVerification === "structural",
    ...guardAssociation(capabilities),
  };
}

function structurallyParameterizedGuard(capabilities = [], call) {
  if (!capabilities.includes(GuardCapability.SQL_PARAMETERIZATION) || (call?.arguments || []).length < 2) return false;
  const query = String(call.arguments[0] || "").trim();
  return /^(?:[rubf]{0,2})?["'`]/i.test(query) && /(?:\?|\$\d+|%s|%\([^)]+\)s|:[A-Za-z_]\w*)/.test(query);
}

function isSemanticExpression(node) {
  return CALL_TYPES.has(node.type) || /(?:member|field|attribute|access|subscript|expression)$/.test(node.type);
}

function assignmentFromLine(code, language) {
  const match = language === "php"
    ? String(code).match(/^\s*(\$[A-Za-z_]\w*(?:->\w+)*)\s*=/)
    : String(code).match(/^\s*(?:const|let|var|final|[A-Za-z_][\w<>,.?\[\]]*\s+)?([A-Za-z_$][\w$]*(?:[.][A-Za-z_$][\w$]*)*)\s*(?::=|=)/);
  return match ? { target: match[1] } : undefined;
}

function assignmentTarget(value) {
  const text = String(value || "").trim();
  const candidate = text.match(/\$?[A-Za-z_][\w$]*(?:(?:\.|->)[A-Za-z_]\w*|\[[^\]]+\])*$/)?.[0];
  return normalizeAccessPath(candidate);
}

function enclosingScopeFor(node, language, text) {
  const names = [];
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (TYPE_TYPES.has(parent.type)) {
      const name = nodeText(parent.childForFieldName("name"), text);
      if (name) names.unshift(name);
    } else if (FUNCTION_TYPES[language]?.has(parent.type)) {
      const name = nodeText(parent.childForFieldName("name"), text) || anonymousName(parent, text);
      if (name) names.unshift(name);
    }
  }
  if (language === "go" && node.type === "method_declaration") {
    const receiver = nodeText(node.childForFieldName("receiver"), text).match(/\*?([A-Za-z_]\w*)\s*\)?$/)?.[1];
    if (receiver) names.push(receiver);
  }
  return names.join(".") || "<file>";
}

function anonymousName(node, text) {
  const callNode = enclosingCallNode(node);
  const call = callNode ? genericCall(callNode, text) : undefined;
  return call?.function ? `${call.function}$callback` : "anonymous";
}

function anonymousDiscriminator(node, language, text) {
  if (node.childForFieldName("name")) return undefined;
  const callNode = enclosingCallNode(node);
  if (!callNode) return `${node.type}:${stableHash(nodeText(node, text).replace(/\s+/g, " "), 16)}`;
  const call = genericCall(callNode, text);
  const prefix = String(text).slice(callNode.startIndex, node.startIndex);
  const semanticLiterals = [...prefix.matchAll(/["'`]([^"'`]+)["'`]/g)].map(match => match[1]);
  const argumentNode = callNode.childForFieldName("arguments") || callNode.namedChildren?.find(child => /argument/.test(child.type));
  const argumentIndex = Math.max(0, (argumentNode?.namedChildren || []).findIndex(child => containsTreeNode(child, node)));
  return `${language}:${call.receiver ? `${call.receiver}.` : ""}${call.function}#argument:${argumentIndex}${semanticLiterals.length ? `:${semanticLiterals.join("|")}` : ""}`;
}

function enclosingCallNode(node) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (CALL_TYPES.has(parent.type)) return parent;
    if (/statement|declaration/.test(parent.type) || Object.values(FUNCTION_TYPES).some(types => types.has(parent.type))) break;
  }
  return undefined;
}

function containsTreeNode(parent, child) {
  return child.startIndex >= parent.startIndex && child.endIndex <= parent.endIndex;
}

function stabilizeDuplicateSymbols(records) {
  const occurrences = new Map();
  for (const record of records) {
    const occurrence = occurrences.get(record.symbolKey) || 0;
    occurrences.set(record.symbolKey, occurrence + 1);
    if (!occurrence) continue;
    record.symbolKey = `${record.symbolKey}::duplicate:${occurrence}`;
    record.id = symbolId(record.symbolKey);
  }
}

function genericBranchMetadata(node, text, controlKind = "branch") {
  const conditionNode = node.childForFieldName("condition") || node.childForFieldName("condition_clause") || node.namedChildren?.[0];
  const thenNode = node.childForFieldName("consequence") || node.childForFieldName("body");
  const elseNode = node.childForFieldName("alternative");
  return {
    controlKind,
    condition: nodeText(conditionNode, text),
    conditionRange: treeNodeRange(conditionNode),
    thenRange: treeNodeRange(thenNode),
    elseRange: treeNodeRange(elseNode),
  };
}

function genericTryMetadata(node, text) {
  const children = node.namedChildren || [];
  const body = node.childForFieldName("body") || children.find(child => /(?:block|compound_statement)$/.test(child.type));
  const handlers = children.filter(child => /^(?:catch|except)_clause$/.test(child.type));
  const elseClause = children.find(child => child.type === "else_clause");
  const finallyClause = children.find(child => child.type === "finally_clause");
  return {
    controlKind: "try",
    condition: "try",
    thenRange: treeNodeRange(body),
    catchRanges: handlers.map(treeNodeRange).filter(Boolean),
    elseRange: treeNodeRange(elseClause),
    finallyRange: treeNodeRange(finallyClause),
    conditionRange: treeNodeRange(node.childForFieldName("resources")),
    syntax: nodeText(node, text).slice(0, 80),
  };
}

function javaEnclosingTypeInfo(node, text) {
  const typeNode = enclosingJavaTypeNode(node);
  if (!typeNode) return { declarationKind: "java-method", implementedTypes: [] };
  const relationNodes = (typeNode.namedChildren || []).filter(child =>
    /(?:superclass|super_interfaces|extends_interfaces|type_list)/.test(child.type));
  const implementedTypes = relationNodes.flatMap(child =>
    extractIdentifiers(nodeText(child, text)).filter(name => !["extends", "implements"].includes(name)));
  return {
    declarationKind: typeNode.type.replace(/_declaration$/, ""),
    implementedTypes: [...new Set(implementedTypes)],
  };
}

function enclosingJavaTypeNode(node) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (["class_declaration", "interface_declaration", "record_declaration", "enum_declaration"].includes(parent.type)) return parent;
  }
  return undefined;
}

function javaFrameworkEntries(records, text) {
  const entries = [];
  for (const record of records) {
    if (record.node.type !== "method_declaration") continue;
    const methodAnnotations = javaAnnotations(record.node, text);
    const typeNode = enclosingJavaTypeNode(record.node);
    const typeAnnotations = javaAnnotations(typeNode, text);
    const classRoutes = mappingRoutes(typeAnnotations.filter(annotation => ["RequestMapping", "Path"].includes(annotation.name)));
    const mappings = javaMethodMappings(methodAnnotations);
    const servletMethod = /^do(Get|Post|Put|Delete|Patch)$/i.exec(record.name);
    if (!mappings.length && servletMethod && (record.implementedTypes || []).some(type => /HttpServlet$/i.test(type))) {
      mappings.push({ method: servletMethod[1].toUpperCase(), routes: [""], framework: "servlet", node: record.node });
    }
    for (const mapping of mappings) {
      const methodRoutes = mapping.routes.length ? mapping.routes : [""];
      const parents = classRoutes.length ? classRoutes : [""];
      for (const parentRoute of parents) for (const methodRoute of methodRoutes) {
        entries.push(frameworkEntry({
          method: mapping.method,
          route: joinJavaRoute(parentRoute, methodRoute),
          framework: mapping.framework,
          language: "java",
        }, record, treeSourceLocation(mapping.node || record.node)));
      }
    }
  }
  return dedupeFrameworkEntries(entries);
}

function javaMethodMappings(annotations) {
  const result = [];
  for (const annotation of annotations) {
    const direct = /^(Get|Post|Put|Delete|Patch)Mapping$/.exec(annotation.name);
    if (direct) {
      result.push({ method: direct[1].toUpperCase(), routes: annotationRoutes(annotation), framework: "spring", node: annotation.node });
      continue;
    }
    if (annotation.name === "RequestMapping") {
      const methods = [...annotation.raw.matchAll(/RequestMethod\s*\.\s*(GET|POST|PUT|DELETE|PATCH)/g)].map(match => match[1]);
      result.push({ method: methods.length ? [...new Set(methods)].join("|") : "ANY", routes: annotationRoutes(annotation), framework: "spring", node: annotation.node });
      continue;
    }
    if (/^(GET|POST|PUT|DELETE|PATCH)$/.test(annotation.name)) {
      result.push({ method: annotation.name, routes: mappingRoutes(annotations.filter(candidate => candidate.name === "Path")), framework: "jax-rs", node: annotation.node });
    }
  }
  return result;
}

function javaAnnotations(node, text) {
  if (!node) return [];
  const modifiers = (node.namedChildren || []).find(child => child.type === "modifiers");
  if (!modifiers) return [];
  const annotations = [];
  const visit = candidate => {
    if (/^(?:marker_)?annotation$/.test(candidate.type)) {
      const raw = nodeText(candidate, text);
      const name = raw.match(/^@(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)/)?.[1];
      if (name) annotations.push({ name, raw, node: candidate });
      return;
    }
    for (const child of candidate.namedChildren || []) visit(child);
  };
  visit(modifiers);
  return annotations;
}

function annotationRoutes(annotation) {
  const routes = stringLiterals(annotation.raw || "");
  return routes.length ? routes : [""];
}

function mappingRoutes(annotations) {
  return annotations.flatMap(annotationRoutes);
}

function joinJavaRoute(parent, child) {
  const parts = [parent, child].map(value => String(value || "").trim()).filter(Boolean);
  if (!parts.length) return "<dynamic>";
  return "/" + parts.map(value => value.replace(/^\/+|\/+$/g, "")).filter(Boolean).join("/");
}

function javaSecurityAnnotations(record, text) {
  const annotations = javaAnnotations(record.node, text);
  const result = [];
  for (const annotation of annotations) {
    if (!/^(?:Select|Insert|Update|Delete|SelectProvider|InsertProvider|UpdateProvider|DeleteProvider)$/.test(annotation.name)) continue;
    const inputs = [...annotation.raw.matchAll(/\$\{\s*([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\}/g)]
      .map(match => normalizeAccessPath(match[1]) || match[1]);
    if (!inputs.length) continue;
    result.push({
      node: annotation.node,
      inputs: [...new Set(inputs)],
      kind: annotation.name,
      modelId: "java.mybatis.dynamic-sql",
      sinkKind: SinkKind.SQL_QUERY,
      category: "database",
      label: "MyBatis dynamic SQL substitution",
    });
  }
  return result;
}

function inferExpressionType(expression, record, references = []) {
  const value = String(expression || "").trim();
  if (/^(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')$/.test(value)) return "String";
  if (/^(?:true|false)$/.test(value)) return "boolean";
  if (/^-?\d+[lL]$/.test(value)) return "long";
  if (/^-?\d+$/.test(value)) return "int";
  if (/^-?(?:\d+\.\d*|\d*\.\d+)(?:[fFdD])?$/.test(value)) return /[fF]$/.test(value) ? "float" : "double";
  const constructed = /^new\s+([A-Za-z_$][\w$]*)/.exec(value)?.[1];
  if (constructed) return constructed;
  const identifier = /^([A-Za-z_$][\w$]*)$/.exec(value)?.[1];
  if (!identifier) return "?";
  return record?.parameterDescriptors?.find(parameter => parameter.name === identifier)?.type ||
    references.find(reference => reference.kind === "type" && reference.local === identifier)?.target || "?";
}

function treeNodeRange(node) {
  if (!node) return undefined;
  const sourceLocation = treeSourceLocation(node);
  return {
    start: sourceLocation.line,
    end: sourceLocation.endLine,
    startColumn: sourceLocation.startColumn,
    endColumn: sourceLocation.endColumn,
    startOffset: sourceLocation.startOffset,
    endOffset: sourceLocation.endOffset,
  };
}

function entryFunction(functions, entry) {
  return functions.find(candidate => candidate.id === entry.functionId || candidate.symbolKey === entry.symbolKey) ||
    functions.find(candidate => candidate.location.line === entry.functionLine);
}

function applyEntryToFunction(fn, entry) {
  const binding = {
    title: entry.title || fn.name,
    method: entry.method,
    route: entry.route,
    parameterRoles: entry.parameterRoles || [],
    framework: entry.framework,
  };
  fn.entryPoints = [...(fn.entryPoints || []), binding];
  fn.entryPoint ||= binding;
  fn.parameters.forEach((parameter, index) => {
    if (binding.parameterRoles[index]) parameter.role = binding.parameterRoles[index];
  });
}

function assignSignals(records, signals, lines) {
  for (const signal of signals) {
    const containing = records.filter(record => signal.line >= record.line && signal.line <= record.endLine)
      .sort((left, right) => (left.endLine - left.line) - (right.endLine - right.line));
    if (containing[0]) { containing[0].signals.push(signal); continue; }
    if (!/^\s*(?:@|\[)/.test(lines[signal.line - 1] || "")) continue;
    records.filter(record => record.line > signal.line && record.line - signal.line <= 8).sort((a, b) => a.line - b.line)[0]?.signals.push(signal);
  }
}

function nodeText(node, text) { return node ? String(node.text ?? String(text).slice(node.startIndex, node.endIndex)) : ""; }
function normalizedIdentifiers(value) { return extractIdentifiers(value).map(name => normalizeAccessPath(name) || name); }
function expressionInputs(value, language) {
  if (language !== "java") return normalizedIdentifiers(value);
  const accessPaths = [];
  const source = String(value || "");
  for (const match of source.matchAll(/\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\.(?:get|is)([A-Z][A-Za-z0-9_$]*)\s*\(\s*\)/g)) {
    const property = javaBeanProperty(match[2]);
    const path = normalizeAccessPath(`${match[1]}.${property}`);
    if (path) accessPaths.push(path);
  }
  const identifiers = normalizedIdentifiers(source).filter(identifier =>
    !accessPaths.some(path => path === identifier || path.startsWith(`${identifier}.`)) &&
    !/^get[A-Z]|^is[A-Z]/.test(identifier));
  return [...new Set([...accessPaths, ...identifiers])];
}

function javaBeanProperty(value) {
  return /^[A-Z]{2}/.test(value) ? value : value.charAt(0).toLowerCase() + value.slice(1);
}
function stripParens(value) { return String(value || "").trim().replace(/^\(/, "").replace(/\)$/, ""); }
function signalKey(signal) { return [signal.kind, signal.category, signal.line, signal.label].join(":"); }
module.exports = { TreeSitterLanguageFrontend, collectFunctions };
