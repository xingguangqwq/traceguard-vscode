"use strict";

const ts = require("typescript");
const { buildSymbolKey, parameterDescriptors, stableHash, symbolId } = require("../identity");
const { appendAccessPath: appendIRAccessPath, normalizeAccessPath } = require("../ir/access-path");
const { Certainty, OperationKind, ParameterRole, fileIR, functionIR, location, operation, symbol } = require("../ir/schema");
const { GuardCapability, guardAssociation, semanticForSignal } = require("../security/semantics");
const { buildOperationCFG, compareOperations } = require("../dataflow/cfg");
const { collectSignals, findEntries } = require("./pattern-parser");
const { extractAssignment, extractIdentifiers } = require("./syntax-tools");
const { runtime } = require("./tree-sitter-runtime");
const { createCompilerModel, scriptKindFor } = require("./typescript-compiler");
const { classifyFrameworkCall, frameworkEntry, frameworkParameterRoles, inferParameterRoles, mergeFrameworkEntries } = require("./framework-entries");
const { resolveSemanticCall, SemanticRole } = require("../security/semantic-models");

const TREE_FUNCTION_TYPES = new Set([
  "function_declaration", "function_expression", "arrow_function", "method_definition",
  "generator_function_declaration", "generator_function", "required_parameter", "optional_parameter",
]);

class TypeScriptAstFrontend {
  constructor(language) {
    this.language = language;
    this.id = `tree-sitter-typescript-${language}`;
  }

  async parse(input) {
    const text = String(input.text || "");
    const lines = text.split(/\r?\n/);
    const treeResult = await runtime.parse({ ...input, language: this.language, text });
    const compiler = input.options?.compilerModel || createCompilerModel(text, input.absolutePath, this.language);
    const functionNodes = collectFunctionNodes(compiler.sourceFile);
    const signals = collectSignals(lines, this.language);
    const functionRecords = functionNodes.map(node => describeFunction(node, compiler, input));
    stabilizeDuplicateSymbols(functionRecords);
    assignClosureMetadata(functionRecords, compiler);
    assignSignals(functionRecords, signals, lines);
    const references = collectReferences(compiler.sourceFile);
    const functions = functionRecords.map(record => buildFunction(record, compiler, input, lines, references, functionRecords));
    const coveredSignalKeys = new Set(functionRecords.flatMap(record => record.signals.map(signalKey)));
    const globalSignals = signals.filter(signal => !coveredSignalKeys.has(signalKey(signal)));
    if (globalSignals.length) functions.push(buildGlobalFunction(globalSignals, input, lines, references, compiler));

    const compatibilityFunctions = functionRecords.map(record => ({
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
    const astEntries = typescriptFrameworkEntries(compiler, functionRecords, input);
    const entries = mergeFrameworkEntries(
      astEntries,
      findEntries(lines, compatibilityFunctions, signals, this.language, input.relativePath),
    );
    for (const entry of entries) {
      const record = functionRecords.find(candidate => candidate.id === entry.functionId || candidate.symbolKey === entry.symbolKey);
      if (!entry.parameterRoles?.length && record) {
        const roles = frameworkParameterRoles(entry, record.parameterDescriptors);
        entry.parameterRoles = roles.length ? roles : inferParameterRoles(input.language, record.parameterDescriptors);
      }
      const fn = entryFunction(functions, entry);
      if (fn) applyEntryToFunction(fn, entry);
    }
    const treeFunctionCount = countTreeFunctions(treeResult.tree.rootNode);
    const compilerDiagnostics = compiler.sourceFile.parseDiagnostics?.length || 0;
    const treeHasErrors = Boolean(treeResult.tree.rootNode.hasError);
    const degraded = treeHasErrors || compilerDiagnostics > 0;
    const degradedReasons = [
      ...(treeHasErrors ? ["Tree-sitter recovered from syntax errors."] : []),
      ...(compilerDiagnostics ? [`TypeScript Compiler API reported ${compilerDiagnostics} parse diagnostic(s).`] : []),
    ];
    const frontend = {
      id: this.id,
      mode: "ast",
      capability: "tier-b",
      parser: "tree-sitter-wasm+typescript-compiler-api",
      incremental: treeResult.incremental,
      treeHasErrors,
      treeFunctionCount,
      compilerFunctionCount: functionRecords.length,
      compilerDiagnostics,
      compilerProjectMode: Boolean(compiler.projectMode),
      compilerProjectFiles: compiler.projectFileCount || 1,
      compilerProjectGeneration: compiler.projectGeneration || 0,
      compilerStandardLibrary: Boolean(compiler.standardLibrary),
      degraded,
      degradedReason: degradedReasons.join(" ") || undefined,
    };

    return fileIR({
      language: this.language,
      absolutePath: input.absolutePath,
      relativePath: input.relativePath,
      lines: lines.length,
      frontend,
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

function typescriptFrameworkEntries(compiler, records, input) {
  const { sourceFile, checker } = compiler;
  const entries = [];
  const visit = node => {
    if (ts.isCallExpression(node)) {
      const call = callDetails(node, sourceFile, checker);
      const classification = classifyFrameworkCall(input.language, call);
      if (classification) {
        for (const handlerIndex of classification.handlerIndexes || []) {
          const argument = node.arguments[handlerIndex];
          for (const handler of handlerNodes(argument)) {
            const record = handlerRecord(records, handler, handler?.getText(sourceFile), compiler);
            if (!record && !handler) continue;
            entries.push(frameworkEntry({ ...classification, handlerIndex, language: input.language }, record, tsSourceLocation(node, sourceFile)));
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return entries;
}

function handlerNodes(node) {
  if (!node) return [];
  return ts.isArrayLiteralExpression(node) ? node.elements.flatMap(handlerNodes) : [node];
}

function handlerRecord(records, handlerNode, handlerText, compiler) {
  const inline = handlerNode && records
    .filter(record => containsNode(handlerNode, record.node))
    .sort((left, right) => (left.node.end - left.node.pos) - (right.node.end - right.node.pos))[0];
  if (inline) return inline;
  const name = String(handlerText || "").trim().match(/[A-Za-z_$][\w$]*$/)?.[0];
  const local = name ? records.find(record => record.name === name) : undefined;
  if (local) return local;
  const externalNode = resolvedFunctionNode(handlerNode, compiler?.checker);
  if (!externalNode) return undefined;
  const sourceFile = externalNode.getSourceFile();
  const fileInfo = compiler.fileInfoFor?.(sourceFile.fileName);
  if (!fileInfo) return undefined;
  const externalCompiler = { ...compiler, sourceFile };
  const externalRecords = collectFunctionNodes(sourceFile).map(node => describeFunction(node, externalCompiler, fileInfo));
  stabilizeDuplicateSymbols(externalRecords);
  return externalRecords.find(record => record.node === externalNode);
}

function resolvedFunctionNode(node, checker) {
  if (!node || !checker) return undefined;
  const target = ts.isPropertyAccessExpression(node) ? node.name : node;
  let targetSymbol;
  try { targetSymbol = checker.getSymbolAtLocation(target); } catch { return undefined; }
  if (!targetSymbol) return undefined;
  if (targetSymbol.flags & ts.SymbolFlags.Alias) {
    try { targetSymbol = checker.getAliasedSymbol(targetSymbol); } catch {}
  }
  for (const declaration of targetSymbol.declarations || []) {
    if (isFunctionNode(declaration)) return declaration;
    if (ts.isVariableDeclaration(declaration) && declaration.initializer && isFunctionNode(declaration.initializer)) return declaration.initializer;
    if (ts.isPropertyAssignment(declaration) && isFunctionNode(declaration.initializer)) return declaration.initializer;
  }
  return undefined;
}

function tsSourceLocation(node, sourceFile) {
  const startOffset = node.getStart(sourceFile);
  const endOffset = node.end;
  const start = sourceFile.getLineAndCharacterOfPosition(startOffset);
  const end = sourceFile.getLineAndCharacterOfPosition(endOffset);
  return {
    line: start.line + 1,
    endLine: end.line + 1,
    startColumn: start.character + 1,
    endColumn: end.character + 1,
    startOffset,
    endOffset,
  };
}

function collectFunctionNodes(sourceFile) {
  const result = [];
  const visit = node => {
    if (isFunctionNode(node) && node.body) result.push(node);
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return result;
}

function assignClosureMetadata(records, compiler) {
  for (const record of records) {
    const parent = records.filter(candidate => candidate !== record && containsNode(candidate.node, record.node))
      .sort((left, right) => (left.node.end - left.node.pos) - (right.node.end - right.node.pos))[0];
    if (!parent) {
      record.captures = [];
      continue;
    }
    record.closureParentId = parent.id;
    const captures = new Map();
    const visit = node => {
      if (node !== record.node && isFunctionNode(node)) return;
      if (ts.isIdentifier(node)) {
        const symbolValue = checkerSymbol(compiler.checker, node);
        const declaration = symbolValue?.declarations?.find(candidate =>
          containsNode(parent.node, candidate) && !containsNode(record.node, candidate));
        if (declaration && !captures.has(node.text)) {
          captures.set(node.text, {
            name: node.text,
            type: checkerTypeName(compiler.checker, node) || "?",
            declarationLine: nodeLine(declaration, compiler.sourceFile),
          });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(record.node.body || record.node);
    record.captures = [...captures.values()];
  }
}

function closureRecordsForCall(call, parent, records) {
  return records.filter(candidate => candidate.closureParentId === parent.id &&
    call.arguments.some(argument => containsNode(argument, candidate.node)));
}

function describeFunction(node, compiler, input) {
  const { sourceFile, checker } = compiler;
  const name = functionName(node, sourceFile);
  const parametersText = node.parameters.map(parameter => parameter.getText(sourceFile)).join(", ");
  const descriptors = node.parameters.map((parameter, index) => {
    const fallback = parameterDescriptors(parameter.getText(sourceFile), input.language)[0] || { name: `parameter${index}`, type: "?" };
    const bindings = bindingAccessPaths(parameter.name, sourceFile);
    let type = parameter.type?.getText(sourceFile) || fallback.type;
    if (!type || type === "?") {
      try { type = checker.typeToString(checker.getTypeAtLocation(parameter)); } catch { type = "?"; }
    }
    return {
      ...fallback,
      raw: parameter.getText(sourceFile),
      name: ts.isIdentifier(parameter.name) ? parameter.name.text : `parameter${index}`,
      type: !type || type === "any" ? "?" : type,
      optional: Boolean(parameter.questionToken || parameter.initializer),
      variadic: Boolean(parameter.dotDotDotToken),
      parameterIndex: index,
      bindings,
    };
  });
  const enclosingScope = enclosingScopeFor(node, sourceFile);
  const implementedTypes = implementedTypesFor(node, sourceFile);
  const discriminator = callbackDiscriminator(node, sourceFile);
  const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  const end = sourceFile.getLineAndCharacterOfPosition(node.end);
  const symbolKey = buildSymbolKey({
    language: input.language,
    absolutePath: input.absolutePath,
    relativePath: input.relativePath,
    kind: "function",
    enclosingScope,
    implementedTypes,
    name,
    parameterDescriptors: descriptors,
    discriminator,
  });
  return {
    node,
    id: symbolId(symbolKey),
    symbolKey,
    name,
    enclosingScope,
    implementedTypes,
    parametersText,
    parameterDescriptors: descriptors,
    line: start.line + 1,
    endLine: end.line + 1,
    signals: [],
    discriminator,
  };
}

function buildFunction(record, compiler, input, lines, references, records) {
  const operations = operationsFor(record, compiler, input, lines, records);
  const cfg = buildOperationCFG(operations);
  return functionIR({
    id: record.id,
    symbolKey: record.symbolKey,
    name: record.name,
    language: input.language,
    absolutePath: input.absolutePath,
    enclosingScope: record.enclosingScope,
    implementedTypes: record.implementedTypes,
    signature: `${record.name}(${record.parameterDescriptors.map(parameter => parameter.type).join(",")})`,
    location: location({ ...input, ...tsSourceLocation(record.node, compiler.sourceFile), code: lines[record.line - 1] }),
    parameters: [
      ...record.parameterDescriptors.map((parameter, index) => symbol(parameter.name, parameter.type, parameter.role, {
        parameterIndex: parameter.parameterIndex ?? index,
        bindings: parameter.bindings,
      })),
      ...(record.captures || []).map((capture, index) => symbol(capture.name, capture.type, ParameterRole.CAPTURE, {
        parameterIndex: record.parameterDescriptors.length + index,
        captured: true,
      })),
    ],
    operations,
    cfg,
    references,
  });
}

function buildGlobalFunction(signals, input, lines, references, compiler) {
  const symbolKey = buildSymbolKey({
    language: input.language,
    absolutePath: input.absolutePath,
    relativePath: input.relativePath,
    kind: "global",
    enclosingScope: "<file>",
    name: "global scope",
    parameterDescriptors: [],
  });
  return functionIR({
    id: symbolId(symbolKey),
    symbolKey,
    name: "global scope",
    language: input.language,
    enclosingScope: "<file>",
    location: location({ ...input, line: 1, endLine: lines.length }),
    parameters: [],
    operations: signalOperations(signals, symbolKey, symbolId(symbolKey), input, lines, compiler, compiler.sourceFile),
    references,
    isGlobal: true,
  });
}

function operationsFor(record, compiler, input, lines, records = []) {
  const result = signalOperations(record.signals, record.symbolKey, record.id, input, lines, compiler, record.node.body);
  const seen = new Set(result.map(item => `${item.kind}:${item.location.startOffset ?? item.location.line}:${item.output?.name || item.call?.function || ""}`));
  const semanticOccurrences = new Map();
  const add = (kind, node, fields = {}) => {
    const line = nodeLine(node, compiler.sourceFile);
    const code = lines[line - 1]?.trim() || node.getText(compiler.sourceFile);
    const sourceLocation = tsSourceLocation(node, compiler.sourceFile);
    const key = `${kind}:${sourceLocation.startOffset}:${fields.output?.name || fields.call?.function || ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    let operationIdentity = `${record.symbolKey}:${key}:${stableHash(code, 12)}`;
    if (fields.semantic?.modelId) {
      const normalizedCall = node.getText(compiler.sourceFile).replace(/\s+/g, " ").trim();
      const fingerprint = `${kind}:${fields.semantic.modelId}:${stableHash(normalizedCall, 16)}`;
      const occurrence = semanticOccurrences.get(fingerprint) || 0;
      semanticOccurrences.set(fingerprint, occurrence + 1);
      operationIdentity = `${record.symbolKey}:${fingerprint}:${occurrence}`;
    }
    result.push(operation({
      id: stableHash(operationIdentity),
      kind,
      functionId: record.id,
      location: location({ ...input, ...sourceLocation, code }),
      inputs: fields.inputs || [],
      output: fields.output,
      call: fields.call,
      semantic: fields.semantic || {},
      certainty: fields.certainty || Certainty.HIGH,
      metadata: { frontend: "typescript-compiler-api", ...(fields.metadata || {}) },
    }));
  };
  const visit = node => {
    if (node !== record.node && isFunctionNode(node)) return;
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const collectionRead = collectionReadEffect(node.initializer, compiler.sourceFile, compiler.checker);
      const inputs = collectionRead?.inputs || symbolsFromNode(node.initializer, compiler.sourceFile, compiler.checker);
      const initializerPath = accessPathText(node.initializer, compiler.sourceFile);
      const collectionLiteral = ts.isIdentifier(node.name) &&
        (ts.isObjectLiteralExpression(node.initializer) || ts.isArrayLiteralExpression(node.initializer));
      if (!collectionLiteral) {
        for (const binding of bindingAccessPaths(node.name, compiler.sourceFile)) {
          const bindingInputs = initializerPath && binding.path.length
            ? [symbol(appendAccessPath(initializerPath, binding.path))]
            : inputs;
          add(OperationKind.ASSIGNMENT, node, {
            inputs: bindingInputs,
            output: symbol(binding.name),
            metadata: {
              assignmentMode: initializerPath ? "alias" : collectionRead?.mode || "aggregate",
              propagationReason: collectionRead?.reason,
              propagationStatus: collectionRead?.status,
            },
          });
        }
      }
      if (ts.isObjectLiteralExpression(node.initializer) && ts.isIdentifier(node.name)) {
        for (const assignment of collectionLiteralAssignments(node.initializer, node.name.text, compiler.sourceFile, compiler.checker)) {
          add(OperationKind.ASSIGNMENT, assignment.node, {
            inputs: assignment.inputs,
            output: symbol(assignment.target),
            metadata: { assignmentMode: assignment.mode || "aggregate" },
          });
        }
      }
      if (ts.isArrayLiteralExpression(node.initializer) && ts.isIdentifier(node.name)) {
        for (const assignment of collectionLiteralAssignments(node.initializer, node.name.text, compiler.sourceFile, compiler.checker)) {
          add(OperationKind.ASSIGNMENT, assignment.node, {
            inputs: assignment.inputs,
            output: symbol(assignment.target),
            metadata: { assignmentMode: assignment.mode || "aggregate" },
          });
        }
      }
    } else if (ts.isBinaryExpression(node) && assignmentOperator(node.operatorToken.kind)) {
      const directInput = accessPathText(node.right, compiler.sourceFile);
      const collectionRead = collectionReadEffect(node.right, compiler.sourceFile, compiler.checker);
      add(OperationKind.ASSIGNMENT, node, {
        inputs: collectionRead?.inputs || symbolsFromNode(node.right, compiler.sourceFile, compiler.checker),
        output: symbol(normalizeAccessPath(node.left.getText(compiler.sourceFile)) || node.left.getText(compiler.sourceFile)),
        metadata: {
          assignmentMode: directInput ? "alias" : collectionRead?.mode || "aggregate",
          propagationReason: collectionRead?.reason,
          propagationStatus: collectionRead?.status,
        },
      });
    }
    if (ts.isCallExpression(node)) {
      const call = callDetails(node, compiler.sourceFile, compiler.checker);
      call.output = callOutput(node, compiler.sourceFile);
      const modeled = modeledCallOperation(call, input.language, input.options?.semanticModels);
      const collectionWrites = collectionWriteEffects(node, compiler.sourceFile, compiler.checker);
      add(OperationKind.CALL, node, {
        inputs: modeled?.kind === OperationKind.CALL ? modeled.inputs : node.arguments.flatMap(argument => symbolsFromNode(argument, compiler.sourceFile, compiler.checker)),
        output: call.output,
        call,
        semantic: modeled?.kind === OperationKind.CALL ? modeled.semantic : undefined,
        certainty: modeled?.kind === OperationKind.CALL ? modeled.certainty : undefined,
        metadata: {
          ...(modeled?.kind === OperationKind.CALL ? modeled.metadata : {}),
          receiverPropagation: collectionWrites.length ? "precise" : undefined,
        },
      });
      for (const closure of closureRecordsForCall(node, record, records)) {
        const explicit = closure.parameterDescriptors.length;
        const captureNames = (closure.captures || []).map(capture => capture.name);
        const callArguments = [...Array(explicit).fill(""), ...captureNames];
        add(OperationKind.CALL, node, {
          inputs: captureNames.map(symbol),
          call: {
            function: closure.name,
            arguments: callArguments,
            argumentInputs: callArguments.map(value => value ? [symbol(value)] : []),
            targetFunctionId: closure.id,
            closure: true,
          },
          certainty: Certainty.HIGH,
          metadata: {
            closure: true,
            propagationReason: `The callback closes over ${captureNames.join(", ") || "no outer values"}.`,
            propagationStatus: "verified",
          },
        });
      }
      for (const effect of collectionWrites) {
        add(OperationKind.ASSIGNMENT, node, {
          inputs: effect.inputs,
          output: symbol(effect.output),
          metadata: {
            assignmentMode: effect.mode,
            propagationReason: effect.reason,
            propagationStatus: effect.status,
          },
        });
      }
      if (modeled && modeled.kind !== OperationKind.CALL) add(modeled.kind, node, {
        inputs: modeled.inputs,
        output: modeled.output,
        call,
        semantic: modeled.semantic,
        certainty: modeled.certainty,
        metadata: modeled.metadata,
      });
    }
    if (ts.isReturnStatement(node)) add(OperationKind.RETURN, node, { inputs: symbolsFromNode(node.expression, compiler.sourceFile, compiler.checker) });
    if (ts.isThrowStatement(node)) add(OperationKind.THROW, node, { inputs: symbolsFromNode(node.expression, compiler.sourceFile, compiler.checker) });
    if (ts.isBreakStatement(node)) add(OperationKind.BREAK, node);
    if (ts.isContinueStatement(node)) add(OperationKind.CONTINUE, node);
    if (ts.isIfStatement(node) || ts.isSwitchStatement(node) || ts.isConditionalExpression(node) ||
      ts.isWhileStatement(node) || ts.isDoStatement(node) || ts.isForStatement(node) || ts.isForInStatement(node) || ts.isForOfStatement(node)) {
      const condition = node.expression || node.condition;
      add(OperationKind.BRANCH, node, {
        inputs: symbolsFromNode(condition, compiler.sourceFile, compiler.checker),
        metadata: { branch: branchMetadata(node, compiler.sourceFile, isLoopNode(node) ? "loop" : "branch") },
      });
    }
    if (ts.isTryStatement(node)) add(OperationKind.BRANCH, node, {
      inputs: [],
      metadata: { branch: tryMetadata(node, compiler.sourceFile) },
    });
    ts.forEachChild(node, visit);
  };
  visit(record.node.body);
  return result.sort(compareOperations);
}

function signalOperations(signals, symbolKey, functionId, input, lines, compiler, rootNode) {
  const occurrences = new Map();
  return signals.flatMap(signal => {
    const code = signal.code || lines[signal.line - 1]?.trim() || "";
    const semantic = semanticValues(signal, rootNode, compiler?.sourceFile, input.language);
    const call = semantic.node && ts.isCallExpression(semantic.node)
      ? callDetails(semantic.node, compiler.sourceFile, compiler.checker)
      : undefined;
    const modelResolution = call && ["sink", "sanitizer", "auth"].includes(signal.kind)
      ? resolveSemanticCall(input.language, call, input.options?.semanticModels)
      : { status: "none" };
    if (modelResolution.status === "rejected") return [];
    const expectedRole = signal.kind === "sink" ? SemanticRole.SINK :
      ["sanitizer", "auth"].includes(signal.kind) ? SemanticRole.GUARD : undefined;
    const matchingModel = modelResolution.model?.role === expectedRole;
    if (matchingModel && ["verified", "syntax"].includes(modelResolution.status)) return [];
    const signalResolution = matchingModel || modelResolution.status === "candidate"
      ? modelResolution
      : { status: "none", candidates: [] };
    if (!semantic.resolved && looksLikeFunctionDeclaration(code, input.language)) return [];
    const assignment = semantic.output ? undefined : extractAssignment(code);
    const kind = signal.kind === "source" ? OperationKind.SOURCE : signal.kind === "sink" ? OperationKind.SINK : OperationKind.GUARD;
    const signalInput = semantic.resolved
      ? semantic.inputs
      : signal.kind === "source" && assignment?.target ? [assignment.target] : extractIdentifiers(code);
    const fingerprint = `${kind}:${signal.category}:${signal.label}:${stableHash(code, 12)}`;
    const occurrence = occurrences.get(fingerprint) || 0;
    occurrences.set(fingerprint, occurrence + 1);
    const signalSemantic = semanticForSignal(signal);
    const guardVerification = structurallyParameterizedGuard(signalSemantic.guardCapabilities, call)
      ? "structural"
      : signalResolution.status;
    const guardBinding = kind === OperationKind.GUARD
      ? buildGuardBinding(signalSemantic.guardCapabilities, semantic, call, guardVerification)
      : undefined;
    return [operation({
      id: stableHash(`${symbolKey}:${fingerprint}:${occurrence}`),
      kind,
      functionId,
      location: location({
        ...input,
        ...(semantic.node ? tsSourceLocation(semantic.node, compiler.sourceFile) : { line: signal.line }),
        code,
      }),
      inputs: signalInput.map(symbol),
      output: semantic.output ? symbol(semantic.output) : signal.kind === "source" && assignment?.target ? symbol(assignment.target) : undefined,
      call,
      semantic: signalSemantic,
      certainty: signalResolution.status === "candidate" || !semantic.resolved ? Certainty.LOW : Certainty.MEDIUM,
      metadata: {
        category: signal.category,
        controlKind: signal.kind,
        frontend: "ast-pattern-candidate",
        candidateStatus: signalResolution.status === "candidate" ? "symbol-unverified" : semantic.resolved ? "ast-validated" : "unverified",
        modelCandidates: signalResolution.candidates || [],
        guardBinding,
      },
    })];
  });
}

function modeledCallOperation(call, language, semanticModels) {
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
  const taintArguments = modeledTaintArguments(model, call);
  const inputs = taintArguments.flatMap(index => call.argumentInputs?.[index] || []);
  const semantic = {
    modelId: model.id,
    modelRole: model.role,
    sinkKind: model.sinkKind,
    sourceKind: model.sourceKind,
    category: model.category,
    guardCapabilities: model.guardCapabilities || [],
    label: model.id,
  };
  const guardBinding = model.role === SemanticRole.GUARD ? {
    capabilities: model.guardCapabilities || [],
    inputs: inputs.map(value => value.name),
    output: call.output?.name,
    receiver: call.receiver,
    trustedOperands: (call.argumentConstants || []).filter(Boolean),
    semanticVerification: resolution.status,
    ...guardAssociation(model.guardCapabilities || []),
  } : undefined;
  return {
    kind,
    inputs,
    output: model.returnsTaint || model.role === SemanticRole.GUARD ? call.output : undefined,
    semantic,
    certainty: resolution.status === "verified" ? Certainty.HIGH : Certainty.MEDIUM,
    metadata: {
      frontend: "typescript-semantic-registry",
      semanticVerification: resolution.status,
      taintArguments,
      callForms: model.callForms,
      applicableSinkKinds: model.applicableSinkKinds || [],
      receiverScoped: Boolean(model.receiverScoped),
      guardBinding,
    },
  };
}

function modeledTaintArguments(model, call) {
  const result = [...model.taintArguments];
  if (Number.isInteger(model.taintRestFrom)) {
    for (let index = model.taintRestFrom; index < (call.argumentInputs || []).length; index += 1) result.push(index);
  }
  return [...new Set(result)];
}

function looksLikeFunctionDeclaration(code, language) {
  if (!["javascript", "typescript"].includes(language)) return false;
  return /^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\b/.test(String(code || ""));
}

function semanticValues(signal, rootNode, sourceFile, language) {
  if (!rootNode || !sourceFile) return { inputs: [], resolved: false };
  const candidates = [];
  const visit = node => {
    if (node !== rootNode && isFunctionNode(node)) return;
    const expression = ts.isCallExpression(node) || ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node);
    if (expression && nodeLine(node, sourceFile) === signal.line) {
      const matches = collectSignals([node.getText(sourceFile)], language).some(candidate =>
        candidate.kind === signal.kind && candidate.category === signal.category,
      );
      if (matches) candidates.push(node);
    }
    ts.forEachChild(node, visit);
  };
  visit(rootNode);
  const node = candidates.sort((left, right) =>
    Number(ts.isCallExpression(right)) - Number(ts.isCallExpression(left)) || left.getWidth(sourceFile) - right.getWidth(sourceFile),
  )[0];
  if (!node) return { inputs: [], resolved: false };
  if (signal.kind === "sink" || signal.kind === "sanitizer" || signal.kind === "auth") {
    const values = ts.isCallExpression(node)
      ? [
        ...(ts.isPropertyAccessExpression(node.expression) ? symbolsFromNode(node.expression.expression, sourceFile) : []),
        ...node.arguments.flatMap(argument => symbolsFromNode(argument, sourceFile)),
      ]
      : symbolsFromNode(node, sourceFile);
    const output = signal.kind === "sanitizer" ? enclosingAssignmentOutputs(node, sourceFile)[0] : undefined;
    return { inputs: values.map(value => value.name), output, resolved: true, node };
  }
  const output = enclosingAssignmentOutputs(node, sourceFile)[0];
  return {
    inputs: output ? [output] : symbolsFromNode(node, sourceFile).map(value => value.name),
    output,
    resolved: true,
    node,
  };
}

function enclosingAssignmentOutputs(node, sourceFile) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (ts.isVariableDeclaration(parent) && parent.initializer && containsNode(parent.initializer, node)) return bindingNames(parent.name, sourceFile);
    if (ts.isBinaryExpression(parent) && assignmentOperator(parent.operatorToken.kind) && containsNode(parent.right, node)) return [parent.left.getText(sourceFile)];
    if (ts.isStatement(parent) || isFunctionNode(parent)) break;
  }
  return [];
}

function containsNode(parent, child) {
  return child.pos >= parent.pos && child.end <= parent.end;
}

function bindingNames(node, sourceFile) {
  return bindingAccessPaths(node, sourceFile).map(binding => binding.name);
}

function bindingAccessPaths(node, sourceFile, prefix = []) {
  if (ts.isIdentifier(node)) return [{ name: node.text, path: prefix }];
  if (ts.isObjectBindingPattern(node)) {
    return node.elements.flatMap(element => {
      const property = element.propertyName?.getText(sourceFile) || (ts.isIdentifier(element.name) ? element.name.text : undefined);
      const next = element.dotDotDotToken ? [...prefix, "*"] : property ? [...prefix, property.replace(/^['"]|['"]$/g, "")] : prefix;
      return bindingAccessPaths(element.name, sourceFile, next);
    });
  }
  if (ts.isArrayBindingPattern(node)) {
    return node.elements.flatMap((element, index) => ts.isBindingElement(element)
      ? bindingAccessPaths(element.name, sourceFile, [...prefix, index])
      : []);
  }
  return [{ name: node.getText(sourceFile), path: prefix }];
}

function accessPathText(node, sourceFile) {
  if (ts.isIdentifier(node) || ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    return normalizeAccessPath(node.getText(sourceFile));
  }
  return undefined;
}

function appendAccessPath(root, path) {
  return appendIRAccessPath(root, path);
}

function collectionLiteralAssignments(node, root, sourceFile, checker) {
  if (ts.isObjectLiteralExpression(node)) {
    return node.properties.flatMap(property => {
      if (ts.isShorthandPropertyAssignment(property)) return [{
        node: property,
        target: appendAccessPath(root, [property.name.text]),
        inputs: [symbol(property.name.text)],
        mode: "alias",
      }];
      if (ts.isPropertyAssignment(property)) {
        const key = literalPropertyName(property.name, sourceFile);
        if (key === undefined) return [{
          node: property,
          target: root,
          inputs: symbolsFromNode(property.initializer, sourceFile, checker),
          mode: accessPathText(property.initializer, sourceFile) ? "alias" : "aggregate",
        }];
        const target = appendAccessPath(root, [key]);
        if (ts.isObjectLiteralExpression(property.initializer) || ts.isArrayLiteralExpression(property.initializer)) {
          return collectionLiteralAssignments(property.initializer, target, sourceFile, checker);
        }
        return [{
          node: property,
          target,
          inputs: symbolsFromNode(property.initializer, sourceFile, checker),
          mode: accessPathText(property.initializer, sourceFile) ? "alias" : "aggregate",
        }];
      }
      if (ts.isSpreadAssignment(property)) return [{
        node: property,
        target: root,
        inputs: symbolsFromNode(property.expression, sourceFile, checker),
        mode: "alias",
      }];
      return [];
    });
  }
  if (ts.isArrayLiteralExpression(node)) {
    return node.elements.flatMap((element, index) => {
      if (ts.isOmittedExpression(element)) return [];
      const target = appendAccessPath(root, [index]);
      if (ts.isObjectLiteralExpression(element) || ts.isArrayLiteralExpression(element)) {
        return collectionLiteralAssignments(element, target, sourceFile, checker);
      }
      if (ts.isSpreadElement(element)) return [{
        node: element,
        target: root,
        inputs: symbolsFromNode(element.expression, sourceFile, checker),
        mode: "alias",
      }];
      return [{
        node: element,
        target,
        inputs: symbolsFromNode(element, sourceFile, checker),
        mode: accessPathText(element, sourceFile) ? "alias" : "aggregate",
      }];
    });
  }
  return [{
    node,
    target: root,
    inputs: symbolsFromNode(node, sourceFile, checker),
    mode: accessPathText(node, sourceFile) ? "alias" : "aggregate",
  }];
}

function literalPropertyName(node, sourceFile) {
  if (ts.isIdentifier(node) || ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)) return node.text;
  if (ts.isComputedPropertyName(node) && (ts.isStringLiteralLike(node.expression) || ts.isNumericLiteral(node.expression))) {
    return node.expression.text;
  }
  return undefined;
}

function assignSignals(records, signals, lines) {
  for (const signal of signals) {
    const containing = records
      .filter(record => signal.line >= record.line && signal.line <= record.endLine)
      .sort((left, right) => (left.endLine - left.line) - (right.endLine - right.line));
    if (containing[0]) {
      containing[0].signals.push(signal);
      continue;
    }
    if (!/^\s*(?:@|\[)/.test(lines[signal.line - 1] || "")) continue;
    const following = records.filter(record => record.line > signal.line && record.line - signal.line <= 8).sort((a, b) => a.line - b.line)[0];
    following?.signals.push(signal);
  }
}

function functionName(node, sourceFile) {
  if (node.name) return node.name.getText(sourceFile);
  if (ts.isVariableDeclaration(node.parent)) return node.parent.name.getText(sourceFile);
  if (ts.isPropertyAssignment(node.parent)) return node.parent.name.getText(sourceFile);
  if (ts.isCallExpression(node.parent)) {
    const index = node.parent.arguments.indexOf(node);
    const expression = node.parent.expression;
    const callee = ts.isPropertyAccessExpression(expression) ? expression.name.text : expression.getText(sourceFile).split(/[?.]/).at(-1);
    return `${callee}$callback${Math.max(0, index)}`;
  }
  return "anonymous";
}

function callbackDiscriminator(node, sourceFile) {
  const call = enclosingCallExpression(node);
  if (!call) return undefined;
  const argumentIndex = call.arguments.findIndex(argument => containsNode(argument, node));
  if (argumentIndex < 0) return undefined;
  const callee = call.expression.getText(sourceFile).replace(/\s+/g, "");
  const semanticArguments = call.arguments.slice(0, argumentIndex).map(argument => staticArgumentIdentity(argument, sourceFile)).filter(Boolean);
  return `${callee}#argument:${argumentIndex}${semanticArguments.length ? `:${semanticArguments.join("|")}` : ""}`;
}

function enclosingCallExpression(node) {
  for (let parent = node.parent; parent && !ts.isStatement(parent) && !isFunctionNode(parent); parent = parent.parent) {
    if (ts.isCallExpression(parent)) return parent;
  }
  return ts.isCallExpression(node.parent) ? node.parent : undefined;
}

function staticArgumentIdentity(node, sourceFile) {
  if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node) || ts.isIdentifier(node)) return node.getText(sourceFile);
  return undefined;
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

function enclosingScopeFor(node, sourceFile) {
  const names = [];
  for (let parent = node.parent; parent; parent = parent.parent) {
    if ((ts.isClassLike(parent) || ts.isInterfaceDeclaration(parent) || ts.isModuleDeclaration(parent)) && parent.name) names.unshift(parent.name.getText(sourceFile));
    else if (isFunctionNode(parent)) names.unshift(functionName(parent, sourceFile));
  }
  return names.join(".") || "<file>";
}

function implementedTypesFor(node, sourceFile) {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (!ts.isClassDeclaration(parent) && !ts.isClassExpression(parent)) continue;
    return (parent.heritageClauses || []).flatMap(clause => clause.types.map(type => type.expression.getText(sourceFile)));
  }
  return [];
}

function collectReferences(sourceFile) {
  const references = [];
  const add = (local, target, kind = "import") => {
    if (local && target && !references.some(reference => reference.local === local && reference.target === target)) references.push({ local, target, kind });
  };
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
    const target = statement.moduleSpecifier.text;
    const clause = statement.importClause;
    if (clause?.name) add(clause.name.text, target);
    if (clause?.namedBindings && ts.isNamespaceImport(clause.namedBindings)) add(clause.namedBindings.name.text, target);
    if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
      for (const element of clause.namedBindings.elements) add(element.name.text, target);
    }
  }
  return references;
}

function collectionReadEffect(node, sourceFile, checker) {
  if (!checker || !ts.isCallExpression(node)) return undefined;
  const receiverNode = callReceiverNode(node.expression);
  const receiver = normalizeAccessPath(receiverNode?.getText(sourceFile));
  const kind = collectionReceiverKind(receiverNode, checker);
  const method = propertyNameForCall(node.expression, sourceFile);
  if (!receiver || !kind) return undefined;
  if (kind === "map" && method === "get") {
    const key = collectionKey(node.arguments[0], checker);
    return collectionRead(receiver, key, `TypeScript resolved ${receiver} as a Map and mapped get(${formatCollectionKey(key)}) to one value Access Path.`);
  }
  if (kind === "array" && method === "at") {
    const key = collectionKey(node.arguments[0], checker);
    return collectionRead(receiver, key, `TypeScript resolved ${receiver} as an array and mapped at(${formatCollectionKey(key)}) to one element Access Path.`);
  }
  if (kind === "array" && ["pop", "shift", "join", "toString", "values"].includes(method)) {
    return collectionRead(receiver, "*", `TypeScript resolved ${receiver}.${method}() as reading array elements.`);
  }
  if ((kind === "map" || kind === "set") && ["values", "keys", "entries"].includes(method)) {
    return collectionRead(receiver, "*", `TypeScript resolved ${receiver}.${method}() as reading collection elements.`);
  }
  return undefined;
}

function collectionRead(receiver, key, reason) {
  const input = appendIRAccessPath(receiver, [key]);
  return input ? { inputs: [symbol(input)], mode: "alias", reason, status: "verified" } : undefined;
}

function collectionWriteEffects(node, sourceFile, checker) {
  if (!checker || !ts.isCallExpression(node)) return [];
  const receiverNode = callReceiverNode(node.expression);
  const receiver = normalizeAccessPath(receiverNode?.getText(sourceFile));
  const kind = collectionReceiverKind(receiverNode, checker);
  const method = propertyNameForCall(node.expression, sourceFile);
  if (!receiver || !kind) return [];
  const effects = [];
  const add = (argument, output, reason) => {
    const inputs = symbolsFromNode(argument, sourceFile, checker);
    if (inputs.length && output) effects.push({ inputs, output, mode: "alias", reason, status: "verified" });
  };
  if (kind === "array" && ["push", "unshift"].includes(method)) {
    for (const argument of node.arguments) add(argument, appendIRAccessPath(receiver, ["*"]),
      `TypeScript resolved ${receiver}.${method}() as storing this argument in an array element.`);
  } else if (kind === "array" && method === "splice") {
    for (const argument of node.arguments.slice(2)) add(argument, appendIRAccessPath(receiver, ["*"]),
      `TypeScript resolved ${receiver}.splice() as inserting this argument into an array element.`);
  } else if (kind === "array" && method === "fill" && node.arguments[0]) {
    add(node.arguments[0], appendIRAccessPath(receiver, ["*"]),
      `TypeScript resolved ${receiver}.fill() as storing its first argument in array elements.`);
  } else if (kind === "set" && method === "add" && node.arguments[0]) {
    add(node.arguments[0], appendIRAccessPath(receiver, ["*"]),
      `TypeScript resolved ${receiver}.add() as storing its first argument in a Set element.`);
  } else if (kind === "map" && method === "set" && node.arguments[1]) {
    const key = collectionKey(node.arguments[0], checker);
    add(node.arguments[1], appendIRAccessPath(receiver, [key]),
      `TypeScript resolved ${receiver}.set(${formatCollectionKey(key)}, value) as storing value at one Map Access Path.`);
  }
  return effects;
}

function collectionReceiverKind(node, checker) {
  if (!node) return undefined;
  const type = checkerTypeName(checker, node) || "";
  if (/\b(?:Map|ReadonlyMap|WeakMap)\s*</.test(type)) return "map";
  if (/\b(?:Set|ReadonlySet|WeakSet)\s*</.test(type)) return "set";
  if (/\b(?:Array|ReadonlyArray)\s*</.test(type) || /\[\](?:\s|$|[|&])/.test(type) || /^readonly\s+\[|^\[/.test(type)) return "array";
  const symbolValue = checkerSymbol(checker, rootIdentifier(node));
  for (const declaration of symbolValue?.declarations || []) {
    const variable = ts.isVariableDeclaration(declaration) ? declaration : ancestorOfKind(declaration, ts.isVariableDeclaration);
    const initializer = variable?.initializer;
    if (!initializer) continue;
    if (ts.isArrayLiteralExpression(initializer)) return "array";
    if (ts.isNewExpression(initializer) && ts.isIdentifier(initializer.expression)) {
      if (initializer.expression.text === "Map" || initializer.expression.text === "WeakMap") return "map";
      if (initializer.expression.text === "Set" || initializer.expression.text === "WeakSet") return "set";
      if (initializer.expression.text === "Array") return "array";
    }
  }
  return undefined;
}

function collectionKey(node, checker) {
  if (!node) return "*";
  if (ts.isNumericLiteral(node)) return Number(node.text);
  const constant = constantStringValue(node, checker);
  return constant === undefined ? "*" : constant;
}

function formatCollectionKey(value) {
  return value === "*" ? "<dynamic>" : JSON.stringify(value);
}

function callDetails(node, sourceFile, checker) {
  const expression = node.expression;
  const callee = propertyNameForCall(expression, sourceFile);
  const receiverNode = callReceiverNode(expression);
  const receiver = receiverNode?.getText(sourceFile);
  return {
    function: callee,
    receiver,
    arguments: node.arguments.map(argument => argument.getText(sourceFile)),
    argumentInputs: node.arguments.map(argument => symbolsFromNode(argument, sourceFile, checker)),
    argumentConstants: node.arguments.map((argument, index) => {
      const value = constantStringValue(argument, checker);
      return value === undefined ? undefined : { index, expression: argument.getText(sourceFile), value };
    }),
    handlerArguments: node.arguments.map(argument =>
      handlerNodes(argument).some(candidate => isFunctionNode(candidate) || Boolean(resolvedFunctionNode(candidate, checker)))),
    routeValue: constantStringValue(node.arguments[0], checker),
    symbol: callSymbolIdentity(node, sourceFile, checker),
    receiverCall: receiverNode && ts.isCallExpression(receiverNode) ? callDetails(receiverNode, sourceFile, checker) : undefined,
  };
}

function buildGuardBinding(capabilities = [], semantic = {}, call, semanticVerification = "none") {
  const association = guardAssociation(capabilities);
  return {
    capabilities,
    inputs: semantic.inputs || [],
    output: semantic.output,
    receiver: call?.receiver,
    trustedOperands: (call?.argumentConstants || []).filter(Boolean),
    semanticVerification,
    allowsBoundParameters: semanticVerification === "structural",
    ...association,
  };
}

function structurallyParameterizedGuard(capabilities = [], call) {
  if (!capabilities.includes(GuardCapability.SQL_PARAMETERIZATION) || (call?.arguments || []).length < 2) return false;
  const query = String(call.arguments[0] || "").trim();
  return /^(?:[rubf]{0,2})?["'`]/i.test(query) && /(?:\?|\$\d+|%s|%\([^)]+\)s|:[A-Za-z_]\w*)/.test(query);
}

function callSymbolIdentity(node, sourceFile, checker) {
  const expression = node.expression;
  const property = propertyNameForCall(expression, sourceFile);
  const receiver = callReceiverNode(expression);
  const receiverRoot = rootIdentifier(receiver);
  const target = ts.isPropertyAccessExpression(expression) ? expression.name :
    ts.isElementAccessExpression(expression) ? expression.argumentExpression : expression;
  const targetSymbol = checkerSymbol(checker, target);
  const receiverSymbol = checkerSymbol(checker, receiverRoot);
  const declaration = targetSymbol?.declarations?.[0];
  const receiverDeclaration = receiverSymbol?.declarations?.[0];
  const importBinding = importBindingFor(declaration, property) || importBindingFor(receiverDeclaration, property);
  const requireBinding = requireBindingFor(declaration, property, sourceFile) || requireBindingFor(receiverDeclaration, property, sourceFile);
  const aliasBinding = semanticAliasBinding(declaration, sourceFile, checker);
  const moduleBinding = importBinding || requireBinding || (aliasBinding?.kind === "global" ? undefined : aliasBinding);
  const receiverType = receiver && checker ? checkerTypeName(checker, receiver) : undefined;
  const fullyQualified = checkerQualifiedName(checker, targetSymbol);
  const local = localDeclaration(declaration) || localDeclaration(receiverDeclaration);
  const globalAlias = aliasBinding?.kind === "global";
  const globalBuiltin = !receiver && ["fetch", "eval", "Function", "String", "decodeURIComponent", "encodeURIComponent"].includes(property);
  const global = globalAlias || (!local && globalBuiltin);
  const kind = moduleBinding?.kind || (globalAlias ? "global" : local ? "local" : global ? "global" : declaration ? "symbol" : "unresolved");
  const exportName = moduleBinding?.exportName || aliasBinding?.exportName || property;

  return {
    kind,
    moduleName: moduleBinding?.moduleName,
    exportName,
    receiverType,
    qualifiedName: moduleBinding?.moduleName ? `${moduleBinding.moduleName}.${exportName}` : fullyQualified ||
      (receiverType ? `${receiverType}.${property}` : global ? `global.${property}` : undefined),
    declarationKind: declaration?.kind !== undefined ? ts.SyntaxKind[declaration.kind] : undefined,
    shadowed: kind === "local",
    verified: Boolean(moduleBinding || global || (receiverType && !/^(?:any|unknown|\?)$/i.test(receiverType))),
  };
}

function semanticAliasBinding(declaration, sourceFile, checker, seen = new Set()) {
  if (!declaration || seen.has(declaration)) return undefined;
  seen.add(declaration);
  if (!ts.isVariableDeclaration(declaration) || !declaration.initializer) return undefined;
  let initializer = declaration.initializer;
  while (ts.isParenthesizedExpression(initializer) || ts.isAsExpression(initializer) || ts.isTypeAssertionExpression(initializer)) {
    initializer = initializer.expression;
  }
  const property = propertyNameForCall(initializer, sourceFile);
  const receiver = callReceiverNode(initializer);
  const targetSymbol = checkerSymbol(checker, ts.isPropertyAccessExpression(initializer) ? initializer.name : initializer);
  const receiverSymbol = checkerSymbol(checker, rootIdentifier(receiver));
  const targetDeclaration = targetSymbol?.declarations?.[0];
  const receiverDeclaration = receiverSymbol?.declarations?.[0];
  const moduleBinding = importBindingFor(targetDeclaration, property) || importBindingFor(receiverDeclaration, property) ||
    requireBindingFor(targetDeclaration, property, sourceFile) || requireBindingFor(receiverDeclaration, property, sourceFile);
  if (moduleBinding) return moduleBinding;
  if (!receiver && ["fetch", "String", "decodeURIComponent", "encodeURIComponent"].includes(property) &&
      (!targetDeclaration || targetDeclaration.getSourceFile?.().isDeclarationFile)) {
    return { kind: "global", exportName: property };
  }
  return semanticAliasBinding(targetDeclaration, sourceFile, checker, seen);
}

function propertyNameForCall(expression, sourceFile) {
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  if (ts.isElementAccessExpression(expression) && ts.isStringLiteralLike(expression.argumentExpression)) return expression.argumentExpression.text;
  return expression.getText(sourceFile).split(/[?.]/).at(-1);
}

function callReceiverNode(expression) {
  if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) return expression.expression;
  return undefined;
}

function rootIdentifier(node) {
  let current = node;
  while (current && (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current))) current = current.expression;
  return current && ts.isIdentifier(current) ? current : undefined;
}

function checkerSymbol(checker, node) {
  if (!checker || !node) return undefined;
  try { return checker.getSymbolAtLocation(node); } catch { return undefined; }
}

function checkerTypeName(checker, node) {
  try { return checker.typeToString(checker.getTypeAtLocation(node)); } catch { return undefined; }
}

function checkerQualifiedName(checker, symbolValue) {
  if (!checker || !symbolValue) return undefined;
  try { return checker.getFullyQualifiedName(symbolValue).replace(/^"|"$/g, ""); } catch { return undefined; }
}

function importBindingFor(declaration, memberName) {
  if (!declaration) return undefined;
  const importDeclaration = ancestorOfKind(declaration, ts.isImportDeclaration);
  if (importDeclaration && ts.isStringLiteralLike(importDeclaration.moduleSpecifier)) {
    if (ts.isImportSpecifier(declaration)) {
      return { kind: "import", moduleName: importDeclaration.moduleSpecifier.text, exportName: declaration.propertyName?.text || declaration.name.text };
    }
    if (ts.isNamespaceImport(declaration)) {
      return { kind: "import", moduleName: importDeclaration.moduleSpecifier.text, exportName: memberName };
    }
    if (ts.isImportClause(declaration)) {
      return { kind: "import", moduleName: importDeclaration.moduleSpecifier.text, exportName: memberName || "default" };
    }
  }
  if (ts.isImportEqualsDeclaration(declaration) && ts.isExternalModuleReference(declaration.moduleReference) &&
      ts.isStringLiteralLike(declaration.moduleReference.expression)) {
    return { kind: "import", moduleName: declaration.moduleReference.expression.text, exportName: memberName };
  }
  return undefined;
}

function requireBindingFor(declaration, memberName, sourceFile) {
  if (!declaration) return undefined;
  const variable = ancestorOfKind(declaration, ts.isVariableDeclaration);
  if (!variable?.initializer) return undefined;
  const moduleName = moduleNameFromLoader(variable.initializer);
  if (!moduleName) return undefined;
  let exportName = memberName;
  if (ts.isBindingElement(declaration)) exportName = declaration.propertyName?.getText(sourceFile) || declaration.name.getText(sourceFile);
  return { kind: "require", moduleName, exportName };
}

function moduleNameFromLoader(node) {
  let current = node;
  while (ts.isAwaitExpression(current) || ts.isParenthesizedExpression(current)) current = current.expression;
  if (!ts.isCallExpression(current) || !current.arguments.length || !ts.isStringLiteralLike(current.arguments[0])) return undefined;
  const requireCall = ts.isIdentifier(current.expression) && current.expression.text === "require";
  const dynamicImport = current.expression.kind === ts.SyntaxKind.ImportKeyword;
  return requireCall || dynamicImport ? current.arguments[0].text : undefined;
}

function ancestorOfKind(node, predicate) {
  for (let current = node; current; current = current.parent) if (predicate(current)) return current;
  return undefined;
}

function localDeclaration(declaration) {
  if (!declaration || declaration.getSourceFile?.().isDeclarationFile) return false;
  return Boolean(
    isFunctionNode(declaration) || ts.isParameter(declaration) || ts.isVariableDeclaration(declaration) ||
    ts.isPropertyAssignment(declaration) || ts.isMethodDeclaration(declaration)
  );
}

function constantStringValue(node, checker, seen = new Set()) {
  if (!node) return undefined;
  if (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)) {
    return constantStringValue(node.expression, checker, seen);
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = constantStringValue(node.left, checker, seen);
    const right = constantStringValue(node.right, checker, seen);
    return left !== undefined && right !== undefined ? left + right : undefined;
  }
  if (ts.isIdentifier(node) && checker) {
    let targetSymbol;
    try { targetSymbol = checker.getSymbolAtLocation(node); } catch { return undefined; }
    if (!targetSymbol || seen.has(targetSymbol)) return undefined;
    seen.add(targetSymbol);
    for (const declaration of targetSymbol.declarations || []) {
      if (ts.isVariableDeclaration(declaration) && declaration.initializer) {
        const value = constantStringValue(declaration.initializer, checker, seen);
        if (value !== undefined) return value;
      }
    }
  }
  try {
    const constant = checker?.getConstantValue(node);
    return typeof constant === "string" ? constant : undefined;
  } catch { return undefined; }
}

function callOutput(node, sourceFile) {
  if (ts.isVariableDeclaration(node.parent) && node.parent.initializer === node) return symbol(node.parent.name.getText(sourceFile));
  if (ts.isBinaryExpression(node.parent) && node.parent.right === node && assignmentOperator(node.parent.operatorToken.kind)) return symbol(node.parent.left.getText(sourceFile));
  return undefined;
}

function symbolsFromNode(node, sourceFile, checker) {
  if (!node) return [];
  const collectionRead = collectionReadEffect(node, sourceFile, checker);
  if (collectionRead) return collectionRead.inputs;
  const names = [];
  const visit = current => {
    if (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) {
      const accessPath = normalizeAccessPath(current.getText(sourceFile));
      if (accessPath) names.push(accessPath);
      return;
    }
    if (ts.isIdentifier(current)) {
      if (!ts.isPropertyAccessExpression(current.parent) || current.parent.name !== current) names.push(current.text);
    }
    ts.forEachChild(current, visit);
  };
  visit(node);
  return [...new Set(names)].map(symbol);
}

function branchMetadata(node, sourceFile, controlKind = "branch") {
  const condition = node.expression || node.condition;
  const thenNode = node.thenStatement || node.whenTrue || node.statement;
  const elseNode = node.elseStatement || node.whenFalse;
  return {
    controlKind,
    condition: condition?.getText(sourceFile) || "",
    conditionRange: nodeRange(condition, sourceFile),
    thenRange: nodeRange(thenNode, sourceFile),
    elseRange: nodeRange(elseNode, sourceFile),
  };
}

function tryMetadata(node, sourceFile) {
  return {
    controlKind: "try",
    condition: "try",
    thenRange: nodeRange(node.tryBlock, sourceFile),
    catchRanges: node.catchClause ? [nodeRange(node.catchClause, sourceFile)] : [],
    finallyRange: nodeRange(node.finallyBlock, sourceFile),
  };
}

function isLoopNode(node) {
  return ts.isWhileStatement(node) || ts.isDoStatement(node) || ts.isForStatement(node) ||
    ts.isForInStatement(node) || ts.isForOfStatement(node);
}

function nodeRange(node, sourceFile) {
  if (!node) return undefined;
  const sourceLocation = tsSourceLocation(node, sourceFile);
  return {
    start: sourceLocation.line,
    end: sourceLocation.endLine,
    startColumn: sourceLocation.startColumn,
    endColumn: sourceLocation.endColumn,
    startOffset: sourceLocation.startOffset,
    endOffset: sourceLocation.endOffset,
  };
}

function assignmentOperator(kind) {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

function isFunctionNode(node) {
  return ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) || ts.isConstructorDeclaration(node) || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node);
}

function nodeLine(node, sourceFile) {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
}

function countTreeFunctions(node) {
  let count = TREE_FUNCTION_TYPES.has(node.type) && !["required_parameter", "optional_parameter"].includes(node.type) ? 1 : 0;
  for (const child of node.namedChildren || []) count += countTreeFunctions(child);
  return count;
}

function signalKey(signal) {
  return [signal.kind, signal.category, signal.line, signal.label].join(":");
}

module.exports = { TypeScriptAstFrontend, collectFunctionNodes, createCompilerModel, scriptKindFor };
