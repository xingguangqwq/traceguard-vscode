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
const { resolveSemanticCall, resolveStructuralSemantic, SemanticRole } = require("../security/catalog");
const { interpretCollectionCall } = require("../security/collection-semantics");
const { expressionInputs, javaBeanGetterRead } = require("./expression-inputs");
const { fixedNumericCollectionJoinFact } = require("./collection-predicates");

const FUNCTION_TYPES = Object.freeze({
  java: new Set(["method_declaration", "constructor_declaration", "lambda_expression"]),
  python: new Set(["function_definition", "lambda"]),
  php: new Set(["function_definition", "method_declaration", "anonymous_function", "arrow_function"]),
  csharp: new Set(["method_declaration", "constructor_declaration", "local_function_statement", "lambda_expression", "anonymous_method_expression"]),
  go: new Set(["function_declaration", "method_declaration", "func_literal"]),
});

const TYPE_TYPES = new Set([
  "class_declaration", "class_definition", "interface_declaration", "enum_declaration", "record_declaration", "struct_declaration", "namespace_declaration",
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
const JAVA_LANG_TYPES = new Set([
  "Boolean", "Byte", "Character", "Class", "ClassLoader", "Double", "Enum", "Float", "Integer", "Long",
  "Math", "Number", "Object", "Process", "ProcessBuilder", "Runtime", "Short", "String", "StringBuffer",
  "StringBuilder", "System", "Thread", "ThreadLocal", "Throwable", "Void",
]);

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
    const typeRelations = this.language === "java" ? javaTypeRelations(root, text, references, input) : [];
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
      ...treeFrameworkEntries(root, records, this.language, text, references),
      ...(this.language === "java" ? javaFrameworkEntries(records, text) : []),
      ...(this.language === "php" ? phpFrameworkEntries(records, text) : []),
      ...(this.language === "python" ? pythonFrameworkEntries(records, text) : []),
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
      typeRelations,
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
          handler: entry.handler,
          location: location({ ...input, ...entry, code: lines[entry.line - 1] }),
        };
      }),
    });
  }
}

function treeFrameworkEntries(root, records, language, text, references = []) {
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
          const argumentText = handlerCall?.arguments?.[handlerIndex];
          const externalHandler = externalHandlerDescriptor(language, argumentText, references);
          if (externalHandler) {
            const entry = frameworkEntry({ ...classification, handlerIndex }, undefined, treeSourceLocation(argumentNode || node));
            entry.handler = externalHandler;
            entries.push(entry);
            continue;
          }
          for (const target of handlerTargets(argumentNode, argumentText)) {
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

function externalHandlerDescriptor(language, argumentText, references = []) {
  const value = String(argumentText || "").trim();
  if (language === "php") {
    let className;
    let functionName;
    const array = value.match(/^\[([\s\S]+)\]$/);
    if (array) {
      const parts = splitArguments(array[1]);
      className = parts[0]?.match(/(?:^|\\)([A-Za-z_]\w*)\s*::\s*class$/i)?.[1];
      functionName = stringLiterals(parts[1])[0];
    } else {
      const legacy = stringLiterals(value)[0]?.match(/^([A-Za-z_\\][\w\\]*)@([A-Za-z_]\w*)$/);
      className = legacy?.[1];
      functionName = legacy?.[2];
    }
    if (!className || !functionName) {
      const invokable = value.match(/^([A-Za-z_\\][\w\\]*)\s*::\s*class$/i);
      className = invokable?.[1];
      functionName = invokable ? "__invoke" : undefined;
    }
    if (!className || !functionName) return undefined;
    const simple = className.split("\\").at(-1);
    const imported = references.find(reference => reference.kind === "import" && canonicalSymbolName(reference.local) === canonicalSymbolName(simple));
    const namespaceName = references.find(reference => reference.kind === "namespace")?.target;
    const targetType = imported?.target || (className.includes("\\") ? className : namespaceName ? `${namespaceName}\\${className}` : className);
    return { language, className: simple, targetType, functionName };
  }
  if (language === "python") {
    const member = value.match(/^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$/);
    if (member) {
      const imported = references.find(reference => ["import", "require"].includes(reference.kind) && canonicalSymbolName(reference.local) === canonicalSymbolName(member[1]));
      if (!imported) return undefined;
      const moduleName = imported.target === member[1] || imported.target.endsWith(`.${member[1]}`)
        ? imported.target
        : `${imported.target}.${member[1]}`;
      return { language, moduleName, functionName: member[2] };
    }
    const imported = references.find(reference => reference.kind === "import" && canonicalSymbolName(reference.local) === canonicalSymbolName(value));
    if (imported) return { language, moduleName: imported.target, functionName: value };
  }
  return undefined;
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
  const packageName = input.language === "java" ? references.find(reference => reference.kind === "package")?.target : undefined;
  const namespaceName = input.language === "php" ? references.find(reference => reference.kind === "namespace")?.target : undefined;
  return functionIR({
    id: record.id,
    symbolKey: record.symbolKey,
    name: record.name,
    language: input.language,
    enclosingScope: record.enclosingScope,
    packageName,
    namespaceName,
    qualifiedEnclosingScope: packageName ? `${packageName}.${record.enclosingScope}` :
      namespaceName ? `${namespaceName}\\${record.enclosingScope}` : record.enclosingScope,
    implementedTypes: record.implementedTypes || [],
    declarationKind: record.declarationKind,
    executable: record.executable,
    signature: `${record.name}(${record.parameterDescriptors.map(parameter => parameter.type).join(",")})`,
    location: location({ ...input, ...treeSourceLocation(record.node), code: lines[record.line - 1] }),
    parameters: record.parameterDescriptors.map(parameter => {
      const annotations = input.language === "java" ? javaParameterAnnotationNames(parameter.raw) : [];
      return symbol(parameter.name, parameter.type, parameter.role, {
        annotations,
        cascadedValidation: annotations.some(name => ["Valid", "Validated"].includes(name)),
      });
    }),
    operations,
    cfg: buildOperationCFG(operations),
    references,
  });
}

function buildOperations(record, input, lines, text, references = []) {
  const operations = signalOperations(record, input, lines, text, references);
  const constantValues = new Map();
  const inferredTypes = new Map();
  const collectionStates = new Map();
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
    if (ASSIGNMENT_TYPES.has(node.type) && !(input.language === "java" && node.type === "enhanced_for_statement")) {
      const left = node.childForFieldName("left") || node.childForFieldName("name") || node.namedChildren?.[0];
      const explicitRight = node.childForFieldName("right") || node.childForFieldName("value");
      const right = explicitRight || node.namedChildren?.at(-1);
      const target = assignmentTarget(nodeText(left, text));
      if (target && right && right !== left) {
        const inputs = assignmentExpressionInputs(right, text, input.language);
        const constant = constantExpressionValue(right, text, constantValues);
        const uninitializedSelfReference = !explicitRight && inputs.length === 1 && inputs[0] === target;
        if (!hasBranchAncestor(node, record.node) && constant !== NO_CONSTANT) constantValues.set(target, constant);
        else if (!hasBranchAncestor(node, record.node) && explicitRight) constantValues.delete(target);
        if (!uninitializedSelfReference && (inputs.length || explicitRight && constant !== NO_CONSTANT)) add(OperationKind.ASSIGNMENT, node, {
          inputs: inputs.map(symbol),
          output: symbol(target),
          metadata: { assignmentMode: inputs.length ? (normalizeAccessPath(nodeText(right, text)) ? "alias" : "aggregate") : "constant" },
        });
        const guardFact = fixedNumericCollectionJoinFact(node, input.language, text, {
          parseCall: genericCall,
          callTypes: CALL_TYPES,
          functionTypes: FUNCTION_TYPES,
        });
        const guardModel = guardFact && resolveStructuralSemantic("fixed-numeric-collection-join", input.language);
        if (guardFact && guardModel) add(OperationKind.GUARD, node, {
          inputs: guardFact.inputs.map(symbol),
          output: symbol(guardFact.output),
          semantic: {
            modelId: guardModel.id,
            modelRole: guardModel.role,
            guardCapabilities: guardModel.guardCapabilities,
            label: guardModel.label,
          },
          certainty: Certainty.HIGH,
          metadata: {
            semanticVerification: "structural",
            controlKind: "sanitizer",
            guardBinding: {
              capabilities: guardModel.guardCapabilities,
              inputs: guardFact.inputs,
              output: guardFact.output,
              semanticVerification: "structural",
              collectionFacts: guardFact.facts,
              ...guardAssociation(guardModel.guardCapabilities, guardModel),
            },
          },
        });
      }
    }
    if (input.language === "java" && node.type === "enhanced_for_statement") {
      const nameNode = node.childForFieldName("name") || node.childForFieldName("variable");
      const valueNode = node.childForFieldName("value") || node.childForFieldName("iterable");
      const target = assignmentTarget(nodeText(nameNode, text));
      const collection = normalizeAccessPath(nodeText(valueNode, text));
      if (target && collection) add(OperationKind.ASSIGNMENT, valueNode, {
        inputs: [symbol(`${collection}[*]`)],
        output: symbol(target),
        metadata: {
          assignmentMode: "aggregate",
          propagationReason: `Enhanced-for binds one element of ${collection} to ${target}.`,
          propagationStatus: "verified",
        },
      });
    }
    if (CALL_TYPES.has(node.type)) {
      const call = genericCall(node, text);
      call.argumentInputs = call.arguments.map(argument => expressionInputs(argument, input.language).map(symbol));
      call.receiverInputs = genericReceiverInputs(call, input.language);
      call.argumentTypes = call.arguments.map(argument => inferExpressionType(argument, record, references));
      attachGenericCallIdentity(call, record, references, input.language, inferredTypes);
      const output = enclosingCallOutput(node, text, input.language);
      const collectionAccess = interpretCollectionCall(call, output, input.language, collectionStates, {
        controlScope: input.language === "java" ? javaControlScope(node, record.node) : "",
      });
      if (collectionAccess.receiverInputs) call.receiverInputs = collectionAccess.receiverInputs.map(symbol);
      const modeled = genericModeledCall(call, input.language, output, input.options?.semanticModels);
      if (output?.name && modeled?.returnType) inferredTypes.set(canonicalSymbolName(output.name), modeled.returnType);
      const operationCall = serializableGenericCall(call);
      const representedSource = modeled?.kind === OperationKind.SOURCE || Boolean(output?.name) && operations.some(item =>
        item.kind === OperationKind.SOURCE && item.location.startOffset === node.startIndex && item.output?.name === output.name);
      if (call.function && !representedSource) add(OperationKind.CALL, node, {
        inputs: modeled?.kind === OperationKind.CALL ? modeled.inputs : call.argumentInputs.flat(),
        output,
        call: operationCall,
        semantic: modeled?.kind === OperationKind.CALL ? modeled.semantic : undefined,
        certainty: modeled?.kind === OperationKind.CALL ? modeled.certainty : undefined,
        metadata: modeled?.kind === OperationKind.CALL ? modeled.metadata : undefined,
      });
      if (modeled && modeled.kind !== OperationKind.CALL) add(modeled.kind, node, {
        inputs: modeled.inputs,
        output: modeled.output,
        call: operationCall,
        semantic: modeled.semantic,
        certainty: modeled.certainty,
        metadata: modeled.metadata,
      });
      const beanRead = javaBeanGetterRead(call, output, input.language);
      if (beanRead) add(OperationKind.ASSIGNMENT, node, {
        inputs: [symbol(beanRead.input)],
        output: symbol(beanRead.output),
        metadata: {
          assignmentMode: "alias",
          propagationReason: `${call.function}() reads JavaBean property ${beanRead.input}.`,
          propagationStatus: "verified",
        },
      });
      for (const effect of collectionAccess.writes || []) {
        add(OperationKind.ASSIGNMENT, node, {
          inputs: effect.inputs,
          output: symbol(effect.output),
          metadata: {
            assignmentMode: "aggregate",
            propagationReason: effect.reason,
            propagationStatus: "verified",
          },
        });
      }
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
      const branch = genericBranchMetadata(node, text, LOOP_TYPES.has(node.type) ? "loop" : "branch", constantValues);
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
    const boundParameters = signal.kind === "source" && (
      /Framework-bound request data/i.test(signal.label || "") ||
      /\.framework\.bound-request$/.test(signal.catalogModelId || "")
    )
      ? record.parameterDescriptors
        .filter(parameter => /@(?:RequestParam|PathVariable|RequestBody|CookieValue|RequestHeader|ModelAttribute)\b/.test(parameter.raw || ""))
        .map(parameter => parameter.name)
      : [];
    const names = boundParameters.length
      ? boundParameters
      : semantic.resolved
      ? semantic.inputs
      : signal.kind === "source" && assignment?.target ? [assignment.target] : normalizedIdentifiers(code);
    const fingerprint = `${kind}:${signal.category}:${signal.label}:${stableHash(code, 12)}`;
    const occurrence = occurrences.get(fingerprint) || 0;
    occurrences.set(fingerprint, occurrence + 1);
    const signalSemantic = semanticForSignal(signal);
    const call = semantic.node && CALL_TYPES.has(semantic.node.type) ? genericCall(semantic.node, text) : undefined;
    if (call) {
      call.argumentInputs = call.arguments.map(argument => expressionInputs(argument, input.language).map(symbol));
      call.receiverInputs = genericReceiverInputs(call, input.language);
      call.symbol = genericCallIdentity(call, record, references, input.language);
    }
    const expectedRole = signal.kind === "sink" ? SemanticRole.SINK :
      signal.kind === "source" ? SemanticRole.SOURCE :
        ["sanitizer", "auth"].includes(signal.kind) ? SemanticRole.GUARD : undefined;
    // A broad textual candidate can match `function exec(...)` itself.  A
    // declaration is not a call site and must never become a sink/guard.
    if (expectedRole && semantic.node && FUNCTION_TYPES[input.language]?.has(semantic.node.type)) return [];
    if (expectedRole && !semantic.resolved && input.language === "php" &&
      FUNCTION_TYPES.php?.has(record.node?.type) && record.node.startPosition?.row + 1 === signal.line &&
      new RegExp(`\\bfunction\\s+${escapeRegExp(record.name)}\\s*\\(`, "i").test(code)) return [];
    let modeledCall = call;
    let modelResolution = expectedRole && modeledCall
      ? resolveSemanticCall(input.language, modeledCall, input.options?.semanticModels, expectedRole)
      : { status: "none" };
    if (expectedRole && modelResolution.status === "none" && call?.receiverCall) {
      modeledCall = call.receiverCall;
      modeledCall.receiverInputs = genericReceiverInputs(modeledCall, input.language);
      modeledCall.symbol = genericCallIdentity(modeledCall, record, references, input.language);
      modelResolution = resolveSemanticCall(input.language, modeledCall, input.options?.semanticModels, expectedRole);
    }
    const matchingModel = Boolean(expectedRole && modelResolution.model?.role === expectedRole);
    if (modelResolution.status === "rejected" && expectedRole) return [];
    if (matchingModel && ["verified", "syntax"].includes(modelResolution.status)) {
      const model = modelResolution.model;
      signalSemantic.modelId = model.id;
      signalSemantic.modelRole = model.role;
      signalSemantic.sinkKind = model.sinkKind;
      signalSemantic.category = model.category;
      signalSemantic.guardCapabilities = model.guardCapabilities || signalSemantic.guardCapabilities;
      signalSemantic.applicableSinkKinds = model.applicableSinkKinds || signalSemantic.applicableSinkKinds;
    }
    const contractModels = matchingModel
      ? [modelResolution.model]
      : modelResolution.status === "candidate" ? modelResolution.candidateModels || [] : [];
    const taintArguments = matchingModel && modeledCall
      ? genericTaintArguments(modelResolution.model, modeledCall)
      : modeledCall && kind !== OperationKind.SOURCE
        ? modeledCall.argumentInputs.map((_, index) => index)
        : undefined;
    const operationInputs = matchingModel && kind !== OperationKind.SOURCE
      ? [
        ...(modelResolution.model.taintReceiver ? modeledCall.receiverInputs || [] : []),
        ...taintArguments.flatMap(index => modeledCall.argumentInputs[index] || []),
      ].map(value => value.name)
      : modeledCall && kind === OperationKind.SINK
        ? [
          ...(contractModels.some(model => model.taintReceiver) ? modeledCall.receiverInputs || [] : []),
          ...modeledCall.argumentInputs.flat(),
        ].map(value => value.name)
        : names;
    const guardVerification = matchingModel ? modelResolution.status :
      modelResolution.status === "rejected" ? "rejected" :
        structurallyParameterizedGuard(signalSemantic.guardCapabilities, call) ? "structural" : undefined;
    const guardBinding = kind === OperationKind.GUARD
      ? buildGenericGuardBinding(
        signalSemantic.guardCapabilities,
        semantic,
        modeledCall,
        guardVerification,
        matchingModel ? modelResolution.model : signalSemantic,
      )
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
      call: serializableGenericCall(modeledCall),
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
        taintReceiver: contractModels.some(model => model.taintReceiver),
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
  const record = { id: symbolId(symbolKey), symbolKey, signals, node: rootNode, parameterDescriptors: [], name: "global scope" };
  const operations = buildOperations(record, input, lines, lines.join("\n"), references);
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
  const argumentNodes = argumentNode?.namedChildren || [];
  return {
    function: nodeText(nameNode, text) || parts.at(-1) || callable,
    form: node.type === "object_creation_expression" ? "constructor" : callFormFromReceiver(objectNode),
    receiver: nodeText(objectNode, text) || (parts.length > 1 ? parts.slice(0, -1).join(".") : undefined),
    arguments: args,
    argumentInputs: args.map(argument => normalizedIdentifiers(argument).map(symbol)),
    argumentTypes: args.map(inferExpressionType),
    argumentConstants: args.map((expression, index) => genericArgumentConstant(argumentNodes[index], text, expression, index)),
    receiverCall: objectNode && CALL_TYPES.has(objectNode.type) ? genericCall(objectNode, text) : undefined,
    receiverCallNode: objectNode && CALL_TYPES.has(objectNode.type) ? objectNode : undefined,
  };
}

function serializableGenericCall(call) {
  if (!call) return undefined;
  const { receiverCallNode: _frontendNode, receiverCall, ...serializable } = call;
  return {
    ...serializable,
    receiverCall: receiverCall ? serializableGenericCall(receiverCall) : undefined,
  };
}

function attachGenericCallIdentity(call, record, references, language, inferredTypes) {
  if (call.receiverCall) attachGenericCallIdentity(call.receiverCall, record, references, language, inferredTypes);
  call.symbol = genericCallIdentity(call, record, references, language, inferredTypes);
}

function genericCallIdentity(call, record, references = [], language, inferredTypes = new Map()) {
  const receiverRoot = String(call.receiver || "").match(/^[A-Za-z_$][\w$]*/)?.[0];
  const receiverMember = String(call.receiver || "").match(/^(?:this|self|\$this)(?:\.|->)(\$?[A-Za-z_]\w*)/)?.[1];
  const receiverNames = [call.receiver, receiverMember, receiverMember && language === "php" ? `$${receiverMember.replace(/^\$/, "")}` : receiverMember, receiverRoot].filter(Boolean);
  const inferredReceiverType = receiverRoot ? inferredTypes.get(canonicalSymbolName(receiverRoot)) : undefined;
  const javaPackage = language === "java" ? references.find(reference => reference.kind === "package")?.target : undefined;
  const javaSpecialReceiverType = language === "java" && call.receiver === "this"
    ? resolveDeclaredJavaType(record.enclosingScope, javaPackage, references)
    : language === "java" && call.receiver === "super" && record.superClassType
      ? resolveDeclaredJavaType(record.superClassType, javaPackage, references)
      : undefined;
  const parameterType = inferredReceiverType || (receiverRoot && !["this", "self", "$this"].includes(receiverRoot)
    ? record.parameterDescriptors?.find(parameter => canonicalSymbolName(parameter.name) === canonicalSymbolName(receiverRoot))?.type
    : undefined) || javaSpecialReceiverType || call.receiverCall?.symbol?.receiverType;
  const sameLocal = (reference, value) => canonicalSymbolName(reference.local) === canonicalSymbolName(value);
  const receiverReferences = references.filter(reference => receiverNames.some(name => sameLocal(reference, name)));
  // A Java method declaration is represented in the lightweight reference table
  // as `<method name> -> <return type>`.  That return type describes the value
  // produced by the call, not its receiver.  Treating it as the receiver made an
  // unqualified same-class call such as `injectableQuery(query)` look like
  // `AttackResult.injectableQuery(query)` and caused the call resolver to reject
  // the real local method.  Callable imports/declarations still participate in
  // identity resolution, but type evidence must come from an actual receiver.
  const callableReferences = !call.receiver
    ? references.filter(reference => sameLocal(reference, call.function) && ["import", "require", "declaration"].includes(reference.kind))
    : [];
  const matchingReferences = [...receiverReferences, ...callableReferences];
  const localType = receiverReferences.find(reference => reference.kind === "type");
  const declaredType = parameterType && parameterType !== "?" ? parameterType : localType?.target;
  const declaredTypeName = simpleTypeName(declaredType);
  const declaredImport = declaredTypeName ? references.find(reference => reference.kind === "import" && sameLocal(reference, declaredTypeName)) : undefined;
  const wildcardImports = declaredTypeName
    ? references.filter(reference => reference.kind === "import" && reference.local === "*" && String(reference.target || "").endsWith(".*"))
    : [];
  // A single Java wildcard import gives one deterministic package candidate for
  // the receiver type. Multiple wildcard packages remain syntax-only because
  // choosing one would recreate the same-name collision problem this identity
  // layer is meant to prevent.
  const wildcardImport = language === "java" && wildcardImports.length === 1
    ? { ...wildcardImports[0], target: `${wildcardImports[0].target.slice(0, -2)}.${declaredTypeName}` }
    : undefined;
  const resolvedTypeImport = declaredImport || wildcardImport;
  const declaredTypeDeclaration = declaredTypeName ? references.find(reference => reference.kind === "declaration" && sameLocal(reference, declaredTypeName)) : undefined;
  const declaredTypeRoot = String(declaredType || "").split(".")[0];
  const qualifiedTypeImport = declaredTypeRoot && declaredTypeRoot !== declaredType
    ? references.find(reference => ["import", "require"].includes(reference.kind) && sameLocal(reference, declaredTypeRoot))
    : undefined;
  const directImport = localType ? undefined : matchingReferences.find(reference => ["import", "require"].includes(reference.kind));
  const localDeclaration = !call.receiver
    ? matchingReferences.find(reference => reference.kind === "declaration")
    : undefined;
  const moduleReference = resolvedTypeImport || qualifiedTypeImport || directImport;
  const qualifiedDeclaredModule = language === "python" && String(declaredType || "").includes(".")
    ? String(declaredType).split(".").slice(0, -1).join(".")
    : undefined;
  const implicitJavaType = language === "java"
    ? javaLangType(declaredType || call.receiver || (call.form === "constructor" ? call.function : undefined))
    : undefined;
  const explicitQualifiedJavaReceiver = language === "java" && /^(?:[a-z_$][\w$]*\.)+[A-Z_$][\w$]*$/.test(String(call.receiver || ""))
    ? String(call.receiver)
    : undefined;
  const implicitPhpGlobal = language === "php" && !call.receiver && !moduleReference && !localDeclaration;
  const unresolvedDeclaredType = ["java", "python"].includes(language) && declaredType && declaredType !== "?" &&
    !moduleReference && !qualifiedDeclaredModule && !implicitJavaType && !declaredTypeDeclaration && !String(declaredType).includes(".");
  const resolvedReceiverType = resolvedTypeImport
    ? language === "python" ? `${resolvedTypeImport.target}.${declaredTypeName}` : resolvedTypeImport.target
    : implicitJavaType || declaredType || (call.form === "constructor" ? call.function : undefined) || call.receiver;
  const qualifiedBase = resolvedTypeImport ? resolvedReceiverType : moduleReference?.target || resolvedReceiverType;
  return {
    kind: moduleReference ? moduleReference.kind : explicitQualifiedJavaReceiver ? "fully-qualified" : implicitJavaType ? "implicit-import" : implicitPhpGlobal ? "global" : declaredTypeDeclaration || localDeclaration ? "local" : unresolvedDeclaredType ? "syntax" : localType || declaredType ? "local" : "syntax",
    moduleName: moduleReference?.target || qualifiedDeclaredModule || explicitQualifiedJavaReceiver || (implicitJavaType ? "java.lang" : undefined),
    exportName: call.function,
    qualifiedName: qualifiedBase ? `${qualifiedBase}.${call.function}` : call.function,
    receiverType: resolvedReceiverType,
    unresolvedType: Boolean(unresolvedDeclaredType),
    shadowed: Boolean(declaredTypeDeclaration || localDeclaration),
    verified: Boolean(moduleReference || qualifiedDeclaredModule || explicitQualifiedJavaReceiver || implicitJavaType || implicitPhpGlobal || declaredTypeDeclaration || localDeclaration || (declaredType && !unresolvedDeclaredType)),
  };
}

function javaLangType(value) {
  const name = simpleTypeName(value);
  return JAVA_LANG_TYPES.has(name) ? `java.lang.${name}` : undefined;
}

function simpleTypeName(value) {
  return String(value || "").replace(/<.*>/g, "").split(/[.\\]/).filter(Boolean).at(-1)?.replace(/[^A-Za-z0-9_$]/g, "");
}

function canonicalSymbolName(value) {
  return String(value || "").replace(/^\$/, "").replace(/[^A-Za-z0-9_$]/g, "").toLowerCase();
}

function callFormFromReceiver(receiverNode) {
  return receiverNode ? "instance-method" : "function";
}

function genericModeledCall(call, language, output, semanticModels) {
  const resolution = resolveSemanticCall(language, call, semanticModels);
  const reviewSink = resolution.status === "candidate" && resolution.model?.role === SemanticRole.SINK;
  if (!["verified", "syntax"].includes(resolution.status) && !reviewSink) return undefined;
  const model = resolution.model;
  const kind = {
    [SemanticRole.SOURCE]: OperationKind.SOURCE,
    [SemanticRole.SINK]: OperationKind.SINK,
    [SemanticRole.PROPAGATOR]: OperationKind.CALL,
    [SemanticRole.GUARD]: OperationKind.GUARD,
  }[model.role];
  if (!kind) return undefined;
  const taintArguments = genericTaintArguments(model, call);
  const inputs = [
    ...(model.taintReceiver ? call.receiverInputs || [] : []),
    ...taintArguments.flatMap(index => call.argumentInputs[index] || []),
  ];
  const guardBinding = model.role === SemanticRole.GUARD ? {
    capabilities: model.guardCapabilities || [],
    inputs: inputs.map(value => value.name),
    output: output?.name,
    receiver: call.receiver,
    trustedOperands: (call.argumentConstants || []).filter(Boolean),
    semanticVerification: resolution.status,
    ...guardAssociation(model.guardCapabilities || [], model),
  } : undefined;
  return {
    kind,
    returnType: model.returnType,
    inputs,
    output: model.returnsTaint || model.role === SemanticRole.GUARD ? output : undefined,
    semantic: {
      modelId: model.id,
      modelRole: model.role,
      sourceKind: model.sourceKind,
      exposure: model.exposure,
      sinkKind: model.sinkKind,
      category: model.category,
      guardCapabilities: model.guardCapabilities || [],
      applicableSinkKinds: model.applicableSinkKinds || [],
      label: model.id,
    },
    certainty: reviewSink ? Certainty.LOW : Certainty.MEDIUM,
    metadata: {
      frontend: "tree-sitter-semantic-registry",
      semanticVerification: resolution.status,
      candidateStatus: reviewSink ? "symbol-unverified" : undefined,
      taintArguments,
      taintReceiver: Boolean(model.taintReceiver),
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
    // Only the outermost call expression produces the assignment target. Giving
    // every nested receiver/argument call the same output made inner return
    // types overwrite the real outer type (for example Path.resolve(...)
    // becoming String because getOriginalFilename() was nested inside it).
    if (CALL_TYPES.has(parent.type)) return undefined;
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
      const matches = collectSignals([semanticCandidateText(node, text, language)], language).some(candidate =>
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

function semanticCandidateText(node, text, language) {
  if (!CALL_TYPES.has(node.type)) return nodeText(node, text);
  const call = genericCall(node, text);
  const directArguments = call.arguments.filter(argument => !/(?:=>|\bfunction\s*\(|\bfunc\s*\()/i.test(argument));
  const separator = language === "php" ? "->" : ".";
  return `${call.receiver ? `${call.receiver}${separator}` : ""}${call.function}(${directArguments.join(", ")})`;
}

function buildGenericGuardBinding(capabilities = [], semantic = {}, call, semanticVerification, associationOptions = {}) {
  return {
    capabilities,
    inputs: semantic.inputs || [],
    output: semantic.output,
    receiver: call?.receiver,
    trustedOperands: (call?.argumentConstants || []).filter(Boolean),
    semanticVerification,
    allowsBoundParameters: semanticVerification === "structural",
    ...guardAssociation(capabilities, associationOptions),
  };
}

function genericArgumentConstant(node, text, expression, index) {
  const value = genericLiteralValue(node, text);
  return value === undefined ? undefined : { index, expression, value };
}

function genericLiteralValue(node, text) {
  if (!node) return undefined;
  const children = node.namedChildren || [];
  if (/^(?:argument|parenthesized_expression|parenthesized_expression_list)$/.test(node.type) && children.length === 1) {
    return genericLiteralValue(children[0], text);
  }
  if (/^(?:string|string_literal|character_literal|char_literal|rune_literal|raw_string_literal|interpreted_string_literal)$/.test(node.type)) {
    return nodeText(node, text);
  }
  if (/^(?:integer|float|number|real|decimal_integer|decimal_floating_point)(?:_literal)?$/.test(node.type)) {
    return nodeText(node, text);
  }
  if (/^(?:true|false|null|none|nil|boolean_literal|null_literal)$/.test(node.type)) {
    return nodeText(node, text);
  }
  return undefined;
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

function genericBranchMetadata(node, text, controlKind = "branch", constantValues = new Map()) {
  const conditionNode = node.type === "enhanced_for_statement"
    ? node.childForFieldName("value")
    : node.childForFieldName("condition") || node.childForFieldName("condition_clause") || node.namedChildren?.[0];
  const thenNode = node.childForFieldName("consequence") || node.childForFieldName("body");
  const elseNode = node.childForFieldName("alternative");
  const constant = controlKind === "branch" ? constantExpressionValue(conditionNode, text, constantValues) : NO_CONSTANT;
  return {
    controlKind,
    condition: nodeText(conditionNode, text),
    constantOutcome: typeof constant === "boolean" ? constant : undefined,
    conditionRange: treeNodeRange(conditionNode),
    thenRange: treeNodeRange(thenNode),
    elseRange: treeNodeRange(elseNode),
  };
}

const NO_CONSTANT = Symbol("no-constant");

function constantExpressionValue(node, text, constants = new Map()) {
  if (!node) return NO_CONSTANT;
  const children = node.namedChildren || [];
  if (["parenthesized_expression", "condition_clause"].includes(node.type) && children.length === 1) {
    return constantExpressionValue(children[0], text, constants);
  }
  const source = nodeText(node, text).trim();
  if (/^(?:true|false)$/.test(source)) return source === "true";
  if (/^null$/.test(source)) return null;
  if (/^[+-]?\d+$/.test(source)) return Number(source);
  if (/^[A-Za-z_$][\w$]*$/.test(source)) return constants.has(source) ? constants.get(source) : NO_CONSTANT;
  if (/^(?:string_literal|character_literal)$/.test(node.type)) return source.slice(1, -1);
  if (/^(?:unary_expression)$/.test(node.type) && children.length === 1) {
    const value = constantExpressionValue(children[0], text, constants);
    if (value === NO_CONSTANT) return NO_CONSTANT;
    const operator = source.slice(0, source.indexOf(nodeText(children[0], text))).trim();
    if (operator === "!" && typeof value === "boolean") return !value;
    if (operator === "+" && typeof value === "number") return value;
    if (operator === "-" && typeof value === "number") return -value;
    return NO_CONSTANT;
  }
  if (children.length !== 2 || !/(?:binary_expression|infix_expression)$/.test(node.type)) return NO_CONSTANT;
  const left = constantExpressionValue(children[0], text, constants);
  const right = constantExpressionValue(children[1], text, constants);
  if (left === NO_CONSTANT || right === NO_CONSTANT) return NO_CONSTANT;
  const operator = String(text).slice(children[0].endIndex, children[1].startIndex).trim();
  switch (operator) {
    case "+": return typeof left === "number" && typeof right === "number" ? left + right : NO_CONSTANT;
    case "-": return typeof left === "number" && typeof right === "number" ? left - right : NO_CONSTANT;
    case "*": return typeof left === "number" && typeof right === "number" ? left * right : NO_CONSTANT;
    case "/": return typeof left === "number" && typeof right === "number" && right !== 0 ? Math.trunc(left / right) : NO_CONSTANT;
    case "%": return typeof left === "number" && typeof right === "number" && right !== 0 ? left % right : NO_CONSTANT;
    case ">": return left > right;
    case ">=": return left >= right;
    case "<": return left < right;
    case "<=": return left <= right;
    case "==": case "===": return left === right;
    case "!=": case "!==": return left !== right;
    case "&&": return typeof left === "boolean" && typeof right === "boolean" ? left && right : NO_CONSTANT;
    case "||": return typeof left === "boolean" && typeof right === "boolean" ? left || right : NO_CONSTANT;
    default: return NO_CONSTANT;
  }
}

function hasBranchAncestor(node, boundary) {
  for (let parent = node.parent; parent && parent !== boundary; parent = parent.parent) {
    if (BRANCH_TYPES.has(parent.type) || LOOP_TYPES.has(parent.type)) return true;
  }
  return false;
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
  const implementedTypes = relationNodes.flatMap(child => javaRelationTypes(nodeText(child, text)));
  const superClassType = javaRelationTypes(nodeText(relationNodes.find(child => child.type === "superclass"), text))[0];
  return {
    declarationKind: typeNode.type.replace(/_declaration$/, ""),
    implementedTypes: [...new Set(implementedTypes)],
    superClassType,
  };
}

function javaTypeRelations(root, text, references, input = {}) {
  const packageName = references.find(reference => reference.kind === "package")?.target;
  const hasBeanPatternCandidate = references.some(reference => reference.kind === "import" &&
    /^(?:jakarta|javax)\.validation\.constraints\.(?:Pattern|\*)$/.test(reference.target || "")) ||
    /@(?:jakarta|javax)\.validation\.constraints\.Pattern\b/.test(text);
  const relations = [];
  const visit = node => {
    if (["class_declaration", "interface_declaration", "record_declaration", "enum_declaration"].includes(node.type)) {
      const nameNode = node.childForFieldName("name");
      const name = nodeText(nameNode, text);
      if (name) {
        const relationNodes = (node.namedChildren || []).filter(child =>
          /(?:superclass|super_interfaces|extends_interfaces|type_list)/.test(child.type));
        const directTypes = relationNodes.flatMap(child => javaRelationTypes(nodeText(child, text)));
        relations.push({
          language: "java",
          type: packageName ? `${packageName}.${name}` : name,
          extends: [...new Set(directTypes.map(type => resolveDeclaredJavaType(type, packageName, references)).filter(Boolean))],
          validationConstraints: hasBeanPatternCandidate ? javaBeanValidationConstraints(node, text, input, references) : [],
        });
      }
    }
    for (const child of node.namedChildren || []) visit(child);
  };
  visit(root);
  return relations;
}

function javaParameterAnnotationNames(raw) {
  return [...String(raw || "").matchAll(/@(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\b/g)]
    .map(match => match[1]);
}

function javaBeanValidationConstraints(typeNode, text, input = {}, references = []) {
  const constraints = [];
  const body = typeNode.childForFieldName("body") || (typeNode.namedChildren || []).find(child => child.type === "class_body");
  const fields = (body?.namedChildren || []).filter(child => child.type === "field_declaration");
  const typeGeneratesGetters = javaAnnotations(typeNode, text).some(annotation => isLombokGetterAnnotation(annotation, references));
  const declaredMethods = new Set((body?.namedChildren || [])
    .filter(child => child.type === "method_declaration")
    .map(method => nodeText(method.childForFieldName("name"), text))
    .filter(Boolean));
  const generatedPureAccessors = fields.flatMap(field => {
    const fieldGeneratesGetter = typeGeneratesGetters || javaAnnotations(field, text).some(annotation =>
      annotation.name === "Getter" && annotationTarget(annotation, references) === "lombok.Getter");
    if (!fieldGeneratesGetter) return [];
    return (field.namedChildren || []).filter(child => child.type === "variable_declarator")
      .map(declarator => nodeText(declarator.childForFieldName("name"), text))
      .filter(Boolean)
      .map(property => `get${property[0]?.toUpperCase() || ""}${property.slice(1)}`)
      .filter(accessor => !declaredMethods.has(accessor));
  });
  for (const field of fields) {
    const patterns = javaAnnotations(field, text).filter(annotation => annotation.name === "Pattern" &&
      /^(?:jakarta|javax)\.validation\.constraints\.Pattern$/.test(annotationTarget(annotation, references) || ""));
    if (!patterns.length) continue;
    const names = (field.namedChildren || [])
      .filter(child => child.type === "variable_declarator")
      .map(declarator => nodeText(declarator.childForFieldName("name"), text))
      .filter(Boolean);
    for (const property of names) for (const annotation of patterns) {
      constraints.push({
        kind: "PATTERN",
        property,
        accessor: `get${property[0]?.toUpperCase() || ""}${property.slice(1)}`,
        regexp: javaAnnotationStringAttribute(annotation.raw, "regexp"),
        annotation: annotation.raw,
        defaultValidationGroup: !/\bgroups\s*=/.test(annotation.raw),
        generatedPureAccessors,
        verification: "syntax-only",
        location: {
          absolutePath: input.absolutePath,
          relativePath: input.relativePath,
          ...treeSourceLocation(annotation.node),
        },
      });
    }
  }
  return constraints;
}

function isLombokGetterAnnotation(annotation, references) {
  if (!["Getter", "Data", "Value"].includes(annotation.name)) return false;
  return annotationTarget(annotation, references) === `lombok.${annotation.name}`;
}

function annotationTarget(annotation, references) {
  const qualified = String(annotation.raw || "").match(/^@([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)/)?.[1];
  if (qualified?.includes(".")) return qualified;
  const explicit = references.find(reference => reference.kind === "import" && reference.local === annotation.name);
  if (explicit) return explicit.target;
  const wildcard = references.filter(reference => reference.kind === "import" && reference.local === "*" && reference.target.endsWith(".*"))
    .map(reference => `${reference.target.slice(0, -2)}.${annotation.name}`)
    .filter(target => /^(?:(?:jakarta|javax)\.validation\.constraints|lombok)\./.test(target));
  return wildcard.length === 1 ? wildcard[0] : undefined;
}

function javaAnnotationStringAttribute(raw, attribute) {
  const match = new RegExp(`\\b${attribute}\\s*=\\s*(\"(?:\\\\.|[^\"\\\\])*\")`).exec(String(raw || ""));
  if (!match) return undefined;
  try { return JSON.parse(match[1]); } catch { return match[1].slice(1, -1); }
}

function javaRelationTypes(value) {
  const list = String(value || "").replace(/^\s*(?:extends|implements)\s+/, "");
  return splitArguments(list).map(part => part.trim().match(/^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)/)?.[1]).filter(Boolean);
}

function resolveDeclaredJavaType(type, packageName, references) {
  const value = String(type || "").replace(/<.*>/g, "").trim();
  if (!value) return undefined;
  if (value.includes(".")) return value;
  const explicit = references.find(reference => reference.kind === "import" &&
    reference.local !== "*" && reference.local.toLowerCase() === value.toLowerCase());
  if (explicit) return explicit.target;
  const wildcard = references.find(reference => reference.kind === "import" && reference.local === "*" && reference.target.endsWith(".*"));
  if (wildcard) return `${wildcard.target.slice(0, -2)}.${value}`;
  return packageName ? `${packageName}.${value}` : value;
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
    const servletAnnotation = typeAnnotations.find(annotation => annotation.name === "WebServlet");
    const mappings = javaMethodMappings(methodAnnotations);
    const servletMethod = /^do(Get|Post|Put|Delete|Patch)$/i.exec(record.name);
    if (!mappings.length && servletMethod && (record.implementedTypes || []).some(type => /HttpServlet$/i.test(type))) {
      mappings.push({
        method: servletMethod[1].toUpperCase(),
        routes: servletAnnotation ? annotationRoutes(servletAnnotation) : ["<dynamic>"],
        framework: "servlet",
        node: servletAnnotation?.node || record.node,
      });
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

function phpFrameworkEntries(records, text) {
  const entries = [];
  for (const record of records) {
    if (record.node.type !== "method_declaration" && record.node.type !== "function_definition") continue;
    const attributesNode = record.node.childForFieldName("attributes") ||
      (record.node.namedChildren || []).find(child => child.type === "attribute_list");
    if (!attributesNode) continue;
    const attributes = [];
    const visit = node => {
      if (node.type === "attribute") attributes.push(node);
      else for (const child of node.namedChildren || []) visit(child);
    };
    visit(attributesNode);
    for (const attribute of attributes) {
      const raw = nodeText(attribute, text);
      const name = raw.match(/^\s*(?:[A-Za-z_\\][\w\\]*\\)?([A-Za-z_]\w*)/)?.[1];
      if (name !== "Route") continue;
      const route = stringLiterals(raw)[0] || "<dynamic>";
      const methodsText = raw.match(/methods\s*:\s*\[([\s\S]*?)\]/i)?.[1] || "";
      const methods = stringLiterals(methodsText).map(method => method.toUpperCase());
      entries.push(frameworkEntry({
        method: methods.length ? [...new Set(methods)].join("|") : "ANY",
        route,
        framework: "php-route",
        language: "php",
      }, record, treeSourceLocation(attribute)));
    }
  }
  return dedupeFrameworkEntries(entries);
}

function pythonFrameworkEntries(records, text) {
  const entries = [];
  for (const record of records) {
    if (record.node.type !== "function_definition") continue;
    const decorated = record.node.parent?.type === "decorated_definition" ? record.node.parent : undefined;
    if (!decorated) continue;
    const decorators = (decorated.namedChildren || []).filter(child => child.type === "decorator");
    for (const decorator of decorators) {
      const raw = nodeText(decorator, text);
      const match = raw.match(/^\s*@\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.(get|post|put|delete|patch|options|head|websocket|route|api_route)\s*\(([\s\S]*)\)\s*$/i);
      if (!match) continue;
      const receiver = match[1].split(".").at(-1).toLowerCase();
      if (!/(?:app|router|blueprint|bp)$/.test(receiver)) continue;
      const methodName = match[2].replace("_", "").toLowerCase();
      const methodsText = match[3].match(/methods\s*=\s*\[([\s\S]*?)\]/i)?.[1] || "";
      const methods = stringLiterals(methodsText).map(method => method.toUpperCase());
      const method = methodName === "route" || methodName === "apiroute"
        ? methods.length ? [...new Set(methods)].join("|") : "ANY"
        : methodName === "websocket" ? "WEBSOCKET" : methodName.toUpperCase();
      entries.push(frameworkEntry({
        method,
        route: stringLiterals(match[3])[0] || "<dynamic>",
        framework: methodName === "route" ? "flask" : "fastapi",
        language: "python",
      }, record, treeSourceLocation(decorator)));
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
function genericReceiverInputs(call, language) {
  if (call?.receiverCall) return (call.receiverCall.argumentInputs || []).flat();
  return expressionInputs(call?.receiver || "", language).map(symbol);
}

function assignmentExpressionInputs(right, text, language) {
  const source = nodeText(right, text);
  const callRanges = [];
  const visit = node => {
    if (CALL_TYPES.has(node.type)) {
      callRanges.push([node.startIndex - right.startIndex, node.endIndex - right.startIndex]);
      return;
    }
    for (const child of node.namedChildren || []) visit(child);
  };
  visit(right);
  if (!callRanges.length) return expressionInputs(source, language);
  const outsideCalls = [...source];
  for (const [start, end] of callRanges) {
    for (let index = Math.max(0, start); index < Math.min(outsideCalls.length, end); index += 1) outsideCalls[index] = " ";
  }
  return expressionInputs(outsideCalls.join(""), language);
}

function javaControlScope(node, boundary) {
  const parts = [];
  for (let parent = node?.parent; parent && parent !== boundary; parent = parent.parent) {
    if (!BRANCH_TYPES.has(parent.type) && !LOOP_TYPES.has(parent.type)) continue;
    const thenNode = parent.childForFieldName("consequence") || parent.childForFieldName("body");
    const elseNode = parent.childForFieldName("alternative");
    const arm = containsTreeNode(elseNode, node) ? "else" : containsTreeNode(thenNode, node) ? "then" : "condition";
    parts.push(`${parent.startIndex}:${arm}`);
  }
  return parts.reverse().join("/");
}

function containsTreeNode(container, node) {
  return Boolean(container && node && container.startIndex <= node.startIndex && container.endIndex >= node.endIndex);
}
function escapeRegExp(value) { return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function stripParens(value) { return String(value || "").trim().replace(/^\(/, "").replace(/\)$/, ""); }
function signalKey(signal) { return [signal.kind, signal.category, signal.line, signal.label].join(":"); }
module.exports = { TreeSitterLanguageFrontend, collectFunctions };
