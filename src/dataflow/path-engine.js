"use strict";

const { normalizePath, stableHash } = require("../identity");
const { SourceKind } = require("../security/semantics");
const callResolver = require("./call-resolver");
const {
  appendAccessPath,
  normalizeAccessPath,
  pathFeeds,
  pathsOverlap,
  propagatedAssignmentTargets,
  rebaseTaint,
  relativeAccessPath: accessPathSuffix,
  removeAssignedTaint,
} = require("../ir/access-path");
const { functionsFromAnalyses } = require("./ir-adapter");
const { assignmentFact, isReachableEvent } = require("./propagation");
const { eventSequences } = require("./control-flow");

const SOURCE_TOKEN = "<source>";
// Compatibility fallback for legacy entry IR that predates parameter roles.
// AST frontends now provide positional/type-derived provenance instead.
const RESPONSE_OBJECTS = new Set(["res", "response", "reply", "w", "next", "done"]);
const NON_TAINTED_PARAMETER_ROLES = new Set([
  "response", "context", "continuation", "service", "logger", "database", "cancellation", "error", "capture",
]);
const TAINTED_PARAMETER_ROLES = new Set(["request", "body", "query", "path", "header"]);

function findSourceSinkPaths(analyses, options = {}) {
  const functions = options._flowFunctions || functionsFromAnalyses(analyses, options);
  const index = options._functionIndex || callResolver.buildFunctionIndex(functions);
  const selectedFunctions = selectFunctions(functions, options);
  const potentialRanks = Array.isArray(options.rootFunctionIds)
    ? new Map()
    : buildPotentialRanks(functions, index, Math.min(4, Math.max(1, options.maxDepth || 6)));
  const roots = buildRoots(selectedFunctions, options)
    .sort((left, right) => (potentialRanks.get(right.fn.id) || 0) - (potentialRanks.get(left.fn.id) || 0));
  const paths = [];
  const maxDepth = Math.max(1, options.maxDepth || 6);
  const maxPaths = Math.max(1, options.maxPaths || 80);
  const candidateLimit = Math.min(10000, Math.max(2000, maxPaths * 20));
  const limits = { truncated: false };

  for (const root of roots) {
    if (paths.length >= candidateLimit) { limits.truncated = true; break; }
    const rootVariables = root.variables.map(variable => normalizeAccessPath(variable) || variable);
    const visited = new Set([visitKey(root.fn, rootVariables)]);
    walkFlow({
      fn: root.fn,
      rootFunctionId: root.fn.id,
      tainted: new Set(rootVariables),
      startLine: root.line,
      startOperationId: root.step.operationId,
      steps: [root.step],
      evidence: new Map(rootVariables.map(variable => [variable, [root.step]])),
      depth: 0,
      visited,
      index,
      paths,
      maxDepth,
      maxPaths: candidateLimit,
      limits,
    });
  }

  const uniquePaths = new Map();
  for (const flowPath of paths) {
    const key = flowPath.steps.map(step => [step.workspaceRoot, step.kind, step.operationId, step.functionId].join(":")).join("|");
    if (!uniquePaths.has(key)) uniquePaths.set(key, flowPath);
  }
  const sorted = [...uniquePaths.values()]
    .sort((a, b) => sinkReviewRank(b) - sinkReviewRank(a) ||
      Number(a.reviewPriority !== "uncontrolled") - Number(b.reviewPriority !== "uncontrolled") ||
      confidenceRank(a.confidence) - confidenceRank(b.confidence) ||
      a.files.length - b.files.length || a.steps.length - b.steps.length);
  const result = sorted.slice(0, maxPaths);
  Object.defineProperties(result, {
    truncated: { value: limits.truncated || sorted.length > maxPaths, enumerable: false },
    explorationTruncated: { value: limits.truncated, enumerable: false },
    totalCandidates: { value: sorted.length, enumerable: false },
  });
  return result;
}

function walkFlow(state) {
  if (state.depth > state.maxDepth) return;
  if (state.paths.length >= state.maxPaths) { state.limits.truncated = true; return; }
  const sequences = flowEventSequences(state.fn, state.startLine, state.startOperationId, Math.min(96, state.maxPaths));
  if (sequences.truncated) state.limits.truncated = true;
  for (const events of sequences) {
    if (state.paths.length >= state.maxPaths) { state.limits.truncated = true; return; }
    walkLinearFlow({ ...state, events });
  }
}

function walkLinearFlow(state) {
  const tainted = new Set(state.tainted);
  const evidence = new Map(state.evidence || [...tainted].map(variable => [variable, state.steps.slice()]));
  let activeSteps = state.steps.slice();
  const addedControls = new Set();
  const availableControls = [];

  for (const event of state.events) {
    const functionAnnotationControl = event.line <= state.fn.line && (event.type === "control" || event.functionAnnotation);
    if (state.paths.length >= state.maxPaths) { state.limits.truncated = true; return; }
    if (event.line < state.startLine && !functionAnnotationControl) continue;
    if (event.type === "assignment") {
      if (sourceDefinesSameValue(state.fn, event) || evidenceDefinesSameValue(evidence, event)) continue;
      const propagated = assignmentEvidence(event, tainted, evidence, state.fn);
      const remaining = removeAssignedTaint(tainted, event.target);
      removeAssignedEvidence(evidence, event.target);
      tainted.clear();
      for (const value of remaining) tainted.add(value);
      for (const item of propagated) {
        tainted.add(item.output);
        evidence.set(item.output, item.steps);
      }
      continue;
    }
    if (event.type === "control") {
      const controlKey = event.id || event.line + ":" + event.controlKind;
      if (!addedControls.has(controlKey) && (intersects(event.variables, tainted) || !event.variables.length)) {
        availableControls.push({
          event,
          step: makeStep(event.controlKind === "auth" ? "authorization" : "validation", event.label, state.fn, event, {
            guardCapabilities: event.guardCapabilities || [],
            guardDominance: event.guardDominance,
            guardBinding: event.guardBinding,
          }),
        });
        addedControls.add(controlKey);
      }
      continue;
    }
    if (event.type === "call") {
      const directlyTaintedArguments = [];
      event.argumentVariables.forEach((variables, index) => {
        if ((!event.taintArgumentIndexes || event.taintArgumentIndexes.includes(index)) && intersects(variables, tainted)) {
          directlyTaintedArguments.push(index);
        }
      });
      const applicableControlSteps = availableControls
        .map(control => ({ ...control, relation: controlRelation(control.event, event, state.fn) }))
        .filter(control => control.relation.status === "effective")
        .map(control => effectiveControlStep(control.step, control.relation));
      const candidates = callResolver.resolveCandidates(state.index, event, state.fn);
      const candidateFlows = candidates.map(resolution => ({
        resolution,
        incoming: incomingParameterVariables(resolution.fn, event, tainted),
      }));
      if (!directlyTaintedArguments.length && !candidateFlows.some(flow => flow.incoming.length)) continue;
      let returnedFlow;
      for (const { resolution, incoming } of candidateFlows) {
        const candidate = resolution.fn;
        if (!incoming.length) continue;
        const key = visitKey(candidate, incoming);
        if (state.visited.has(key)) continue;
        const accessPathTransition = callAccessPathTransition(candidate, event, tainted, incoming);
        const callStep = makeStep(
          "call",
          state.fn.name + "() → " + candidate.name + "()",
          state.fn,
          event,
          {
            candidateCount: candidates.length,
            candidateMatch: resolution.quality,
            candidateReason: resolution.reason,
            calleePath: candidate.relativePath,
            ...accessPathTransition,
          },
        );
        const visited = new Set(state.visited);
        visited.add(key);
        const callEvidence = bestEvidenceForValues(
          [...(event.argumentVariables || []).flat(), ...(event.variables || [])],
          evidence,
        ) || activeSteps;
        const nextSteps = [...callEvidence, ...applicableControlSteps, callStep];
        walkFlow({
          ...state,
          fn: candidate,
          tainted: new Set(incoming),
          evidence: new Map(incoming.map(variable => [variable, nextSteps])),
          startLine: candidate.line,
          startOperationId: undefined,
          steps: nextSteps,
          depth: state.depth + 1,
          visited,
        });
        if (!returnedFlow && event.target) {
          const returned = findTaintedReturn(candidate, incoming, state.index, new Set(state.visited), state.depth + 1, state.maxDepth);
          if (returned) returnedFlow = { candidate, event: returned, callStep, applicableControlSteps };
        }
      }
      if (event.target && returnedFlow) {
        tainted.add(event.target);
        activeSteps = [
          ...activeSteps,
          ...returnedFlow.applicableControlSteps,
          returnedFlow.callStep,
          makeStep("return", `${returnedFlow.candidate.name}() → ${event.target}`, returnedFlow.candidate, returnedFlow.event),
        ];
        evidence.set(event.target, activeSteps);
      } else if (event.target && !candidates.length && directlyTaintedArguments.length) {
        tainted.add(event.target);
        activeSteps = [...activeSteps, makeStep(
          "call",
          `${state.fn.name}() → unresolved ${event.callee}()`,
          state.fn,
          event,
          { candidateCount: 0, candidateMatch: "opaque", candidateReason: "unresolved external or dynamic call" },
        )];
        evidence.set(event.target, activeSteps);
      }
      continue;
    }
    if (event.type === "sink" && intersects(event.variables, tainted)) {
      const sinkStep = makeStep("sink", event.label, state.fn, event, {
        category: event.category,
        sinkKind: event.sinkKind,
        certainty: event.certainty,
        semanticModelId: event.semanticModelId,
        semanticVerification: event.semanticVerification,
        candidateStatus: event.candidateStatus,
      });
      const evaluatedControls = availableControls.map(control => ({
        ...control,
        relation: controlRelation(control.event, event, state.fn),
      }));
      const applicableControlSteps = evaluatedControls.filter(control => control.relation.status === "effective")
        .map(control => effectiveControlStep(control.step, control.relation));
      const guardHints = evaluatedControls.flatMap(control => (control.relation.hints || []).map(hint => ({
        label: control.step.label,
        line: control.step.line,
        relativePath: control.step.relativePath,
        capabilities: [hint.capability],
        reason: hint.reason,
      })));
      const sinkEvidence = bestEvidenceForValues(event.variables, evidence) || activeSteps;
      const steps = [...sinkEvidence, ...applicableControlSteps, sinkStep];
      const files = unique(steps.map(step => step.relativePath));
      const validationCount = steps.filter(step => step.kind === "validation").length;
      const authorizationCount = steps.filter(step => step.kind === "authorization").length;
      const guardCapabilities = unique(steps.flatMap(step => step.guardCapabilities || []));
      const callMatches = steps.filter(step => step.kind === "call").map(step => step.candidateMatch || "medium");
      const propagationStatuses = steps.filter(step => step.kind === "propagation").map(step => step.analysisStatus || "verified");
      const sourceConfidence = steps[0].confidence || "high";
      const semanticReview = sinkStep.certainty === "low" || [
        "unverified", "symbol-unverified", "regex-unverified", "ast-validated-symbol-unverified",
      ].includes(sinkStep.candidateStatus);
      const semanticMedium = sinkStep.certainty === "medium" || sinkStep.semanticVerification === "syntax";
      const confidence = semanticReview || callMatches.includes("review") || propagationStatuses.some(status => ["heuristic", "unresolved"].includes(status)) ? "review" :
        semanticMedium || sourceConfidence !== "high" || !callMatches.every(match => match === "high") || propagationStatuses.includes("syntax-only") ? "medium" : "high";
      state.paths.push({
        id: `path_${stableHash(steps.map(step => [step.workspaceRoot, step.kind, step.operationId || step.label, step.functionId].join(":")).join("|"))}`,
        rootFunctionId: state.rootFunctionId,
        touchedFunctionIds: unique(steps.map(step => step.functionId)),
        source: steps[0],
        sink: sinkStep,
        steps,
        files,
        calls: steps.filter(step => step.kind === "call").length,
        category: event.category || "sensitive operation",
        sourceKind: steps[0].sourceKind || SourceKind.EXTERNAL_INPUT,
        sinkKind: event.sinkKind,
        guardCapabilities,
        guardHints,
        confidence,
        controls: { validation: validationCount, authorization: authorizationCount },
        reviewPriority: validationCount || authorizationCount ? "controls-present" : "uncontrolled",
      });
    }
  }
}

function flowEventSequences(fn, startLine, startOperationId, maxPaths = 64) {
  return eventSequences(fn, {
    startLine,
    startBlock: startOperationId ? `op:${startOperationId}` : fn.cfg?.entry,
    maxPaths,
    maxVisits: 3,
  });
}

function buildPotentialRanks(functions, index, maxDepth) {
  let ranks = new Map(functions.map(fn => [fn.id, Math.max(0, ...fn.events.filter(event => event.type === "sink" && isReachableEvent(event)).map(sinkReviewRank))]));
  for (let depth = 0; depth < maxDepth; depth += 1) {
    const next = new Map(ranks);
    for (const fn of functions) {
      let rank = ranks.get(fn.id) || 0;
      for (const event of fn.events.filter(item => item.type === "call" && isReachableEvent(item))) {
      for (const candidate of callResolver.resolveCandidates(index, event, fn)) rank = Math.max(rank, ranks.get(candidate.fn.id) || 0);
      }
      next.set(fn.id, rank);
    }
    ranks = next;
  }
  return ranks;
}

function sinkReviewRank(value) {
  const category = value?.category || value?.sink?.category || "";
  return {
    command: 6,
    expression: 6,
    deserialization: 6,
    database: 5,
    file: 5,
    network: 5,
    redirect: 4,
    output: 4,
    directory: 3,
  }[category] || 1;
}

function findTaintedReturn(fn, incoming, index, visited, depth, maxDepth) {
  if (depth > maxDepth) return undefined;
  const key = visitKey(fn, incoming);
  if (visited.has(key)) return undefined;
  visited.add(key);
  const sequences = flowEventSequences(fn, fn.line, undefined, 64);
  for (const events of sequences) {
    const returned = findTaintedReturnOnPath(fn, events, incoming, index, visited, depth, maxDepth);
    if (returned) return returned;
  }
  return undefined;
}

function findTaintedReturnOnPath(fn, events, incoming, index, visited, depth, maxDepth) {
  const tainted = new Set(incoming);
  for (const event of events) {
    if (event.type === "assignment") {
      if (sourceDefinesSameValue(fn, event) || precedingCallDefinesSameValue(fn, event, tainted)) continue;
      const propagated = propagatedAssignmentTargets(
        event.target,
        event.variables,
        tainted,
        event.assignmentMode || "expression",
      );
      const remaining = sourceDefinesSameValue(fn, event)
        ? new Set(tainted)
        : removeAssignedTaint(tainted, event.target);
      tainted.clear();
      for (const value of remaining) tainted.add(value);
      for (const value of propagated) tainted.add(value);
      continue;
    }
    if (event.type === "call" && event.target) {
      const directlyTaintedArguments = [];
      event.argumentVariables.forEach((variables, argumentIndex) => {
        if ((!event.taintArgumentIndexes || event.taintArgumentIndexes.includes(argumentIndex)) && intersects(variables, tainted)) {
          directlyTaintedArguments.push(argumentIndex);
        }
      });
      const candidates = callResolver.resolveCandidates(index, event, fn);
      if (!candidates.length) {
        if (directlyTaintedArguments.length) tainted.add(event.target);
        continue;
      }
      for (const resolution of candidates) {
        const candidate = resolution.fn;
        const nextIncoming = incomingParameterVariables(candidate, event, tainted);
        if (nextIncoming.length && findTaintedReturn(candidate, nextIncoming, index, new Set(visited), depth + 1, maxDepth)) {
          tainted.add(event.target);
          break;
        }
      }
      continue;
    }
    if (event.type === "return" && intersects(event.variables, tainted)) return event;
  }
  return undefined;
}

function buildRoots(functions, options) {
  const roots = [];
  const selectedIdentifier = /^[$A-Za-z_][\w$]*$/.test(options.identifier || "") ? options.identifier : "";
  if (selectedIdentifier) {
    for (const fn of functions) {
      roots.push({
        fn,
        line: options.line || fn.line,
        variables: [selectedIdentifier],
        step: makeStep("source", "Selected variable " + selectedIdentifier, fn, {
          line: options.line || fn.line,
          code: options.code || selectedIdentifier,
        }, { sourceKind: SourceKind.SELECTED_SYMBOL }),
      });
    }
    return dedupeRoots(roots);
  }

  for (const fn of functions) {
    for (const event of fn.events.filter(event => event.type === "source" && event.variables.length)) {
      const inputVariables = event.variables;
      if (!inputVariables.length) continue;
      roots.push({
        fn,
        line: event.line,
        variables: inputVariables,
        step: makeStep("source", event.label || "External input", fn, event, { sourceKind: event.sourceKind }),
      });
    }
    for (const entry of fn.entryPoints || (fn.isEntry ? [{ title: fn.entryTitle }] : [])) {
      const roles = fn.parameters.map((name, index) =>
        entry.parameterRoles?.[index] || fn.parameterDetails?.[index]?.role || (RESPONSE_OBJECTS.has(name) ? "response" : "unknown"));
      const entryInputs = fn.parameters.flatMap((name, index) => {
        if (NON_TAINTED_PARAMETER_ROLES.has(roles[index])) return [];
        const bindings = fn.parameterDetails?.[index]?.bindings || [];
        return bindings.length ? bindings.map(binding => binding.name) : [name];
      });
      if (!entryInputs.length) continue;
      const knownInputs = entryInputs.filter(name => {
        const index = parameterIndexForVariable(fn, name);
        return TAINTED_PARAMETER_ROLES.has(roles[index]);
      });
      const unknownInputs = entryInputs.filter(name => !knownInputs.includes(name));
      addEntryRoot(knownInputs, "high");
      addEntryRoot(unknownInputs, "medium");

      function addEntryRoot(variables, confidence) {
        if (!variables.length) return;
        roots.push({
          fn,
          line: fn.line,
          variables,
          step: makeStep("source", entry.title ? "Entry parameters · " + entry.title : "Entry parameters", fn, {
            line: fn.line,
            code: variables.join(", "),
          }, {
            sourceKind: SourceKind.HTTP_INPUT,
            confidence,
            parameterRoles: roles,
          }),
        });
      }
    }
  }
  return dedupeRoots(roots);
}

function selectFunctions(functions, options) {
  if (Array.isArray(options.rootFunctionIds)) {
    const selected = new Set(options.rootFunctionIds);
    return functions.filter(fn => selected.has(fn.id));
  }
  if (!options.absolutePath) return functions;
  const target = normalizePath(options.absolutePath);
  const matches = functions.filter(fn => normalizePath(fn.absolutePath) === target);
  if (!options.line) return matches;
  const containing = matches
    .filter(fn => options.line >= fn.line && options.line <= fn.endLine)
    .sort((a, b) => (a.endLine - a.line) - (b.endLine - b.line));
  return containing.length ? [containing[0]] : matches;
}

function confidenceRank(value) {
  return { high: 0, medium: 1, review: 2 }[value] ?? 3;
}

function makeStep(kind, label, fn, event, extra = {}) {
  return {
    kind,
    label,
    functionId: fn.id,
    symbolKey: fn.symbolKey,
    operationId: event.id,
    functionName: fn.name,
    workspaceRoot: fn.workspaceRoot,
    absolutePath: fn.absolutePath,
    relativePath: fn.relativePath,
    line: event.line || fn.line,
    code: event.code || "",
    ...extra,
  };
}

function dedupeRoots(roots) {
  const seen = new Set();
  return roots.filter(root => {
    const key = [root.fn.workspaceRoot, root.fn.id, root.line, root.variables.slice().sort().join(",")].join(":");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function visitKey(fn, variables) {
  return [fn.workspaceRoot, fn.id, [...variables].sort().join(",")].join(":");
}

function intersects(values, set) {
  return values?.some(value => [...set].some(tainted => pathsOverlap(value, tainted)));
}

function assignmentEvidence(event, tainted, evidence, fn) {
  const outputs = new Map();
  const mode = event.assignmentMode || "expression";
  for (const input of event.variables || []) {
    for (const taintedPath of tainted) {
      const output = rebaseTaint(taintedPath, input, event.target, mode);
      if (!output) continue;
      const fact = assignmentFact(event, taintedPath, output);
      const step = makeStep("propagation", `${taintedPath} → ${output}`, fn, event, {
        analysisStatus: fact.status,
        propagationKind: mode,
        propagationReason: fact.reason,
        inputAccessPath: taintedPath,
        outputAccessPath: output,
      });
      const steps = [...(evidence.get(taintedPath) || []), step];
      const current = outputs.get(output);
      if (!current || steps.length < current.steps.length) outputs.set(output, { output, steps });
    }
  }
  return [...outputs.values()];
}

function removeAssignedEvidence(evidence, target) {
  for (const value of [...evidence.keys()]) if (pathFeeds(target, value)) evidence.delete(value);
}

function bestEvidenceForValues(values, evidence) {
  let best;
  for (const value of values || []) {
    for (const [taintedPath, steps] of evidence) {
      if (!pathsOverlap(value, taintedPath)) continue;
      if (!best || steps.length < best.length) best = steps;
    }
  }
  return best;
}

function sourceDefinesSameValue(fn, assignment) {
  return fn.events.some(event => event.type === "source" && event.line === assignment.line &&
    [event.target, ...(event.variables || [])].some(value =>
      normalizeAccessPath(value) === normalizeAccessPath(assignment.target)));
}

function evidenceDefinesSameValue(evidence, assignment) {
  const target = normalizeAccessPath(assignment.target);
  const steps = evidence.get(target) || [];
  return steps.some(step => step.kind === "call" && step.line === assignment.line);
}

function precedingCallDefinesSameValue(fn, assignment, tainted) {
  const assignmentIndex = fn.events.indexOf(assignment);
  return assignmentIndex >= 0 && fn.events.slice(0, assignmentIndex).some(event =>
    event.type === "call" && event.line === assignment.line && event.target === assignment.target && tainted.has(event.target));
}

function incomingParameterVariables(fn, event, tainted) {
  const incoming = [];
  const parameterOffset = fn.language === "python" && event.receiver && ["self", "cls"].includes(fn.parameters[0]) ? 1 : 0;
  for (let index = parameterOffset; index < fn.parameters.length; index += 1) {
    const argumentIndex = index - parameterOffset;
    if (event.taintArgumentIndexes && !event.taintArgumentIndexes.includes(argumentIndex)) continue;
    const variables = event.argumentVariables[argumentIndex] || [];
    const root = fn.parameters[index];
    const bindings = parameterAccessBindings(fn, index);
    const wholeArgumentTainted = variables.some(value => [...tainted].some(taintedPath => pathFeeds(taintedPath, value)));
    if (wholeArgumentTainted) {
      incoming.push(root, ...bindings.map(binding => binding.name));
      continue;
    }
    const argumentRoot = argumentAccessPath(event.arguments?.[argumentIndex]);
    if (!argumentRoot) continue;
    if (!bindings.length && [...tainted].some(taintedPath => pathsOverlap(argumentRoot, taintedPath))) {
      incoming.push(root);
      continue;
    }
    for (const binding of bindings) {
      const callerPath = appendBindingPath(argumentRoot, binding.path || []);
      if (intersects([callerPath], tainted)) incoming.push(binding.name);
    }
  }
  return unique(incoming);
}

function callAccessPathTransition(fn, event, tainted, incoming) {
  const parameterOffset = fn.language === "python" && event.receiver && ["self", "cls"].includes(fn.parameters[0]) ? 1 : 0;
  for (let argumentIndex = 0; argumentIndex < (event.argumentVariables || []).length; argumentIndex += 1) {
    const input = (event.argumentVariables[argumentIndex] || [])
      .find(value => [...tainted].some(taintedPath => pathsOverlap(value, taintedPath)));
    if (!input) continue;
    const parameter = fn.parameters[argumentIndex + parameterOffset];
    const output = incoming.find(value => value === parameter || value.startsWith(`${parameter}.`) || value.startsWith(`${parameter}[`));
    return {
      inputAccessPath: normalizeAccessPath(input),
      outputAccessPath: normalizeAccessPath(output || parameter),
      propagationReason: `argument ${argumentIndex} maps to parameter ${parameter}`,
    };
  }
  return {};
}

function parameterAccessBindings(fn, index) {
  const root = fn.parameters[index];
  const declared = (fn.parameterDetails?.[index]?.bindings || []).filter(binding => (binding.path || []).length);
  const observed = fn.events.flatMap(event => [
    ...(event.variables || []),
    event.target,
    event.receiver,
    ...(event.argumentVariables || []).flat(),
  ]).flatMap(name => {
    const path = relativeAccessPath(name, root);
    return path?.length ? [{ name: argumentAccessPath(name), path }] : [];
  });
  const uniqueBindings = new Map();
  for (const binding of [...declared, ...observed]) {
    const key = `${binding.name}:${JSON.stringify(binding.path || [])}`;
    if (!uniqueBindings.has(key)) uniqueBindings.set(key, binding);
  }
  return [...uniqueBindings.values()];
}

function relativeAccessPath(value, root) {
  const segments = accessPathSuffix(value, root);
  return segments?.length ? segments : undefined;
}

function argumentAccessPath(value) {
  return normalizeAccessPath(value) || undefined;
}

function appendBindingPath(root, path) {
  return appendAccessPath(root, path);
}

function parameterIndexForVariable(fn, variable) {
  const direct = fn.parameters.indexOf(variable);
  if (direct >= 0) return direct;
  return fn.parameterDetails?.findIndex(parameter => (parameter.bindings || []).some(binding => binding.name === variable)) ?? -1;
}

function isPropertyDescendant(value, parent) {
  const normalizedValue = normalizeAccessPath(value);
  const normalizedParent = normalizeAccessPath(parent);
  return Boolean(normalizedValue && normalizedParent && normalizedValue !== normalizedParent && pathFeeds(normalizedParent, normalizedValue));
}

function controlScopeApplies(control, target, fn) {
  if (Array.isArray(control.guardAppliesToBlocks)) return control.guardAppliesToBlocks.includes(target.blockId);
  if (control.blockId && target.blockId && fn.cfg?.dominators?.[target.blockId]) {
    return fn.cfg.dominators[target.blockId].includes(control.blockId);
  }
  return control.line <= target.line;
}

function controlRelation(control, target, fn) {
  if (!controlScopeApplies(control, target, fn)) return { status: "none", reason: "The guard does not control this sink path." };
  const binding = control.guardBinding;
  const capabilities = control.guardCapabilities || [];
  if (!binding) return {
    status: "hint",
    effectiveCapabilities: [],
    hints: capabilities.map(capability => ({ capability, reason: "No value-level guard association was produced by the frontend." })),
  };
  const effectiveCapabilities = [];
  const hints = [];
  for (const capability of capabilities) {
    const scope = binding.capabilityScopes?.[capability] || {
      applicableSinkKinds: binding.applicableSinkKinds || [],
      outputScoped: binding.outputScoped,
      receiverScoped: binding.receiverScoped,
      requiresTrustedOperand: binding.requiresTrustedOperand,
      requiresSemanticProof: binding.requiresSemanticProof,
      forbidsDirectSinkInput: binding.forbidsDirectSinkInput,
    };
    const reasons = guardCapabilityFailures(scope, binding, target);
    if (reasons.length) reasons.forEach(reason => hints.push({ capability, reason }));
    else effectiveCapabilities.push(capability);
  }
  return { status: effectiveCapabilities.length ? "effective" : "hint", effectiveCapabilities, hints };
}

function guardCapabilityFailures(scope, binding, target) {
  const reasons = [];
  if (scope.applicableSinkKinds?.length && !scope.applicableSinkKinds.includes(target.sinkKind)) {
    reasons.push(`The guard capability does not apply to ${target.sinkKind || "this sink"}.`);
  }
  if (scope.receiverScoped && (!binding.receiver || !target.receiver || canonicalReceiver(binding.receiver) !== canonicalReceiver(target.receiver))) {
    reasons.push("The guard and sink operate on different or unresolved receivers.");
  }
  if (scope.requiresTrustedOperand && !(binding.trustedOperands || []).length) {
    reasons.push("The guard depends on an operand that could not be proven trusted.");
  }
  if (scope.requiresSemanticProof && !["verified", "syntax", "structural"].includes(binding.semanticVerification)) {
    reasons.push("The guard API could not be resolved to a trusted semantic model.");
  }
  if (scope.forbidsDirectSinkInput && !binding.allowsBoundParameters &&
    (binding.inputs || []).length && intersects(target.variables, new Set(binding.inputs))) {
    reasons.push("The sink still consumes the raw value observed by the guard.");
  }
  if (scope.outputScoped) {
    if (!binding.output) reasons.push("The guard return value is not captured, so the protected value cannot be proven.");
    else if (!intersects(target.variables, new Set([binding.output]))) reasons.push("The sink does not consume the value produced by the guard.");
  }
  if (!scope.receiverScoped && !scope.outputScoped) {
    const protectedValues = binding.inputs || [];
    if (protectedValues.length && !intersects(target.variables, new Set(protectedValues))) {
      reasons.push("The guard validates a different value from the one consumed by the sink.");
    }
  }
  return [...new Set(reasons)];
}

function effectiveControlStep(step, relation) {
  return { ...step, guardCapabilities: relation.effectiveCapabilities || [] };
}

function canonicalReceiver(value) {
  return String(value || "").replace(/\?\./g, ".").replace(/\s+/g, "").toLowerCase();
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

module.exports = {
  SOURCE_TOKEN,
  findSourceSinkPaths,
};
