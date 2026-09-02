"use strict";

const { functionsFromAnalyses } = require("../dataflow/ir-adapter");
const callResolver = require("../dataflow/call-resolver");
const {
  appendAccessPath,
  normalizeAccessPath,
  pathFeeds,
  pathsOverlap,
  relativeAccessPath,
} = require("../ir/access-path");
const { normalizePath, stableHash } = require("../identity");
const { assignmentFact, assignmentInputs, assignmentOutputs, eventConsumes, isReachableEvent } = require("../dataflow/propagation");
const { eventSequences, targetBlocksAtLine } = require("../dataflow/control-flow");
const { applyAssignment, applyCallOutput, applySource } = require("../dataflow/taint-kernel");

const QueryKind = Object.freeze({
  TRACE_BACKWARD: "trace-backward",
  TRACE_FORWARD: "trace-forward",
  FIND_CALLERS: "find-callers",
  FIND_CALLEES: "find-callees",
  TRACE_TO_ENTRY: "trace-to-entry",
  REACHABLE_SINKS: "reachable-sinks",
  EXPLAIN: "explain",
});

const QueryStatus = Object.freeze({
  VERIFIED: "verified",
  SYNTAX_ONLY: "syntax-only",
  HEURISTIC: "heuristic",
  UNRESOLVED: "unresolved",
});

function runAuditQuery(analyses, request = {}) {
  const context = createContext(analyses, request);
  const fn = selectFunction(context.functions, request);
  if (!fn) return emptyResult(request, "No indexed function contains the requested location.");
  const limits = {
    maxDepth: Math.min(16, Math.max(1, Number(request.maxDepth) || 8)),
    maxNodes: Math.min(1000, Math.max(20, Number(request.maxNodes) || 250)),
    nodes: 0,
    truncated: false,
  };
  const variable = normalizeAccessPath(request.identifier) || inferVariable(fn, request.line);
  let roots;
  let title;
  switch (request.kind) {
    case QueryKind.TRACE_BACKWARD:
      title = `Trace Backward · ${variable || fn.name}`;
      roots = variable ? backwardVariable(context, fn, variable, request.line || fn.endLine, new Set(), 0, limits) : [missingVariable(fn)];
      break;
    case QueryKind.TRACE_FORWARD:
      title = `Trace Forward · ${variable || fn.name}`;
      roots = variable ? forwardVariable(context, fn, variable, request.line || fn.line, new Set(), 0, limits) : [missingVariable(fn)];
      break;
    case QueryKind.FIND_CALLERS:
      title = `Find Callers · ${fn.name}`;
      roots = callerNodes(context, fn, limits);
      break;
    case QueryKind.FIND_CALLEES:
      title = `Find Callees · ${fn.name}`;
      roots = calleeNodes(context, fn, limits);
      break;
    case QueryKind.TRACE_TO_ENTRY:
      title = `Trace to Entry Point · ${fn.name}`;
      roots = traceToEntries(context, fn, new Set(), 0, limits);
      break;
    case QueryKind.REACHABLE_SINKS:
      title = `Reachable Sinks · ${fn.name}`;
      roots = reachableSinks(context, fn, new Set(), 0, limits);
      break;
    case QueryKind.EXPLAIN:
      title = `Explain Analysis Here · ${fn.name}`;
      roots = explainHere(context, fn, request, limits);
      break;
    default:
      return emptyResult(request, `Unknown audit query: ${request.kind || "<missing>"}.`);
  }
  const resolvedRoots = roots.length ? roots : [queryNode({
    kind: "empty",
    label: "No matching result",
    status: QueryStatus.UNRESOLVED,
    reason: noResultReason(request.kind, fn, variable),
    fn,
  })];
  if (request.indexIncomplete && isWorkspaceGraphQuery(request.kind)) {
    resolvedRoots.unshift(partialIndexNode(fn, request));
  }
  return {
    schema: "traceguard-audit-query",
    version: 1,
    kind: request.kind,
    title,
    subject: { functionId: fn.id, functionName: fn.name, variable, location: functionLocation(fn) },
    roots: resolvedRoots,
    summary: summarize(resolvedRoots, limits),
    truncated: limits.truncated,
    coverage: queryCoverage(request),
  };
}

function createContext(analyses, request) {
  const functions = functionsFromAnalyses(analyses || [], request);
  const functionIndex = callResolver.buildFunctionIndex(functions);
  const byId = new Map(functions.map(fn => [fn.id, fn]));
  const incoming = new Map();
  const outgoing = new Map();
  const unresolved = new Map();
  for (const caller of functions) {
    const calls = [];
    const missing = [];
    for (const event of caller.events.filter(item => item.type === "call" && item.callee && isReachableEvent(item))) {
      const resolutions = callResolver.resolveCandidates(functionIndex, event, caller);
      if (!resolutions.length) {
        missing.push({ caller, event });
        continue;
      }
      for (const resolution of resolutions) {
        const edge = { caller, event, callee: resolution.fn, resolution };
        calls.push(edge);
        if (!incoming.has(resolution.fn.id)) incoming.set(resolution.fn.id, []);
        incoming.get(resolution.fn.id).push(edge);
      }
    }
    outgoing.set(caller.id, calls);
    unresolved.set(caller.id, missing);
  }
  const analysisByPath = new Map((analyses || []).map(analysis => [normalizePath(analysis.absolutePath), analysis]));
  return { analyses: analyses || [], functions, functionIndex, byId, incoming, outgoing, unresolved, analysisByPath, request };
}

function selectFunction(functions, request) {
  if (request.functionId) {
    const exact = functions.find(fn => fn.id === request.functionId || fn.symbolKey === request.functionId);
    if (exact) return exact;
  }
  if (!request.absolutePath) return undefined;
  const target = normalizePath(request.absolutePath);
  const matches = functions.filter(fn => normalizePath(fn.absolutePath) === target);
  if (!request.line) return matches[0];
  return matches.filter(fn => request.line >= fn.line && request.line <= fn.endLine)
    .sort((left, right) => (left.endLine - left.line) - (right.endLine - right.line))[0] ||
    matches.sort((left, right) => Math.abs(left.line - request.line) - Math.abs(right.line - request.line))[0];
}

function backwardVariable(context, fn, variable, beforeLine, visiting, depth, limits) {
  if (!reserve(limits)) return [truncatedNode(fn)];
  const key = `back:${fn.id}:${variable}:${beforeLine}`;
  if (visiting.has(key) || depth > limits.maxDepth) return [cycleNode(fn, variable, depth > limits.maxDepth)];
  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const definitions = latestDefinitions(fn, variable, beforeLine);
  if (definitions.length) return definitions.map(event => {
    const children = [];
    if (event.type === "source") {
      children.push(queryNode({ kind: "source", label: event.label || `Source · ${variable}`, status: eventStatus(event), reason: sourceReason(event), fn, event }));
      if (fn.isEntry) children.push(...entryNodes(fn, variable));
    } else if (event.type === "assignment") {
      for (const input of assignmentInputs(event, variable)) {
        children.push(...backwardVariable(context, fn, input, event.line, nextVisiting, depth + 1, limits));
      }
    } else if (event.type === "call") {
      const callees = context.outgoing.get(fn.id)?.filter(edge => edge.event.id === event.id) || [];
      if (!callees.length) children.push(unresolvedCallNode(fn, event));
      for (const edge of callees) {
        const returns = edge.callee.events.filter(item => item.type === "return" && item.variables?.length);
        const returnChildren = returns.flatMap(item => item.variables.flatMap(input =>
          backwardVariable(context, edge.callee, input, item.line, nextVisiting, depth + 1, limits)));
        children.push(callNode(edge, returnChildren.length ? returnChildren : [queryNode({
          kind: "return",
          label: `No modeled return value from ${edge.callee.name}()` ,
          status: QueryStatus.UNRESOLVED,
          reason: "The callee was resolved, but its return operation does not expose a symbolic value.",
          fn: edge.callee,
        })]));
      }
    }
    return queryNode({
      kind: event.type,
      label: definitionLabel(event, variable),
      status: eventStatus(event),
      reason: definitionReason(event, variable),
      fn,
      event,
      children,
    });
  });

  const parameter = parameterForVariable(fn, variable);
  if (parameter) {
    const callers = context.incoming.get(fn.id) || [];
    if (!callers.length) {
      if (fn.isEntry) return entryNodes(fn, variable);
      return [queryNode({
        kind: "parameter",
        label: `Parameter · ${variable}`,
        status: QueryStatus.UNRESOLVED,
        reason: "The value is a function parameter, but no indexed caller or entry binding reaches this function.",
        fn,
      })];
    }
    return callers.map(edge => {
      const callerValues = callerValuesForParameter(edge.event, parameter, edge.callee);
      const children = callerValues.length
        ? callerValues.flatMap(value => backwardVariable(context, edge.caller, value, edge.event.line, nextVisiting, depth + 1, limits))
        : [queryNode({ kind: "argument", label: `Argument ${parameter.index + 1} was not resolved`, status: QueryStatus.UNRESOLVED,
          reason: "The call was resolved, but the argument expression could not be converted to an Access Path.", fn: edge.caller, event: edge.event })];
      return callNode(edge, children, `Parameter ${variable} is supplied by argument ${parameter.index + 1}.`);
    });
  }
  return [queryNode({
    kind: "unknown-origin",
    label: `Origin unresolved · ${variable}`,
    status: QueryStatus.UNRESOLVED,
    reason: "No preceding Source, assignment, call return, parameter binding or indexed caller defines this Access Path.",
    fn,
  })];
}

function forwardVariable(context, fn, variable, afterLine, visiting, depth, limits) {
  if (!reserve(limits)) return [truncatedNode(fn)];
  const key = `forward:${fn.id}:${variable}:${afterLine}`;
  if (visiting.has(key) || depth > limits.maxDepth) return [cycleNode(fn, variable, depth > limits.maxDepth)];
  const nextVisiting = new Set(visiting);
  nextVisiting.add(key);
  const consumers = fn.events.filter(event => event.line >= afterLine && isReachableEvent(event) &&
    eventConsumes(event, variable) && taintReachesEventOnSomePath(fn, variable, afterLine, event));
  const roots = [];
  for (const event of consumers) {
    if (!reserve(limits)) { roots.push(truncatedNode(fn)); break; }
    if (event.type === "assignment" && event.target) {
      const outputs = assignmentOutputs(event, [variable]);
      for (const output of outputs) roots.push(queryNode({
        kind: "assignment",
        label: `${variable} → ${output}`,
        status: eventStatus(event),
        reason: assignmentFact(event, variable, output).reason,
        fn,
        event,
        details: { assignmentMode: event.assignmentMode || "expression", input: variable, output },
        children: forwardVariable(context, fn, output, event.line + 1, nextVisiting, depth + 1, limits),
      }));
      continue;
    }
    if (event.type === "sink") {
      roots.push(queryNode({ kind: "sink", label: event.label || `Sink · ${event.sinkKind || event.category}`,
        status: eventStatus(event), reason: `${variable} is consumed by a modeled ${event.sinkKind || event.category || "sensitive"} operation.`, fn, event }));
      continue;
    }
    if (event.type === "call") {
      const edges = context.outgoing.get(fn.id)?.filter(edge => edge.event.id === event.id) || [];
      if (!edges.length) { roots.push(unresolvedCallNode(fn, event)); continue; }
      for (const edge of edges) {
        const mappings = calleeValuesForCallerVariable(edge, variable);
        const children = mappings.length
          ? mappings.flatMap(value => forwardVariable(context, edge.callee, value, edge.callee.line, nextVisiting, depth + 1, limits))
          : [queryNode({ kind: "argument", label: "Argument mapping unresolved", status: QueryStatus.UNRESOLVED,
            reason: "The call target was resolved, but the selected Access Path could not be mapped to a callee parameter.", fn: edge.callee })];
        roots.push(callNode(edge, children, `${variable} reaches ${edge.callee.name}() through ${mappings.join(", ") || "an unresolved argument"}.`));
      }
      continue;
    }
    if (event.type === "return") {
      const callers = context.incoming.get(fn.id) || [];
      if (!callers.length) roots.push(queryNode({ kind: "return", label: `Return · ${variable}`, status: eventStatus(event),
        reason: "The value is returned, but no indexed caller consumes this function.", fn, event }));
      for (const edge of callers) {
        if (!edge.event.target) {
          roots.push(callNode(edge, [queryNode({ kind: "return", label: "Return value is ignored", status: QueryStatus.VERIFIED,
            reason: "The caller invokes the function without assigning its return value.", fn: edge.caller, event: edge.event })]));
        } else {
          roots.push(callNode(edge, forwardVariable(context, edge.caller, edge.event.target, edge.event.line + 1, nextVisiting, depth + 1, limits),
            `The return value is assigned to ${edge.event.target} in ${edge.caller.name}().`));
        }
      }
      continue;
    }
    if (event.type === "control") roots.push(queryNode({ kind: "guard", label: event.label || "Guard",
      status: eventStatus(event), reason: `${variable} participates in this control or validation operation; effectiveness remains sink-specific.`, fn, event }));
  }
  return dedupeNodes(roots);
}

function taintReachesEventOnSomePath(fn, variable, afterLine, targetEvent) {
  const sequences = eventSequences(fn, {
    startLine: afterLine,
    targetBlocks: targetEvent.blockId ? [targetEvent.blockId] : [],
    includeTarget: true,
    maxPaths: 64,
    maxVisits: 3,
  });
  return sequences.some(events => {
    let tainted = new Set([variable]);
    for (const event of events) {
      if (event.id === targetEvent.id) return eventConsumes(event, variable) && [...tainted].some(value => pathsOverlap(value, variable));
      if (event.type === "assignment" && event.target) {
        if (event.line === afterLine && pathFeeds(event.target, variable)) continue;
        tainted = applyAssignment(tainted, event).tainted;
        continue;
      }
      if (event.type === "source" && event.target && event.line > afterLine) {
        tainted = applySource(tainted, event);
        continue;
      }
      if (event.type === "call" && event.target) {
        const propagates = (event.argumentVariables || []).some((variables, index) =>
          (!event.taintArgumentIndexes || event.taintArgumentIndexes.includes(index)) &&
          variables.some(value => [...tainted].some(current => pathsOverlap(current, value))));
        tainted = applyCallOutput(tainted, event, propagates);
      }
    }
    return false;
  });
}

function callerNodes(context, fn, limits) {
  return (context.incoming.get(fn.id) || []).map(edge => {
    reserve(limits);
    return callNode(edge, [], `${edge.caller.name}() calls ${fn.name}() at this location.`);
  });
}

function calleeNodes(context, fn, limits) {
  const nodes = (context.outgoing.get(fn.id) || []).map(edge => {
    reserve(limits);
    return callNode(edge, [], `${fn.name}() calls ${edge.callee.name}() at this location.`);
  });
  for (const missing of context.unresolved.get(fn.id) || []) {
    reserve(limits);
    nodes.push(unresolvedCallNode(missing.caller, missing.event));
  }
  return nodes;
}

function traceToEntries(context, fn, visiting, depth, limits) {
  if (!reserve(limits)) return [truncatedNode(fn)];
  if (fn.isEntry) return entryNodes(fn);
  if (depth > limits.maxDepth || visiting.has(fn.id)) return [cycleNode(fn, fn.name, depth > limits.maxDepth)];
  const next = new Set(visiting);
  next.add(fn.id);
  const callers = context.incoming.get(fn.id) || [];
  if (!callers.length) return [queryNode({ kind: "entry", label: "No indexed entry reaches this function", status: QueryStatus.UNRESOLVED,
    reason: "Reverse call-graph traversal stopped because the function has no resolved callers and is not an entry point.", fn })];
  return callers.map(edge => callNode(edge, traceToEntries(context, edge.caller, next, depth + 1, limits),
    `${edge.caller.name}() is a resolved caller on a possible path toward an entry point.`));
}

function reachableSinks(context, fn, visiting, depth, limits) {
  if (!reserve(limits)) return [truncatedNode(fn)];
  if (depth > limits.maxDepth || visiting.has(fn.id)) return [cycleNode(fn, fn.name, depth > limits.maxDepth)];
  const next = new Set(visiting);
  next.add(fn.id);
  const nodes = fn.events.filter(event => event.type === "sink" && isReachableEvent(event)).map(event => queryNode({
    kind: "sink",
    label: event.label || event.sinkKind || "Sensitive operation",
    status: eventStatus(event),
    reason: "This sink is present in the current function. This query proves call reachability, not necessarily taint reachability.",
    fn,
    event,
  }));
  for (const edge of context.outgoing.get(fn.id) || []) {
    const children = reachableSinks(context, edge.callee, next, depth + 1, limits);
    if (children.some(node => node.kind !== "empty" && node.status !== QueryStatus.UNRESOLVED)) {
      nodes.push(callNode(edge, children, `${edge.callee.name}() is reachable through this call edge.`));
    }
  }
  for (const missing of context.unresolved.get(fn.id) || []) nodes.push(unresolvedCallNode(missing.caller, missing.event));
  return dedupeNodes(nodes);
}

function explainHere(context, fn, request, limits) {
  const analysis = context.analysisByPath.get(normalizePath(fn.absolutePath));
  const frontend = analysis?.ir?.frontend || analysis?.frontend || { mode: "unknown", capability: "fallback" };
  const line = Number(request.line) || fn.line;
  const exact = fn.events.filter(event => event.line === line && isReachableEvent(event));
  const nearby = exact.length ? exact : fn.events.filter(event => isReachableEvent(event) && Math.abs(event.line - line) <= 1);
  const operationNodes = nearby.map(event => {
    reserve(limits);
    const children = [];
    if (event.type === "call") {
      const edges = context.outgoing.get(fn.id)?.filter(edge => edge.event.id === event.id) || [];
      if (!edges.length) children.push(unresolvedCallNode(fn, event));
      else children.push(...edges.map(edge => callNode(edge, [], callReason(edge))));
    }
    return queryNode({
      kind: event.type,
      label: `${event.type} · ${event.label || event.callee || event.target || event.variables?.join(", ") || "operation"}`,
      status: eventStatus(event),
      reason: operationExplanation(event),
      fn,
      event,
      children,
      details: {
        inputs: event.variables || [],
        output: event.target,
        semanticModelId: event.semanticModelId,
        semanticVerification: event.semanticVerification,
        candidateStatus: event.candidateStatus,
        certainty: event.certainty,
        blockId: event.blockId,
        assignmentMode: event.assignmentMode,
        propagationReason: event.propagationReason,
        propagationStatus: event.propagationStatus,
      },
    });
  });
  const parameterIssues = (fn.parameterDetails || []).filter(parameter => !parameter.role || parameter.role === "unknown").map(parameter =>
    queryNode({ kind: "parameter", label: `Unknown parameter role · ${parameter.name}`, status: QueryStatus.HEURISTIC,
      reason: "The frontend could not prove whether this parameter is request data, a response object, context or a service dependency.", fn }));
  const unresolvedCalls = (context.unresolved.get(fn.id) || []).map(item => unresolvedCallNode(fn, item.event));
  return [queryNode({
    kind: "analysis",
    label: `${fn.name}${fn.isEntry ? " · entry point" : ""}`,
    status: frontend.mode === "ast" && !frontend.degraded ? QueryStatus.VERIFIED : frontend.mode === "ast" ? QueryStatus.SYNTAX_ONLY : QueryStatus.HEURISTIC,
    reason: frontendReason(frontend),
    fn,
    details: {
      frontend,
      symbolKey: fn.symbolKey,
      language: fn.language,
      signature: analysis?.ir?.functions?.find(item => item.id === fn.id)?.signature,
      entryPoints: fn.entryPoints || [],
    },
    children: [
      ...operationNodes,
      ...parameterIssues,
      ...unresolvedCalls,
      ...(!operationNodes.length ? [queryNode({ kind: "gap", label: "No IR operation at this line", status: QueryStatus.UNRESOLVED,
        reason: "The AST frontend parsed the function, but this source line did not produce a Source, assignment, call, return, branch, Guard or Sink fact.", fn })] : []),
    ],
  })];
}

function latestDefinitions(fn, variable, beforeLine) {
  const targetBlocks = targetBlocksAtLine(fn, beforeLine);
  const sequences = eventSequences(fn, {
    startLine: fn.line,
    targetBlocks,
    includeTarget: false,
    maxPaths: 64,
    maxVisits: 3,
  });
  const definitions = [];
  for (const events of sequences) {
    const matches = events.filter(event => event.line <= beforeLine && event.target && pathFeeds(event.target, variable));
    if (matches.length) definitions.push(matches.at(-1));
  }
  const uniqueDefinitions = new Map(definitions.map(event => [event.id, event]));
  if (uniqueDefinitions.size) return [...uniqueDefinitions.values()];
  const fallback = fn.events.filter(event => event.line <= beforeLine && isReachableEvent(event) && event.target && pathFeeds(event.target, variable));
  if (!fallback.length) return [];
  const line = Math.max(...fallback.map(event => event.line));
  return fallback.filter(event => event.line === line);
}

function parameterForVariable(fn, variable) {
  for (let index = 0; index < fn.parameters.length; index += 1) {
    const root = fn.parameters[index];
    if (pathFeeds(root, variable)) return { index, root, path: relativeAccessPath(variable, root) || [] };
    for (const binding of fn.parameterDetails?.[index]?.bindings || []) {
      if (pathFeeds(binding.name, variable)) {
        return { index, root, path: [...(binding.path || []), ...(relativeAccessPath(variable, binding.name) || [])] };
      }
    }
  }
  return undefined;
}

function callerValuesForParameter(event, parameter, callee) {
  const offset = callee?.language === "python" && event.receiver && ["self", "cls"].includes(callee.parameters?.[0]) ? 1 : 0;
  const argumentIndex = parameter.index - offset;
  if (argumentIndex < 0) return [];
  const argument = normalizeAccessPath(event.arguments?.[argumentIndex]);
  const variables = event.argumentVariables?.[argumentIndex] || [];
  if (parameter.path.length && argument) return [appendAccessPath(argument, parameter.path)];
  if (parameter.path.length) return variables.map(value => appendAccessPath(value, parameter.path));
  return variables.length ? variables : argument ? [argument] : [];
}

function calleeValuesForCallerVariable(edge, variable) {
  const values = [];
  const offset = edge.callee.language === "python" && edge.event.receiver && ["self", "cls"].includes(edge.callee.parameters?.[0]) ? 1 : 0;
  edge.event.argumentVariables.forEach((variables, index) => {
    const argument = normalizeAccessPath(edge.event.arguments?.[index]);
    const parameter = edge.callee.parameters[index + offset];
    if (!parameter) return;
    if ((variables || []).some(value => pathFeeds(variable, value))) values.push(parameter);
    else if (argument && pathFeeds(argument, variable)) {
      values.push(appendAccessPath(parameter, relativeAccessPath(variable, argument) || []));
    }
  });
  return unique(values);
}

function inferVariable(fn, line) {
  const events = fn.events.filter(event => event.line === line);
  return events.find(event => event.target)?.target || events.flatMap(event => event.variables || [])[0];
}

function entryNodes(fn, variable) {
  const entries = fn.entryPoints?.length ? fn.entryPoints : fn.entryTitle ? [{ title: fn.entryTitle }] : [];
  return (entries.length ? entries : [{ title: fn.name }]).map(entry => queryNode({
    kind: "entry",
    label: entry.title || `${entry.method || "REQUEST"} ${entry.route || "<dynamic>"}`,
    status: entry.route === "<dynamic>" ? QueryStatus.SYNTAX_ONLY : QueryStatus.VERIFIED,
    reason: variable ? `${variable} is bound to a parameter of this indexed entry point.` : "The frontend bound this function to a framework or runtime entry point.",
    fn,
    details: entry,
  }));
}

function callNode(edge, children = [], reason) {
  return queryNode({
    kind: "call",
    label: `${edge.caller.name}() → ${edge.callee.name}()`,
    status: callStatus(edge.resolution),
    reason: reason || callReason(edge),
    fn: edge.caller,
    event: edge.event,
    children,
    details: { candidateMatch: edge.resolution.quality, candidateReason: edge.resolution.reason, calleePath: edge.callee.relativePath },
  });
}

function unresolvedCallNode(fn, event) {
  return queryNode({
    kind: "call",
    label: `Unresolved call · ${event.callee || "<dynamic>"}()`,
    status: QueryStatus.UNRESOLVED,
    reason: "No indexed function could be selected using module, receiver, file and language evidence. External libraries and dynamic dispatch may stop the query here.",
    fn,
    event,
  });
}

function queryNode(input) {
  const location = input.event ? eventLocation(input.fn, input.event) : input.fn ? functionLocation(input.fn) : undefined;
  const node = {
    id: `query_${stableHash(JSON.stringify([input.kind, input.label, location?.absolutePath, location?.line, input.reason]))}`,
    kind: input.kind || "step",
    label: input.label || "Analysis step",
    status: input.status || QueryStatus.HEURISTIC,
    reason: input.reason || "No connection explanation was produced.",
    location,
    details: input.details || {},
    children: dedupeNodes(input.children || []),
  };
  return node;
}

function eventStatus(event) {
  if (event.propagationStatus === "verified") return QueryStatus.VERIFIED;
  if (event.propagationStatus === "syntax-only") return QueryStatus.SYNTAX_ONLY;
  if (event.propagationStatus === "heuristic") return QueryStatus.HEURISTIC;
  if (event.propagationStatus === "unresolved") return QueryStatus.UNRESOLVED;
  if (event.semanticVerification === "verified") return QueryStatus.VERIFIED;
  if (event.semanticVerification === "syntax" || event.certainty === "medium") return QueryStatus.SYNTAX_ONLY;
  if (event.certainty === "low" || /unverified|candidate|regex/.test(event.candidateStatus || "")) return QueryStatus.HEURISTIC;
  return QueryStatus.VERIFIED;
}

function callStatus(resolution) {
  if (resolution?.quality === "high") return QueryStatus.VERIFIED;
  if (resolution?.quality === "medium") return QueryStatus.SYNTAX_ONLY;
  return resolution ? QueryStatus.HEURISTIC : QueryStatus.UNRESOLVED;
}

function definitionLabel(event, variable) {
  if (event.type === "source") return `${event.label || "Source"} → ${event.target || variable}`;
  if (event.type === "assignment") return `${(event.variables || []).join(" + ") || "value"} → ${event.target}`;
  if (event.type === "call") return `${event.callee || "call"}() → ${event.target || variable}`;
  return `${event.type} → ${variable}`;
}

function definitionReason(event, variable) {
  if (event.type === "source") return sourceReason(event);
  if (event.type === "assignment") return event.propagationReason ||
    `This is the latest preceding ${event.assignmentMode || "expression"} assignment whose output Access Path can feed ${variable}.`;
  if (event.type === "call") return `${variable} receives the return value of this call; resolved callee returns are expanded below.`;
  return `${variable} is produced by this IR operation.`;
}

function sourceReason(event) {
  return `The frontend classified this operation as ${event.sourceKind || "external input"}${event.semanticModelId ? ` using ${event.semanticModelId}` : ""}.`;
}

function callReason(edge) {
  return `Call target selected by ${edge.resolution.reason}; match quality is ${edge.resolution.quality}.`;
}

function operationExplanation(event) {
  const pieces = [`The frontend emitted a ${event.type} IR operation.`];
  if (event.propagationReason) pieces.push(event.propagationReason);
  if (event.semanticModelId) pieces.push(`Semantic model: ${event.semanticModelId}.`);
  if (event.semanticVerification) pieces.push(`Verification: ${event.semanticVerification}.`);
  if (event.candidateStatus) pieces.push(`Candidate status: ${event.candidateStatus}.`);
  if (event.type === "control") pieces.push("Guard effectiveness is checked against each sink, value, receiver and CFG dominance relation.");
  return pieces.join(" ");
}

function frontendReason(frontend) {
  if (frontend.mode === "ast" && !frontend.degraded) return `Parsed by ${frontend.id || "an AST frontend"} without reported degradation.`;
  if (frontend.mode === "ast") return `AST parsing completed with degraded capability: ${frontend.degradedReason || frontend.capability || "unknown reason"}.`;
  return `Analysis used ${frontend.mode || "fallback"} mode; results derived only from patterns remain heuristic.`;
}

function eventLocation(fn, event) {
  return { absolutePath: fn.absolutePath, relativePath: fn.relativePath, line: event.line || fn.line, endLine: event.line || fn.line, code: event.code || "" };
}

function functionLocation(fn) {
  return { absolutePath: fn.absolutePath, relativePath: fn.relativePath, line: fn.line, endLine: fn.endLine, code: "" };
}

function reserve(limits) {
  limits.nodes += 1;
  if (limits.nodes <= limits.maxNodes) return true;
  limits.truncated = true;
  return false;
}

function truncatedNode(fn) {
  return queryNode({ kind: "limit", label: "Query truncated", status: QueryStatus.UNRESOLVED,
    reason: "The query reached its node limit. Narrow the starting symbol or increase the configured query limit.", fn });
}

function cycleNode(fn, variable, depthLimit) {
  return queryNode({ kind: "cycle", label: depthLimit ? "Maximum query depth reached" : `Cycle · ${variable}`,
    status: QueryStatus.HEURISTIC, reason: depthLimit ? "Traversal stopped at the configured depth limit." : "Traversal stopped because this function/value state was already visited.", fn });
}

function missingVariable(fn) {
  return queryNode({ kind: "selection", label: "Select an identifier", status: QueryStatus.UNRESOLVED,
    reason: "Backward and forward queries require a selected identifier or an IR value on the current line.", fn });
}

function emptyResult(request, reason) {
  const roots = [queryNode({ kind: "empty", label: "Query could not start", status: QueryStatus.UNRESOLVED, reason })];
  if (request.indexIncomplete && isWorkspaceGraphQuery(request.kind)) roots.unshift(partialIndexNode(undefined, request));
  return {
    schema: "traceguard-audit-query",
    version: 1,
    kind: request.kind,
    title: "TraceGuard Audit Query",
    roots,
    summary: summarize(roots, { truncated: false }),
    truncated: false,
    coverage: queryCoverage(request),
  };
}

function isWorkspaceGraphQuery(kind) {
  return [QueryKind.FIND_CALLERS, QueryKind.FIND_CALLEES, QueryKind.TRACE_TO_ENTRY, QueryKind.REACHABLE_SINKS].includes(kind);
}

function queryCoverage(request) {
  return {
    incomplete: Boolean(request.indexIncomplete),
    scope: request.indexScope || (request.indexIncomplete ? "partial" : "workspace"),
    skippedFiles: Math.max(0, Number(request.indexSkippedFiles) || 0),
    workspaceGraph: isWorkspaceGraphQuery(request.kind),
  };
}

function partialIndexNode(fn, request) {
  const skipped = Number(request.indexSkippedFiles) || 0;
  return queryNode({
    kind: "coverage",
    label: "Partial workspace index",
    status: QueryStatus.UNRESOLVED,
    reason: request.indexScope === "current-files"
      ? "Only currently opened or refreshed files are indexed. Missing callers, entries and sinks must not be interpreted as proof that none exist."
      : `The workspace index is incomplete${skipped ? ` because ${skipped} file${skipped === 1 ? " was" : "s were"} skipped` : ""}. Missing graph results may exist outside analyzed files.`,
    fn,
    details: queryCoverage(request),
  });
}

function noResultReason(kind, fn, variable) {
  if (kind === QueryKind.FIND_CALLERS) return `${fn.name}() has no resolved indexed callers.`;
  if (kind === QueryKind.FIND_CALLEES) return `${fn.name}() has no resolved or unresolved call operations.`;
  if (kind === QueryKind.REACHABLE_SINKS) return `No modeled sink is reachable from ${fn.name}() within the query depth.`;
  return `No path was found for ${variable || fn.name}.`;
}

function summarize(roots, limits) {
  const flat = flattenNodes(roots);
  const statuses = Object.fromEntries(Object.values(QueryStatus).map(status => [status, flat.filter(node => node.status === status).length]));
  return { nodes: flat.length, statuses, truncated: limits.truncated };
}

function flattenNodes(nodes) {
  return (nodes || []).flatMap(node => [node, ...flattenNodes(node.children)]);
}

function dedupeNodes(nodes) {
  const seen = new Set();
  return (nodes || []).filter(node => {
    const key = `${node.kind}:${node.label}:${node.location?.absolutePath || ""}:${node.location?.line || 0}:${node.reason}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function unique(values) { return [...new Set((values || []).filter(Boolean))]; }

function formatQueryMarkdown(result) {
  const lines = [`# ${result.title}`, "", `Nodes: ${result.summary?.nodes || 0}${result.truncated ? " (truncated)" : ""}`, ""];
  for (const root of result.roots || []) appendMarkdownNode(lines, root, 0);
  return lines.join("\n");
}

function appendMarkdownNode(lines, node, depth) {
  const location = node.location?.relativePath ? ` — ${node.location.relativePath}:${node.location.line}` : "";
  lines.push(`${"  ".repeat(depth)}- **[${node.status}] ${node.label}**${location}`);
  lines.push(`${"  ".repeat(depth + 1)}- ${node.reason}`);
  for (const child of node.children || []) appendMarkdownNode(lines, child, depth + 1);
}

module.exports = { QueryKind, QueryStatus, formatQueryMarkdown, runAuditQuery };
