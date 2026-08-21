"use strict";

const crypto = require("crypto");
const { SourceKind } = require("../security/semantics");
const callResolver = require("./call-resolver");
const { functionsFromAnalyses } = require("./ir-adapter");

const SOURCE_TOKEN = "<source>";
// Framework response and pass-through objects never carry attacker-controlled
// data themselves, so they must not seed taint; treating them as input turns
// constant responses like res.send("ok") into findings.
const RESPONSE_OBJECTS = new Set(["res", "response", "reply", "w", "next", "done"]);

function findSourceSinkPaths(analyses, options = {}) {
  const functions = functionsFromAnalyses(analyses);
  const index = callResolver.buildFunctionIndex(functions);
  const selectedFunctions = selectFunctions(functions, options);
  const potentialRanks = buildPotentialRanks(functions, index, Math.min(4, Math.max(1, options.maxDepth || 6)));
  const roots = buildRoots(selectedFunctions, options)
    .sort((left, right) => (potentialRanks.get(right.fn.id) || 0) - (potentialRanks.get(left.fn.id) || 0));
  const paths = [];
  const maxDepth = Math.max(1, options.maxDepth || 6);
  const maxPaths = Math.max(1, options.maxPaths || 80);
  const candidateLimit = Math.min(10000, Math.max(2000, maxPaths * 20));
  const limits = { truncated: false };

  for (const root of roots) {
    if (paths.length >= candidateLimit) { limits.truncated = true; break; }
    const visited = new Set([visitKey(root.fn, root.variables)]);
    walkFlow({
      fn: root.fn,
      tainted: new Set(root.variables),
      startLine: root.line,
      steps: [root.step],
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
    const key = flowPath.steps.map(step => [step.kind, step.relativePath, step.line, step.functionName].join(":")).join("|");
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
  const tainted = new Set(state.tainted);
  let activeSteps = state.steps.slice();
  const addedControls = new Set();

  for (const event of state.fn.events) {
    const functionAnnotationControl = event.type === "control" && event.line <= state.fn.line;
    if (state.paths.length >= state.maxPaths) { state.limits.truncated = true; return; }
    if (event.line < state.startLine && !functionAnnotationControl) continue;
    if (event.type === "assignment") {
      if (intersects(event.variables, tainted)) tainted.add(event.target);
      continue;
    }
    if (event.type === "control") {
      const controlKey = event.line + ":" + event.controlKind;
      if (!addedControls.has(controlKey) && (intersects(event.variables, tainted) || !event.variables.length)) {
        activeSteps = [...activeSteps, makeStep(event.controlKind === "auth" ? "authorization" : "validation", event.label, state.fn, event, {
          guardCapabilities: event.guardCapabilities || [],
        })];
        addedControls.add(controlKey);
      }
      continue;
    }
    if (event.type === "call") {
      const taintedArguments = [];
      event.argumentVariables.forEach((variables, index) => {
        if (intersects(variables, tainted)) taintedArguments.push(index);
      });
      if (!taintedArguments.length) continue;
      if (event.receiver) tainted.add(event.receiver);
      const candidates = callResolver.resolveCandidates(state.index, event, state.fn);
      let returnedFlow;
      for (const resolution of candidates) {
        const candidate = resolution.fn;
        const incoming = unique(taintedArguments.map(index => candidate.parameters[index]).filter(Boolean));
        if (!incoming.length) continue;
        const key = visitKey(candidate, incoming);
        if (state.visited.has(key)) continue;
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
          },
        );
        const visited = new Set(state.visited);
        visited.add(key);
        walkFlow({
          ...state,
          fn: candidate,
          tainted: new Set(incoming),
          startLine: candidate.line,
          steps: [...activeSteps, callStep],
          depth: state.depth + 1,
          visited,
        });
        if (!returnedFlow && event.target) {
          const returned = findTaintedReturn(candidate, incoming, state.index, new Set(state.visited), state.depth + 1, state.maxDepth);
          if (returned) returnedFlow = { candidate, event: returned, callStep };
        }
      }
      if (event.target && returnedFlow) {
        tainted.add(event.target);
        activeSteps = [
          ...activeSteps,
          returnedFlow.callStep,
          makeStep("return", `${returnedFlow.candidate.name}() → ${event.target}`, returnedFlow.candidate, returnedFlow.event),
        ];
      } else if (event.target && !candidates.length) {
        tainted.add(event.target);
        activeSteps = [...activeSteps, makeStep(
          "call",
          `${state.fn.name}() → unresolved ${event.callee}()`,
          state.fn,
          event,
          { candidateCount: 0, candidateMatch: "opaque", candidateReason: "unresolved external or dynamic call" },
        )];
      }
      continue;
    }
    if (event.type === "sink" && intersects(event.variables, tainted)) {
      const sinkStep = makeStep("sink", event.label, state.fn, event, { category: event.category, sinkKind: event.sinkKind });
      const steps = [...activeSteps, sinkStep];
      const files = unique(steps.map(step => step.relativePath));
      const validationCount = steps.filter(step => step.kind === "validation").length;
      const authorizationCount = steps.filter(step => step.kind === "authorization").length;
      const guardCapabilities = unique(steps.flatMap(step => step.guardCapabilities || []));
      const callMatches = steps.filter(step => step.kind === "call").map(step => step.candidateMatch || "medium");
      const confidence = callMatches.includes("review") ? "review" : callMatches.every(match => match === "high") ? "high" : "medium";
      state.paths.push({
        id: shortHash(steps.map(step => [step.kind, step.relativePath, step.line, step.label].join(":")).join("|")),
        source: steps[0],
        sink: sinkStep,
        steps,
        files,
        calls: steps.filter(step => step.kind === "call").length,
        category: event.category || "sensitive operation",
        sourceKind: steps[0].sourceKind || SourceKind.EXTERNAL_INPUT,
        sinkKind: event.sinkKind,
        guardCapabilities,
        confidence,
        controls: { validation: validationCount, authorization: authorizationCount },
        reviewPriority: validationCount || authorizationCount ? "controls-present" : "uncontrolled",
      });
    }
  }
}

function buildPotentialRanks(functions, index, maxDepth) {
  let ranks = new Map(functions.map(fn => [fn.id, Math.max(0, ...fn.events.filter(event => event.type === "sink").map(sinkReviewRank))]));
  for (let depth = 0; depth < maxDepth; depth += 1) {
    const next = new Map(ranks);
    for (const fn of functions) {
      let rank = ranks.get(fn.id) || 0;
      for (const event of fn.events.filter(item => item.type === "call")) {
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
  const tainted = new Set(incoming);
  for (const event of fn.events) {
    if (event.type === "assignment" && intersects(event.variables, tainted)) {
      tainted.add(event.target);
      continue;
    }
    if (event.type === "call" && event.target) {
      const taintedArguments = [];
      event.argumentVariables.forEach((variables, argumentIndex) => {
        if (intersects(variables, tainted)) taintedArguments.push(argumentIndex);
      });
      if (!taintedArguments.length) continue;
      const candidates = callResolver.resolveCandidates(index, event, fn);
      if (!candidates.length) {
        tainted.add(event.target);
        continue;
      }
      for (const resolution of candidates) {
        const candidate = resolution.fn;
        const nextIncoming = unique(taintedArguments.map(argumentIndex => candidate.parameters[argumentIndex]).filter(Boolean));
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
      const inputVariables = event.variables.filter(name => !RESPONSE_OBJECTS.has(name));
      if (!inputVariables.length) continue;
      roots.push({
        fn,
        line: event.line,
        variables: inputVariables,
        step: makeStep("source", event.label || "External input", fn, event, { sourceKind: event.sourceKind }),
      });
    }
    const entryInputs = fn.isEntry ? fn.parameters.filter(name => !RESPONSE_OBJECTS.has(name)) : [];
    if (entryInputs.length) {
      roots.push({
        fn,
        line: fn.line,
        variables: entryInputs,
        step: makeStep("source", fn.entryTitle ? "Entry parameters · " + fn.entryTitle : "Entry parameters", fn, {
          line: fn.line,
          code: entryInputs.join(", "),
        }, { sourceKind: SourceKind.HTTP_INPUT }),
      });
    }
  }
  return dedupeRoots(roots);
}

function selectFunctions(functions, options) {
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
    functionName: fn.name,
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
    const key = [root.fn.id, root.line, root.variables.slice().sort().join(",")].join(":");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function visitKey(fn, variables) {
  return fn.id + ":" + [...variables].sort().join(",");
}

function intersects(values, set) {
  return values?.some(value => set.has(value));
}

function normalizePath(value) {
  return String(value || "").replaceAll("\\", "/").toLowerCase();
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function shortHash(value) {
  return crypto.createHash("sha1").update(value).digest("hex").slice(0, 16);
}

module.exports = {
  SOURCE_TOKEN,
  findSourceSinkPaths,
};
