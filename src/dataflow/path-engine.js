"use strict";

const { normalizePath, stableHash } = require("../identity");
const { GuardCapability, SourceExposure, SourceKind, sourceExposureForKind } = require("../security/semantics");
const callResolver = require("./call-resolver");
const {
  appendAccessPath,
  normalizeAccessPath,
  pathFeeds,
  pathsOverlap,
  rebaseTaint,
  relativeAccessPath: accessPathSuffix,
} = require("../ir/access-path");
const { functionsFromAnalyses } = require("./ir-adapter");
const catalog = require("../security/catalog");
const { assignmentFact, isReachableEvent } = require("./propagation");
const { applyAssignment } = require("./taint-kernel");
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
  const startedAt = performance.now();
  const deadlineClock = typeof options._deadlineClock === "function" ? options._deadlineClock : () => performance.now();
  const maxAnalysisMs = boundedInteger(options.maxAnalysisMs, 3000, 50, 60000);
  const deadline = deadlineClock() + maxAnalysisMs;
  const functions = options._flowFunctions || functionsFromAnalyses(analyses, options);
  const index = options._functionIndex || callResolver.buildFunctionIndex(functions);
  const selectedFunctions = selectFunctions(functions, options);
  const maxDepth = boundedInteger(options.maxDepth, 6, 1, 30);
  const potentialRanks = Array.isArray(options.rootFunctionIds)
    ? new Map()
    : buildPotentialRanks(functions, index, Math.min(4, maxDepth));
  const roots = buildRoots(selectedFunctions, options, index)
    .sort((left, right) => rootReviewRank(right, potentialRanks) - rootReviewRank(left, potentialRanks) ||
      left.fn.relativePath.localeCompare(right.fn.relativePath) || left.line - right.line);
  const rankingMs = performance.now() - startedAt;
  const paths = [];
  const maxPaths = Math.max(1, options.maxPaths || 80);
  const candidateLimit = Math.min(10000, Math.max(2000, maxPaths * 20));
  const limits = {
    truncated: false,
    reasons: new Set(),
    partialRoots: new Map(),
    currentRoot: undefined,
    exploredStates: 0,
    visitedEvents: 0,
    maxExploredStates: boundedInteger(options.maxFlowStates, Math.max(1000, Math.min(10000, maxPaths * 10)), 100, 50000),
    maxVisitedEvents: boundedInteger(options.maxFlowEvents, Math.max(100000, Math.min(2000000, maxPaths * 1000)), 10000, 5000000),
    maxCfgPathsPerFunction: boundedInteger(options.maxCfgPathsPerFunction, 24, 1, 96),
    maxCallCandidates: boundedInteger(options.maxCallCandidates, 16, 1, 64),
    maxHigherOrderDepth: boundedInteger(options.maxHigherOrderDepth, 8, 1, 64),
    maxAsyncDepth: boundedInteger(options.maxAsyncDepth, 8, 1, 64),
    maxStatesPerRoot: boundedInteger(options.maxFlowStatesPerRoot, 32, 1, 500),
    maxEventsPerRoot: boundedInteger(options.maxFlowEventsPerRoot, 10000, 100, 100000),
    maxTraceSteps: boundedInteger(options.maxTraceSteps, 30, 5, 200),
    maxAnalysisMs,
    deadline,
    deadlineClock,
    currentRootStates: 0,
    currentRootEvents: 0,
  };

  let processedRoots = 0;
  for (let rootIndex = 0; rootIndex < roots.length; rootIndex += 1) {
    if (analysisExpired(limits)) break;
    const root = roots[rootIndex];
    if (paths.length >= candidateLimit) { truncate(limits, "path-candidate-budget"); break; }
    if (limits.exploredStates >= limits.maxExploredStates) { truncate(limits, "flow-state-budget"); break; }
    if (limits.visitedEvents >= limits.maxVisitedEvents) { truncate(limits, "flow-event-budget"); break; }
    limits.currentRootStates = 0;
    limits.currentRootEvents = 0;
    limits.currentRoot = flowRootIdentity(root);
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
      versions: new Map(),
      depth: 0,
      higherOrderDepth: 0,
      asyncDepth: 0,
      visited,
      index,
      paths,
      maxDepth,
      maxPaths: candidateLimit,
      limits,
    });
    processedRoots = rootIndex + 1;
  }

  // Roots that were never entered are known incomplete traces. Retaining their
  // identities keeps Scope honest and lets incremental analysis replace only
  // the affected gaps instead of presenting the candidate count as a path count.
  if (processedRoots < roots.length && limits.truncated) {
    for (const root of roots.slice(processedRoots)) {
      const identity = flowRootIdentity(root);
      limits.partialRoots.set(identity.key, identity);
    }
  }
  limits.currentRoot = undefined;

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
    exploration: {
      value: {
        exploredStates: limits.exploredStates,
        visitedEvents: limits.visitedEvents,
        maxExploredStates: limits.maxExploredStates,
        maxVisitedEvents: limits.maxVisitedEvents,
        maxTraceSteps: limits.maxTraceSteps,
        maxHigherOrderDepth: limits.maxHigherOrderDepth,
        maxAsyncDepth: limits.maxAsyncDepth,
        maxAnalysisMs: limits.maxAnalysisMs,
        timedOut: limits.reasons.has("analysis-timeout"),
        totalRoots: roots.length,
        processedRoots,
        partialPaths: limits.partialRoots.size,
        partialRoots: [...limits.partialRoots.values()],
        rankingMs: roundMetric(rankingMs),
        explorationMs: roundMetric(performance.now() - startedAt - rankingMs),
        truncationReasons: [...limits.reasons],
      },
      enumerable: false,
    },
  });
  return result;
}

function walkFlow(state) {
  if (analysisExpired(state.limits)) return;
  if (state.depth > state.maxDepth) { truncate(state.limits, "call-depth-budget"); return; }
  if (state.steps.length >= state.limits.maxTraceSteps) { truncate(state.limits, "trace-step-budget"); return; }
  if (state.paths.length >= state.maxPaths) { truncate(state.limits, "path-candidate-budget"); return; }
  if (state.limits.currentRootStates >= state.limits.maxStatesPerRoot) {
    truncate(state.limits, "per-root-state-budget");
    return;
  }
  if (state.limits.exploredStates >= state.limits.maxExploredStates) {
    truncate(state.limits, "flow-state-budget");
    return;
  }
  state.limits.exploredStates += 1;
  state.limits.currentRootStates += 1;
  const sequences = flowEventSequences(
    state.fn,
    state.startLine,
    state.startOperationId,
    Math.min(state.limits.maxCfgPathsPerFunction, state.maxPaths),
  );
  if (sequences.truncated) truncate(state.limits, "cfg-path-budget");
  for (const events of sequences) {
    if (analysisExpired(state.limits)) return;
    if (state.paths.length >= state.maxPaths) { truncate(state.limits, "path-candidate-budget"); return; }
    if (state.limits.visitedEvents >= state.limits.maxVisitedEvents) {
      truncate(state.limits, "flow-event-budget");
      return;
    }
    if (state.limits.currentRootEvents >= state.limits.maxEventsPerRoot) {
      truncate(state.limits, "per-root-event-budget");
      return;
    }
    walkLinearFlow({ ...state, events });
  }
}

function walkLinearFlow(state) {
  const tainted = new Set(state.tainted);
  const evidence = new Map(state.evidence || [...tainted].map(variable => [variable, state.steps.slice()]));
  const versions = new Map(state.versions || []);
  let activeSteps = state.steps.slice();
  const addedControls = new Set();
  const availableControls = [];

  for (const event of state.events) {
    if (analysisExpired(state.limits)) return;
    if (activeSteps.length >= state.limits.maxTraceSteps) {
      truncate(state.limits, "trace-step-budget");
      return;
    }
    if (state.limits.visitedEvents >= state.limits.maxVisitedEvents) {
      truncate(state.limits, "flow-event-budget");
      return;
    }
    if (state.limits.currentRootEvents >= state.limits.maxEventsPerRoot) {
      truncate(state.limits, "per-root-event-budget");
      return;
    }
    state.limits.visitedEvents += 1;
    state.limits.currentRootEvents += 1;
    const functionAnnotationControl = event.line <= state.fn.line && (event.type === "control" || event.functionAnnotation);
    if (state.paths.length >= state.maxPaths) { truncate(state.limits, "path-candidate-budget"); return; }
    if (event.line < state.startLine && !functionAnnotationControl) continue;
    if (event.type === "assignment") {
      if (sourceDefinesSameValue(state.fn, event) || evidenceDefinesSameValue(evidence, event)) continue;
      advanceValueVersion(versions, event.target);
      propagateOutputGuardAssignments(availableControls, event, tainted, versions);
      const propagated = assignmentEvidence(event, tainted, evidence, state.fn);
      const transition = applyAssignment(tainted, event);
      removeAssignedEvidence(evidence, event.target);
      tainted.clear();
      for (const value of transition.tainted) tainted.add(value);
      for (const item of propagated) {
        tainted.add(item.output);
        evidence.set(item.output, item.steps);
      }
      continue;
    }
    if (event.type === "control") {
      const controlKey = event.id || event.line + ":" + event.controlKind;
      const guardedValues = [...(event.variables || []), event.guardBinding?.output].filter(Boolean);
      if (!addedControls.has(controlKey) && (intersects(guardedValues, tainted) || !guardedValues.length)) {
        const guardBinding = event.guardBinding ? {
          ...event.guardBinding,
          protectedOutputs: unique([...(event.guardBinding.protectedOutputs || []), event.guardBinding.output]),
        } : undefined;
        availableControls.push({
          event: guardBinding ? {
            ...event,
            guardBinding: { ...guardBinding, valueVersions: captureGuardVersions(guardBinding, versions) },
          } : event,
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
      if (event.target && !guardDefinesSameValue(state.events, event)) advanceValueVersion(versions, event.target);
      const directlyTaintedArguments = [];
      event.argumentVariables.forEach((variables, index) => {
        if ((!event.taintArgumentIndexes || event.taintArgumentIndexes.includes(index)) && intersects(variables, tainted)) {
          directlyTaintedArguments.push(index);
        }
      });
      const directlyTaintedReceiver = intersects(event.receiverVariables || [], tainted);
      const boundaries = nextCallBoundaries(event, state, state.limits);
      if (!boundaries) continue;
      const applicableControlSteps = availableControls
        .map(control => ({ ...control, relation: controlRelation(control.event, event, state.fn, versions, { deferSinkKind: true }) }))
        .filter(control => control.relation.status === "effective")
        .map(control => effectiveControlStep(control.step, control.relation));
      const resolvedCandidates = callResolver.resolveCandidates(state.index, event, state.fn);
      const candidates = resolvedCandidates.slice(0, state.limits.maxCallCandidates);
      if (resolvedCandidates.length > candidates.length) truncate(state.limits, "call-candidate-budget");
      const candidateFlows = candidates.map(resolution => ({
        resolution,
        incoming: incomingParameterVariables(resolution.fn, event, tainted),
      }));
      if (!directlyTaintedArguments.length && !directlyTaintedReceiver && !candidateFlows.some(flow => flow.incoming.length)) continue;
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
            candidateCount: resolvedCandidates.length,
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
          versions: new Map(),
          depth: state.depth + 1,
          higherOrderDepth: boundaries.higherOrderDepth,
          asyncDepth: boundaries.asyncDepth,
          visited,
        });
        if (!returnedFlow && event.target) {
          const returned = findTaintedReturn(
            candidate,
            incoming,
            state.index,
            new Set(state.visited),
            state.depth + 1,
            state.maxDepth,
            state.limits,
            boundaries,
          );
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
      } else if (event.target && !candidates.length && (directlyTaintedArguments.length || directlyTaintedReceiver)) {
        const externalEvidence = modeledExternalCallEvidence(event);
        tainted.add(event.target);
        activeSteps = [...activeSteps, makeStep(
          "call",
          externalEvidence.verified
            ? `${state.fn.name}() → modeled ${event.callee}()`
            : `${state.fn.name}() → unresolved ${event.callee}()`,
          state.fn,
          event,
          {
            candidateCount: 0,
            candidateMatch: externalEvidence.candidateMatch,
            candidateReason: externalEvidence.reason,
            analysisStatus: externalEvidence.analysisStatus,
          },
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
        relation: controlRelation(control.event, event, state.fn, versions),
      }));
      const applicableControlSteps = evaluatedControls.filter(control => control.relation.status === "effective")
        .map(control => effectiveControlStep(control.step, control.relation));
      // Hint-level controls keep the trace honest: they show a validation or
      // authorization call was nearby, but carry no suppressible capability.
      const hintControlSteps = evaluatedControls.filter(control => control.relation.status === "hint")
        .map(control => effectiveControlStep(control.step, control.relation));
      const sinkEvidence = bestEvidenceForValues(event.variables, evidence) || activeSteps;
      const declarativeValidationSteps = declarativeValidationEvidence(sinkEvidence, [sinkStep]);
      const guardHints = [
        ...declarativeValidationSteps.map(step => step.guardHint),
        ...evaluatedControls.flatMap(control => (control.relation.hints || []).map(hint => ({
          label: control.step.label,
          line: control.step.line,
          relativePath: control.step.relativePath,
          capabilities: [hint.capability],
          reason: hint.reason,
        }))),
      ].filter(Boolean);
      const steps = [
        ...sinkEvidence.slice(0, 1),
        ...declarativeValidationSteps,
        ...sinkEvidence.slice(1),
        ...applicableControlSteps,
        ...hintControlSteps,
        sinkStep,
      ];
      if (steps.length > state.limits.maxTraceSteps) {
        truncate(state.limits, "trace-step-budget");
        continue;
      }
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
      const confidence = semanticReview || callMatches.some(match => ["review", "opaque"].includes(match)) || propagationStatuses.some(status => ["heuristic", "unresolved"].includes(status)) ? "review" :
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
        sourceExposure: steps[0].sourceExposure || sourceExposureForKind(steps[0].sourceKind || SourceKind.EXTERNAL_INPUT),
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

function modeledExternalCallEvidence(event) {
  if (event.semanticModelId && event.semanticVerification === "verified") return {
    verified: true,
    candidateMatch: "high",
    analysisStatus: "verified",
    reason: `verified external semantic model ${event.semanticModelId}`,
  };
  if (event.semanticModelId && ["syntax", "structural"].includes(event.semanticVerification)) return {
    verified: false,
    candidateMatch: "medium",
    analysisStatus: "syntax-only",
    reason: `${event.semanticVerification} external semantic model ${event.semanticModelId}`,
  };
  return {
    verified: false,
    candidateMatch: "opaque",
    analysisStatus: "unresolved",
    reason: "unresolved external or dynamic call",
  };
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

function rootReviewRank(root, potentialRanks) {
  const sourceKind = root.step?.sourceKind;
  const sourceExposure = root.step?.sourceExposure || sourceExposureForKind(sourceKind);
  const entryRank = root.fn.isEntry || root.step?.parameterRoles ? 1000 : 0;
  const sourceRank = sourceExposure === SourceExposure.REMOTE ? 500 : sourceKind === SourceKind.SELECTED_SYMBOL ? 400 : sourceExposure === SourceExposure.LOCAL ? 50 : 100;
  const sourceConfidence = { high: 30, medium: 20, review: 10 }[root.step?.confidence] || 0;
  return entryRank + sourceRank + sourceConfidence + (potentialRanks.get(root.fn.id) || 0) * 20;
}

function findTaintedReturn(fn, incoming, index, visited, depth, maxDepth, limits, boundaries = { higherOrderDepth: 0, asyncDepth: 0 }) {
  if (analysisExpired(limits)) return undefined;
  if (depth > maxDepth) { truncate(limits, "call-depth-budget"); return undefined; }
  if (limits.currentRootStates >= limits.maxStatesPerRoot) {
    truncate(limits, "per-root-state-budget");
    return undefined;
  }
  if (limits.exploredStates >= limits.maxExploredStates) {
    truncate(limits, "flow-state-budget");
    return undefined;
  }
  limits.exploredStates += 1;
  limits.currentRootStates += 1;
  const key = visitKey(fn, incoming);
  if (visited.has(key)) return undefined;
  visited.add(key);
  const sequences = flowEventSequences(fn, fn.line, undefined, limits.maxCfgPathsPerFunction);
  if (sequences.truncated) truncate(limits, "cfg-path-budget");
  for (const events of sequences) {
    if (analysisExpired(limits)) return undefined;
    const returned = findTaintedReturnOnPath(fn, events, incoming, index, visited, depth, maxDepth, limits, boundaries);
    if (returned) return returned;
  }
  return undefined;
}

function findTaintedReturnOnPath(fn, events, incoming, index, visited, depth, maxDepth, limits, boundaries) {
  const tainted = new Set(incoming);
  for (const event of events) {
    if (analysisExpired(limits)) return undefined;
    if (limits.visitedEvents >= limits.maxVisitedEvents) {
      truncate(limits, "flow-event-budget");
      return undefined;
    }
    limits.visitedEvents += 1;
    limits.currentRootEvents += 1;
    if (limits.currentRootEvents > limits.maxEventsPerRoot) {
      truncate(limits, "per-root-event-budget");
      return undefined;
    }
    if (event.type === "assignment") {
      if (sourceDefinesSameValue(fn, event) || precedingCallDefinesSameValue(fn, event, tainted)) continue;
      const transition = applyAssignment(tainted, event, { preserveTarget: sourceDefinesSameValue(fn, event) });
      tainted.clear();
      for (const value of transition.tainted) tainted.add(value);
      continue;
    }
    if (event.type === "call" && event.target) {
      const nextBoundaries = nextCallBoundaries(event, boundaries, limits);
      if (!nextBoundaries) continue;
      const directlyTaintedArguments = [];
      event.argumentVariables.forEach((variables, argumentIndex) => {
        if ((!event.taintArgumentIndexes || event.taintArgumentIndexes.includes(argumentIndex)) && intersects(variables, tainted)) {
          directlyTaintedArguments.push(argumentIndex);
        }
      });
      const directlyTaintedReceiver = intersects(event.receiverVariables || [], tainted);
      const resolvedCandidates = callResolver.resolveCandidates(index, event, fn);
      const candidates = resolvedCandidates.slice(0, limits.maxCallCandidates);
      if (resolvedCandidates.length > candidates.length) truncate(limits, "call-candidate-budget");
      if (!candidates.length) {
        if (directlyTaintedArguments.length || directlyTaintedReceiver) tainted.add(event.target);
        continue;
      }
      for (const resolution of candidates) {
        const candidate = resolution.fn;
        const nextIncoming = incomingParameterVariables(candidate, event, tainted);
        if (nextIncoming.length && findTaintedReturn(candidate, nextIncoming, index, new Set(visited), depth + 1, maxDepth, limits, nextBoundaries)) {
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

function nextCallBoundaries(event, state, limits) {
  const higherOrderDepth = Number(state.higherOrderDepth || 0) + Number(Boolean(event.closure));
  const asyncDepth = Number(state.asyncDepth || 0) + Number(isAsyncBoundary(event));
  if (higherOrderDepth > limits.maxHigherOrderDepth) {
    truncate(limits, "higher-order-depth-budget");
    return undefined;
  }
  if (asyncDepth > limits.maxAsyncDepth) {
    truncate(limits, "async-depth-budget");
    return undefined;
  }
  return { higherOrderDepth, asyncDepth };
}

function isAsyncBoundary(event) {
  const name = String(event.callee || "").replace(/[^A-Za-z0-9]/g, "").toLowerCase();
  const asyncCalls = ["then", "catch", "finally", "settimeout", "setinterval", "queuemicrotask", "runasync", "supplyasync", "launch", "async", "go"];
  return Boolean(event.asyncBoundary || asyncCalls.includes(name) || asyncCalls.some(call => name.startsWith(`${call}callback`)));
}

function truncate(limits, reason) {
  limits.truncated = true;
  if (reason) limits.reasons.add(reason);
  if (limits.currentRoot) limits.partialRoots?.set(limits.currentRoot.key, limits.currentRoot);
}

function flowRootIdentity(root) {
  const functionId = root.fn.id;
  const operationId = root.step.operationId || `${root.line}:${root.variables.join(",")}`;
  return { key: `${functionId}:${operationId}`, functionId };
}

function analysisExpired(limits) {
  if (!limits?.deadline || (limits.deadlineClock || performance.now)() < limits.deadline) return false;
  truncate(limits, "analysis-timeout");
  return true;
}

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number(value);
  const selected = Number.isFinite(parsed) ? Math.floor(parsed) : fallback;
  return Math.min(maximum, Math.max(minimum, selected));
}

function roundMetric(value) {
  return Math.round(Math.max(0, Number(value) || 0) * 100) / 100;
}

function buildRoots(functions, options, functionIndex) {
  const roots = [];
  const strutsProperties = javaStrutsBoundProperties(functions);
  const transferredRequestParams = collectTransferredRequestParams(functions, functionIndex, options);
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
          variables: [selectedIdentifier],
        }, { sourceKind: SourceKind.SELECTED_SYMBOL, sourceExposure: SourceExposure.REVIEWER }),
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
        step: makeStep("source", event.label || "External input", fn, event, {
          sourceKind: event.sourceKind,
          sourceExposure: event.sourceExposure || sourceExposureForKind(event.sourceKind),
        }),
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
            variables,
          }, {
            sourceKind: SourceKind.HTTP_INPUT,
            sourceExposure: SourceExposure.REMOTE,
            confidence,
            parameterRoles: roles,
            validationFacts: entryValidationFacts(fn, variables),
          }),
        });
      }
    }
    const boundProperties = strutsProperties.get(fn) || [];
    const usedProperties = boundProperties.filter(property => functionUsesAccessPath(fn, property));
    if (usedProperties.length) {
      roots.push({
        fn,
        line: fn.line,
        variables: usedProperties,
        step: makeStep("source", `Struts-bound action properties · ${fn.enclosingScope} (route unresolved)`, fn, {
          line: fn.line,
          code: usedProperties.join(", "),
          variables: usedProperties,
        }, {
          sourceKind: SourceKind.HTTP_INPUT,
          sourceExposure: SourceExposure.REMOTE,
          confidence: "medium",
          analysisStatus: "syntax-only",
          framework: "struts2-convention",
          parameterRoles: usedProperties.map(() => "body"),
        }),
      });
    }
    const transferredIndexes = transferredRequestParams.get(fn.id);
    if (transferredIndexes?.size) {
      const variables = [...transferredIndexes].map(index => fn.parameters[index]).filter(Boolean);
      if (variables.length) {
        roots.push({
          fn,
          line: fn.line,
          variables,
          step: makeStep("source", "Inferred request parameter · transferred from a call-site argument", fn, {
            line: fn.line,
            code: variables.join(", "),
            variables,
          }, {
            sourceKind: SourceKind.HTTP_INPUT,
            sourceExposure: SourceExposure.REMOTE,
            confidence: "medium",
            analysisStatus: "heuristic",
          }),
        });
      }
    }
  }
  return dedupeRoots(roots);
}

function requestRootName(variable) {
  return String(variable || "").split(/[.[]/)[0].replace(/^\$/, "");
}

function collectRequestRootNames(functions) {
  const names = new Set(catalog.CONVENTIONAL_REQUEST_ROOTS);
  for (const fn of functions) {
    for (const event of fn.events.filter(event => event.type === "source" && event.variables.length)) {
      for (const variable of event.variables) {
        const root = requestRootName(variable);
        if (root) names.add(root);
      }
    }
  }
  return names;
}

// Functions that receive a request-shaped value (an argument whose root is an
// observed request source root) become heuristic HTTP-input roots themselves
// when the function also reads properties of that parameter, so helper
// extraction patterns surface as review candidates instead of being silently
// dropped by exact access-path matching.
const transferredRequestCache = new WeakMap();
function collectTransferredRequestParams(functions, functionIndex, options) {
  if (!functionIndex || options.rootFunctionIds) return new Map();
  const cached = transferredRequestCache.get(functions);
  if (cached) return cached;
  const globalRoots = collectRequestRootNames(functions);
  const transferred = new Map();
  if (globalRoots.size) {
    const edges = [];
    for (const fn of functions) {
      for (const event of fn.events.filter(event => event.type === "call" && event.callee)) {
        const argumentGroups = event.argumentVariables || [];
        if (!argumentGroups.some(group => (group || []).some(variable => globalRoots.has(requestRootName(variable))))) continue;
        edges.push({ fn, argumentGroups, resolutions: [...callResolver.resolveCandidates(functionIndex, event, fn)] });
      }
    }
    let changed = true;
    for (let round = 0; changed && round < 8; round += 1) {
      changed = false;
      for (const edge of edges) {
        const requestNames = new Set(globalRoots);
        const own = transferred.get(edge.fn.id);
        if (own) for (const index of own.keys()) requestNames.add(requestRootName(edge.fn.parameters[index]));
        for (const resolution of edge.resolutions) {
          edge.argumentGroups.forEach((group, argumentIndex) => {
            if (!(group || []).some(variable => requestNames.has(requestRootName(variable)))) return;
            const callee = resolution.fn;
            if (argumentIndex >= (callee.parameters || []).length) return;
            if (!transferred.has(callee.id)) transferred.set(callee.id, new Map());
            const indexes = transferred.get(callee.id);
            if (!indexes.has(argumentIndex)) {
              indexes.set(argumentIndex, true);
              changed = true;
            }
          });
        }
      }
    }
    // Seeding a whole-object root for every receiver of a request-shaped value
    // would flood exploration; keep only callees that actually dereference the
    // parameter (read `<param>.member`), where helper extraction matters.
    for (const [calleeId, indexes] of [...transferred]) {
      const callee = functions.find(fn => fn.id === calleeId);
      if (!callee) { transferred.delete(calleeId); continue; }
      for (const [index] of [...indexes]) {
        const parameter = callee.parameters[index];
        if (!parameter || functionReadsParameterProperties(callee, parameter)) continue;
        indexes.delete(index);
      }
      if (!indexes.size) transferred.delete(calleeId);
    }
  }
  transferredRequestCache.set(functions, transferred);
  return transferred;
}

function functionReadsParameterProperties(fn, parameter) {
  const prefix = `${parameter}.`;
  const indexPrefix = `${parameter}[`;
  return fn.events.some(event => [...(event.variables || []), ...(event.argumentVariables || []).flat()]
    .some(variable => {
      const path = normalizeAccessPath(variable) || String(variable);
      return path.startsWith(prefix) || path.startsWith(indexPrefix);
    }));
}

function javaStrutsBoundProperties(functions) {
  const javaFunctions = functions.filter(fn => fn.language === "java" && fn.qualifiedEnclosingScope);
  const groups = new Map();
  for (const fn of javaFunctions) {
    const key = fn.typeRelations || javaFunctions;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(fn);
  }
  const result = new Map();
  for (const scopedFunctions of groups.values()) {
    const relations = scopedFunctions[0]?.typeRelations || [];
    const parents = new Map(relations.filter(relation => relation.language === "java")
      .map(relation => [relation.type, relation.extends || []]));
    const functionsByType = new Map();
    for (const fn of scopedFunctions) {
      if (!functionsByType.has(fn.qualifiedEnclosingScope)) functionsByType.set(fn.qualifiedEnclosingScope, []);
      functionsByType.get(fn.qualifiedEnclosingScope).push(fn);
    }
    for (const type of functionsByType.keys()) {
      if (!javaTypeExtends(type, parents, candidate => [
        "com.opensymphony.xwork2.Action",
        "com.opensymphony.xwork2.ActionSupport",
        "org.apache.struts.action.Action",
      ].includes(candidate))) continue;
      const properties = new Set();
      for (const candidateType of javaTypeAncestors(type, parents)) {
        for (const setter of functionsByType.get(candidateType) || []) {
          const match = /^set([A-Z][A-Za-z0-9_$]*)$/.exec(setter.name || "");
          const parameter = setter.parameterDetails?.[0];
          if (!match || setter.parameterDetails?.length !== 1 || !strutsBindableParameter(parameter)) continue;
          properties.add(javaBeanPropertyName(match[1]));
        }
      }
      if (properties.size) {
        for (const fn of functionsByType.get(type) || []) result.set(fn, [...properties]);
      }
    }
  }
  return result;
}

function javaTypeExtends(type, parents, predicate) {
  return javaTypeAncestors(type, parents).some(predicate);
}

function javaTypeAncestors(type, parents) {
  const pending = [type];
  const visited = new Set();
  while (pending.length) {
    const current = pending.shift();
    if (!current || visited.has(current)) continue;
    visited.add(current);
    pending.push(...(parents.get(current) || []));
  }
  return [...visited];
}

function strutsBindableParameter(parameter) {
  const type = String(parameter?.type || "").replace(/<.*>/g, "").replace(/\[\]$/g, "");
  if (!type || type === "?") return false;
  return !/(?:^|\.)(?:HttpServletRequest|ServletRequest|HttpServletResponse|ServletResponse|ActionContext|ServletContext|Session|Map|Logger|EntityManager|DataSource|ApplicationContext|[A-Za-z0-9_$]*(?:Service|Repository|Dao|Client))$/.test(type);
}

function functionUsesAccessPath(fn, accessPath) {
  return (fn.events || []).some(event => [
    ...(event.variables || []),
    ...(event.receiverVariables || []),
    ...(event.argumentVariables || []).flat(),
  ].some(value => pathsOverlap(value, accessPath)));
}

function javaBeanPropertyName(value) {
  return /^[A-Z]{2}/.test(value) ? value : value.charAt(0).toLowerCase() + value.slice(1);
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
  const accessPaths = unique([
    ...(event.variables || []),
    event.target,
    event.receiver,
    ...(event.argumentVariables || []).flat(),
    extra.inputAccessPath,
    extra.outputAccessPath,
  ].map(value => normalizeAccessPath(value) || value));
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
    accessPaths,
    ...extra,
  };
}

function entryValidationFacts(fn, variables) {
  if (fn.language !== "java") return [];
  const facts = [];
  for (const detail of fn.parameterDetails || []) {
    if (!detail.cascadedValidation || !variables.some(variable => pathsOverlap(variable, detail.name))) continue;
    const relation = javaTypeRelation(fn, detail.type);
    for (const constraint of relation?.validationConstraints || []) {
      facts.push({
        ...constraint,
        parameter: detail.name,
        parameterType: relation.type,
        enforcement: javaBeanValidationEnforcement(fn, detail, constraint),
        accessPaths: unique([
          `${detail.name}.${constraint.property}`,
          `${detail.name}.${constraint.accessor}`,
        ]),
      });
    }
  }
  return facts;
}

function javaTypeRelation(fn, declaredType) {
  const type = String(declaredType || "")
    .replace(/<.*>/g, "")
    .replace(/\[\]/g, "")
    .trim();
  if (!type || type === "?") return undefined;
  const relations = (fn.typeRelations || []).filter(relation => relation.language === "java");
  if (type.includes(".")) return relations.find(relation => relation.type === type);
  const imported = (fn.references || []).find(reference => reference.kind === "import" &&
    reference.local !== "*" && reference.local === type)?.target;
  if (imported) return relations.find(relation => relation.type === imported);
  const localType = fn.packageName ? `${fn.packageName}.${type}` : type;
  const local = relations.find(relation => relation.type === localType);
  if (local) return local;
  const simpleMatches = relations.filter(relation => relation.type === type || relation.type.endsWith(`.${type}`));
  return simpleMatches.length === 1 ? simpleMatches[0] : undefined;
}

function javaBeanValidationEnforcement(fn, validatedParameter, constraint) {
  if (!(fn.entryPoints || []).some(entry => entry.framework === "spring")) return undefined;
  if (!constraint.defaultValidationGroup || !validatedParameter.annotations?.includes("Valid")) return undefined;
  const validTarget = javaImportedType(fn, "Valid");
  if (!/^(?:jakarta|javax)\.validation\.Valid$/.test(validTarget || "")) return undefined;
  const parameterIndex = (fn.parameterDetails || []).indexOf(validatedParameter);
  const bindingResult = fn.parameterDetails?.[parameterIndex + 1];
  if (!bindingResult || !/(?:^|\.)(?:BindingResult|Errors)$/.test(String(bindingResult.type || ""))) return undefined;
  const bindingTarget = bindingResult.type.includes(".") ? bindingResult.type : javaImportedType(fn, bindingResult.type);
  if (!/^org\.springframework\.validation\.(?:BindingResult|Errors)$/.test(bindingTarget || "")) return undefined;
  const cfg = fn.cfg;
  if (!cfg?.edges?.length || !cfg.dominators) return undefined;
  const checks = (fn.events || []).filter(event => event.type === "call" && event.callee === "hasErrors" &&
    (event.receiverVariables || []).some(receiver => pathsOverlap(receiver, bindingResult.name)) &&
    positiveBindingResultCheck(event.code, bindingResult.name));
  for (const check of checks) {
    const trueEdge = cfg.edges.find(edge => edge.from === check.blockId && edge.kind === "true");
    const falseEdge = cfg.edges.find(edge => edge.from === check.blockId && edge.kind === "false");
    if (!trueEdge || !falseEdge) continue;
    const rejected = cfgReachableBlocks(cfg, trueEdge.to);
    const accepted = cfgReachableBlocks(cfg, falseEdge.to);
    const acceptedOnly = new Set([...accepted].filter(block => !rejected.has(block) &&
      (cfg.dominators[block] || []).includes(check.blockId)));
    const mutationBlocks = new Set((fn.events || [])
      .filter(event => event.id !== check.id && eventCouldMutateValidatedProperty(event, validatedParameter, constraint))
      .map(event => event.blockId)
      .filter(block => accepted.has(block)));
    const safeOperationIds = (fn.events || []).filter(event => acceptedOnly.has(event.blockId) &&
      ![...mutationBlocks].some(block => block !== event.blockId && cfgCanReach(cfg, block, event.blockId)))
      .map(event => event.id);
    if (!safeOperationIds.length) continue;
    return {
      kind: "spring-binding-result-rejection",
      verification: "cfg",
      functionId: fn.id,
      bindingResult: bindingResult.name,
      conditionOperationId: check.id,
      line: check.line,
      code: check.code,
      safeOperationIds,
    };
  }
  return undefined;
}

function javaImportedType(fn, local) {
  return (fn.references || []).find(reference => reference.kind === "import" && reference.local === local)?.target;
}

function positiveBindingResultCheck(code, receiver) {
  const target = escapeRegex(receiver);
  return new RegExp(`\\bif\\s*\\(\\s*${target}\\s*\\.\\s*hasErrors\\s*\\(\\s*\\)\\s*\\)`).test(String(code || ""));
}

function eventCouldMutateValidatedProperty(event, parameter, constraint) {
  const root = parameter.name;
  const property = `${root}.${constraint.property}`;
  if (event.type === "assignment" && [root, property].some(value => pathsOverlap(event.target, value))) return true;
  if (event.type !== "call") return false;
  const receiverTouchesRoot = (event.receiverVariables || []).some(value => pathsOverlap(value, root));
  const pureAccessors = new Set(constraint.generatedPureAccessors || []);
  if (receiverTouchesRoot && !pureAccessors.has(event.callee)) return true;
  return (event.argumentVariables || []).some(group => group.some(value => normalizeAccessPath(value) === normalizeAccessPath(root)));
}

function cfgReachableBlocks(cfg, start) {
  const reachable = new Set();
  const pending = [start];
  while (pending.length) {
    const block = pending.pop();
    if (!block || reachable.has(block)) continue;
    reachable.add(block);
    for (const edge of cfg.edges || []) if (edge.from === block) pending.push(edge.to);
  }
  return reachable;
}

function cfgCanReach(cfg, start, target) {
  return start === target || cfgReachableBlocks(cfg, start).has(target);
}

function declarativeValidationEvidence(evidenceSteps, terminalSteps = []) {
  const facts = evidenceSteps.flatMap(step => step.validationFacts || []);
  if (!facts.length) return [];
  const useSteps = [...evidenceSteps, ...terminalSteps];
  const accessPaths = useSteps.flatMap(step => step.accessPaths || []);
  const code = useSteps.map(step => step.code || "").join("\n");
  const seen = new Set();
  return facts.filter(fact => {
    const key = `${fact.parameterType}:${fact.property}:${fact.kind}:${fact.annotation}`;
    if (seen.has(key) || !declarativeFactTouchesEvidence(fact, accessPaths, code)) return false;
    seen.add(key);
    return true;
  }).map(fact => {
    const enforced = fact.enforcement?.safeOperationIds?.some(operationId => useSteps.some(step =>
      step.functionId === fact.enforcement.functionId && step.operationId === operationId));
    const regexp = fact.regexp ? ` /${fact.regexp}/` : "";
    const reason = enforced
      ? `Spring BindingResult rejection at line ${fact.enforcement.line} dominates this use, so the declared constraint is enforced on this path.`
      : "The Bean Validation constraint is declared and cascaded validation is requested, but validator activation and the rejecting control-flow branch were not proven. It cannot suppress this finding.";
    return {
      kind: "validation",
      label: `${enforced ? "Enforced" : "Declared"} @Pattern${regexp} for ${fact.parameterType}.${fact.property}`,
      operationId: `declarative-validation:${fact.parameterType}:${fact.property}`,
      functionId: evidenceSteps[0]?.functionId,
      symbolKey: evidenceSteps[0]?.symbolKey,
      workspaceRoot: evidenceSteps[0]?.workspaceRoot,
      absolutePath: fact.location?.absolutePath || evidenceSteps[0]?.absolutePath,
      relativePath: fact.location?.relativePath || evidenceSteps[0]?.relativePath,
      line: fact.location?.line || evidenceSteps[0]?.line,
      code: fact.annotation || "@Pattern",
      accessPaths: fact.accessPaths || [],
      analysisStatus: enforced ? "verified" : "syntax-only",
      declarationOnly: true,
      guardCapabilities: enforced ? [GuardCapability.INPUT_VALIDATION] : [],
      enforcement: enforced ? fact.enforcement : undefined,
      reason,
      guardHint: enforced ? undefined : {
        label: `Declared @Pattern for ${fact.parameterType}.${fact.property}`,
        line: fact.location?.line || evidenceSteps[0]?.line,
        relativePath: fact.location?.relativePath || evidenceSteps[0]?.relativePath,
        capabilities: [GuardCapability.INPUT_VALIDATION],
        reason,
      },
    };
  });
}

function declarativeFactTouchesEvidence(fact, accessPaths, code) {
  if ((fact.accessPaths || []).some(expected => accessPaths.some(actual => pathsOverlap(expected, actual)))) return true;
  return Boolean(fact.accessor && new RegExp(`\\.${escapeRegex(fact.accessor)}\\s*\\(`).test(code));
}

function escapeRegex(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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
    sameOperationRange(event, assignment) &&
    [event.target, ...(event.variables || [])].some(value =>
      normalizeAccessPath(value) === normalizeAccessPath(assignment.target)));
}

function sameOperationRange(source, assignment) {
  if (![source.startOffset, source.endOffset, assignment.startOffset, assignment.endOffset].every(Number.isFinite)) return true;
  return source.startOffset >= assignment.startOffset && source.endOffset <= assignment.endOffset;
}

function evidenceDefinesSameValue(evidence, assignment) {
  const target = normalizeAccessPath(assignment.target);
  const steps = evidence.get(target) || [];
  return steps.some(step => step.kind === "call" && step.line === assignment.line);
}

function guardDefinesSameValue(events, call) {
  const target = normalizeAccessPath(call.target);
  return Boolean(target && events.some(event => event.type === "control" && event.line === call.line &&
    normalizeAccessPath(event.guardBinding?.output || event.target) === target));
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
  if (control.guardDominance && control.blockId && target.blockId && fn.cfg?.dominators?.[target.blockId]) {
    return fn.cfg.dominators[target.blockId].includes(control.blockId);
  }
  // Without branch dominance, only guards whose soundness is enforced
  // elsewhere may apply by line order: value-transforming guards
  // (outputScoped — guardCapabilityFailures requires the sink to consume the
  // guard's fresh output), receiver-typed guards and trusted-operand guards.
  // A plain predicate guard checked outside any condition proves nothing and
  // stays a hint.
  const binding = control.guardBinding;
  const selfProving = Boolean(
    binding?.outputScoped || binding?.receiverScoped || binding?.requiresTrustedOperand,
  );
  if (!selfProving) return false;
  return control.line <= target.line;
}

function controlRelation(control, target, fn, versions = new Map(), options = {}) {
  if (!controlScopeApplies(control, target, fn)) {
    // A guard that is a plain call with no branch-dominance proof and no
    // self-proving scope is still review context: keep it as a hint step
    // (no capabilities) instead of dropping it from the trace entirely.
    const bare = !control.guardDominance && !Array.isArray(control.guardAppliesToBlocks) &&
      !(control.guardBinding?.outputScoped || control.guardBinding?.receiverScoped ||
        control.guardBinding?.requiresTrustedOperand);
    if (bare) return {
      status: "hint",
      effectiveCapabilities: [],
      hints: (control.guardCapabilities || []).map(capability => ({
        capability,
        reason: "The guard is a plain call with no branch-dominance proof; recorded as review context and it cannot suppress findings.",
      })),
    };
    return { status: "none", reason: "The guard does not control this sink path." };
  }
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
    const reasons = guardCapabilityFailures(scope, binding, target, versions, options);
    if (reasons.length) reasons.forEach(reason => hints.push({ capability, reason }));
    else effectiveCapabilities.push(capability);
  }
  return { status: effectiveCapabilities.length ? "effective" : "hint", effectiveCapabilities, hints };
}

function guardCapabilityFailures(scope, binding, target, versions, options = {}) {
  const reasons = [];
  if (!options.deferSinkKind && scope.applicableSinkKinds?.length && !scope.applicableSinkKinds.includes(target.sinkKind)) {
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
    const protectedOutputs = unique([...(binding.protectedOutputs || []), binding.output]);
    const consumedOutputs = protectedOutputs.filter(output => intersects(target.variables, new Set([output])));
    if (!binding.output) reasons.push("The guard return value is not captured, so the protected value cannot be proven.");
    else if (!consumedOutputs.length) reasons.push("The sink does not consume the value produced by the guard or a value derived only from it.");
    else if (consumedOutputs.every(output => guardVersionChanged(binding, output, versions))) {
      reasons.push("The protected value was reassigned after the guard proof was established.");
    }
  }
  if (!scope.receiverScoped && !scope.outputScoped) {
    const protectedValues = binding.inputs || [];
    if (protectedValues.length && !intersects(target.variables, new Set(protectedValues))) {
      reasons.push("The guard validates a different value from the one consumed by the sink.");
    } else if (protectedValues.some(value => guardVersionChanged(binding, value, versions))) {
      reasons.push("A validated value was reassigned after the guard proof was established.");
    }
  }
  return [...new Set(reasons)];
}

function advanceValueVersion(versions, value) {
  const key = normalizeAccessPath(value);
  if (!key) return;
  versions.set(key, (versions.get(key) || 0) + 1);
}

function captureGuardVersions(binding, versions) {
  return Object.fromEntries([...(binding.inputs || []), ...(binding.protectedOutputs || []), binding.output]
    .map(normalizeAccessPath)
    .filter(Boolean)
    .map(value => [value, versions.get(value) || 0]));
}

function propagateOutputGuardAssignments(controls, assignment, tainted, versions) {
  const target = normalizeAccessPath(assignment.target);
  const taintedInputs = unique((assignment.variables || []).filter(value => intersects([value], tainted)));
  if (!target || !taintedInputs.length) return;
  for (const control of controls) {
    const binding = control.event?.guardBinding;
    if (!binding || !Object.values(binding.capabilityScopes || {}).some(scope => scope.outputScoped)) continue;
    const protectedOutputs = unique([...(binding.protectedOutputs || []), binding.output])
      .filter(value => !guardVersionChanged(binding, value, versions));
    if (!protectedOutputs.length || !taintedInputs.every(input => intersects([input], new Set(protectedOutputs)))) continue;
    binding.protectedOutputs = unique([...protectedOutputs, target]);
    binding.valueVersions ||= {};
    binding.valueVersions[target] = versions.get(target) || 0;
  }
}

function guardVersionChanged(binding, value, versions) {
  const key = normalizeAccessPath(value);
  if (!key || !binding.valueVersions || binding.valueVersions[key] === undefined) return false;
  return binding.valueVersions[key] !== (versions.get(key) || 0);
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
