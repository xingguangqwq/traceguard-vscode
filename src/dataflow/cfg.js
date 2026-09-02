"use strict";

function buildOperationCFG(operations) {
  const ordered = [...operations].sort(compareOperations);
  const blocks = [block("entry", "entry")];
  for (const operation of ordered) blocks.push(block(`op:${operation.id}`, "operation", operation));
  blocks.push(block("exit", "exit"));
  const edges = [];
  for (let index = 0; index < blocks.length - 1; index += 1) edges.push(edge(blocks[index].id, blocks[index + 1].id, "next"));

  const branchOperations = [];
  for (let index = 0; index < ordered.length; index += 1) {
    const operation = ordered[index];
    const blockId = `op:${operation.id}`;
    operation.metadata = { ...operation.metadata, blockId };
    if (["return", "throw", "break", "continue"].includes(operation.kind)) {
      removeOutgoing(edges, blockId);
      if (operation.kind === "return" || operation.kind === "throw") edges.push(edge(blockId, "exit", operation.kind));
      continue;
    }
    if (operation.kind !== "branch" || !operation.metadata.branch) continue;
    branchOperations.push(operation);
    const branch = operation.metadata.branch;
    if (branch.controlKind === "try") {
      buildTryEdges(edges, ordered, operation, branch);
      continue;
    }
    const thenBlocks = blocksInRange(ordered, branch.thenRange).filter(candidate => candidate !== blockId);
    const elseBlocks = blocksInRange(ordered, branch.elseRange).filter(candidate => candidate !== blockId);
    const conditionBlocks = blocksInRange(ordered, branch.conditionRange).filter(candidate => candidate !== blockId);
    const ranges = [branch.thenRange, branch.elseRange].filter(Boolean);
    const branchEnd = ranges.reduce((current, range) => laterRangeEnd(current, range), operation.location);
    const join = ordered.find(candidate => isAfterRange(candidate.location, branchEnd));
    const joinId = join ? `op:${join.id}` : "exit";
    removeOutgoing(edges, blockId);
    const decisionBlock = conditionBlocks.at(-1) || blockId;
    if (conditionBlocks.length) {
      edges.push(edge(blockId, conditionBlocks[0], "condition"));
      removeOutgoing(edges, decisionBlock);
    }
    if (branch.constantOutcome !== false) edges.push(edge(decisionBlock, thenBlocks[0] || joinId, "true"));
    if (branch.constantOutcome !== true) edges.push(edge(decisionBlock, elseBlocks[0] || joinId, "false"));
    connectTail(edges, thenBlocks, branch.controlKind === "loop" ? blockId : joinId, ordered, branch.controlKind === "loop" ? "loop" : "join");
    connectTail(edges, elseBlocks, joinId, ordered);
    branch.thenBlocks = thenBlocks;
    branch.elseBlocks = elseBlocks;
    branch.conditionBlocks = conditionBlocks;
    branch.joinBlock = joinId;
    branch.blockId = blockId;
  }

  wireStructuredTransfers(edges, ordered, branchOperations);

  const reachableBlocks = reachableFrom("entry", edges);
  for (const operation of ordered) operation.metadata.reachable = reachableBlocks.includes(`op:${operation.id}`);
  const dominators = computeDominators(blocks.map(item => item.id), edges, "entry");
  applyGuardScopes(ordered, dominators, edges);
  return { entry: "entry", exit: "exit", blocks, edges, dominators, reachableBlocks };
}

function buildTryEdges(edges, ordered, operation, branch) {
  const blockId = `op:${operation.id}`;
  const tryBlocks = blocksInRange(ordered, branch.thenRange).filter(candidate => candidate !== blockId);
  const catchGroups = (branch.catchRanges || [])
    .map(range => blocksInRange(ordered, range).filter(candidate => candidate !== blockId))
    .filter(group => group.length);
  const catchBlocks = [...new Set(catchGroups.flat())];
  const elseBlocks = blocksInRange(ordered, branch.elseRange).filter(candidate => candidate !== blockId);
  const finallyBlocks = blocksInRange(ordered, branch.finallyRange).filter(candidate => candidate !== blockId);
  const ranges = [branch.thenRange, ...(branch.catchRanges || []), branch.elseRange, branch.finallyRange].filter(Boolean);
  const branchEnd = ranges.reduce((current, range) => laterRangeEnd(current, range), operation.location);
  const join = ordered.find(candidate => isAfterRange(candidate.location, branchEnd));
  const joinId = join ? `op:${join.id}` : "exit";
  const finallyEntry = finallyBlocks[0] || joinId;
  const successAfterTry = elseBlocks[0] || finallyEntry;
  const exceptionEntries = catchGroups.map(group => group[0]);
  if (!exceptionEntries.length) exceptionEntries.push(finallyEntry);
  removeOutgoing(edges, blockId);
  edges.push(edge(blockId, tryBlocks[0] || successAfterTry, "normal"));
  for (const exceptionEntry of exceptionEntries) edges.push(edge(blockId, exceptionEntry, "exception"));
  connectTail(edges, tryBlocks, successAfterTry, ordered, "try-success");
  connectTail(edges, elseBlocks, finallyEntry, ordered, "try-else");
  for (const catchGroup of catchGroups) connectTail(edges, catchGroup, finallyEntry, ordered, "catch");
  connectTail(edges, finallyBlocks, joinId, ordered, "finally");
  branch.thenBlocks = tryBlocks;
  branch.catchBlocks = catchBlocks;
  branch.elseBlocks = elseBlocks;
  branch.finallyBlocks = finallyBlocks;
  branch.joinBlock = joinId;
  branch.blockId = blockId;
  branch.exceptionEntries = exceptionEntries;
  branch.exceptionEntry = exceptionEntries[0];
  branch.finallyEntry = finallyEntry;
}

function wireStructuredTransfers(edges, operations, branches) {
  const loops = branches.filter(operation => operation.metadata.branch.controlKind === "loop");
  const tries = branches.filter(operation => operation.metadata.branch.controlKind === "try");
  for (const operation of operations) {
    const blockId = `op:${operation.id}`;
    if (operation.kind === "break" || operation.kind === "continue") {
      const loop = innermostContaining(loops, operation.location, candidate => candidate.metadata.branch.thenRange);
      if (!loop) continue;
      removeOutgoing(edges, blockId);
      edges.push(edge(
        blockId,
        operation.kind === "continue" ? loop.metadata.branch.blockId : loop.metadata.branch.joinBlock,
        operation.kind,
      ));
    }
    if (operation.kind === "return") {
      const handler = innermostTryContaining(tries, operation.location);
      if (!handler?.metadata.branch.finallyBlocks?.length || locationWithinRange(operation.location, handler.metadata.branch.finallyRange)) continue;
      removeOutgoing(edges, blockId);
      edges.push(edge(blockId, handler.metadata.branch.finallyEntry, "finally-return"));
      handler.metadata.branch.abruptFinallyExit = true;
    }
    if (operation.kind === "throw") {
      const handler = innermostTryContaining(tries, operation.location);
      if (!handler) continue;
      removeOutgoing(edges, blockId);
      const branch = handler.metadata.branch;
      const insideTryBody = locationWithinRange(operation.location, branch.thenRange);
      const exceptionEntries = insideTryBody
        ? branch.exceptionEntries || [branch.exceptionEntry || "exit"]
        : branch.finallyBlocks?.length ? [branch.finallyEntry] : ["exit"];
      for (const exceptionEntry of exceptionEntries) {
        edges.push(edge(blockId, exceptionEntry, "exception"));
      }
      if (!insideTryBody && branch.finallyBlocks?.length) branch.abruptFinallyExit = true;
    }
  }
  for (const operation of tries) {
    const branch = operation.metadata.branch;
    if (!branch.abruptFinallyExit || !branch.finallyBlocks?.length) continue;
    const tail = branch.finallyBlocks.at(-1);
    if (!edges.some(item => item.from === tail && item.to === "exit" && item.kind === "finally-abrupt")) {
      edges.push(edge(tail, "exit", "finally-abrupt"));
    }
  }
}

function innermostTryContaining(tries, value) {
  return tries.filter(candidate => {
    const branch = candidate.metadata.branch;
    return [branch.thenRange, ...(branch.catchRanges || []), branch.elseRange, branch.finallyRange]
      .filter(Boolean).some(range => locationWithinRange(value, range));
  }).sort((left, right) => tryRangeSize(left.metadata.branch) - tryRangeSize(right.metadata.branch))[0];
}

function tryRangeSize(branch) {
  return [branch.thenRange, ...(branch.catchRanges || []), branch.elseRange, branch.finallyRange]
    .filter(Boolean).reduce((total, range) => total + rangeSize(range), 0);
}

function innermostContaining(branches, value, rangeFor) {
  return branches.filter(candidate => locationWithinRange(value, rangeFor(candidate)))
    .sort((left, right) => rangeSize(rangeFor(left)) - rangeSize(rangeFor(right)))[0];
}

function rangeSize(range) {
  if (!range) return Number.MAX_SAFE_INTEGER;
  if (Number.isFinite(range.startOffset) && Number.isFinite(range.endOffset)) return range.endOffset - range.startOffset;
  return (range.end || 0) - (range.start || 0);
}

function applyGuardScopes(operations, dominators, edges = []) {
  const branches = operations.filter(operation => operation.kind === "branch" && operation.metadata.branch);
  for (const guard of operations.filter(operation => operation.kind === "guard")) {
    const branch = branches.find(candidate => {
      const range = candidate.metadata.branch.conditionRange;
      return range
        ? locationWithinRange(guard.location, range)
        : candidate.location.line === guard.location.line;
    });
    if (!branch) continue;
    const metadata = branch.metadata.branch;
    const negative = /^\s*!/.test(metadata.condition || "") || /===?\s*false\b|!==?\s*true\b/.test(metadata.condition || "");
    const guardedBranch = negative ? metadata.elseBlocks : metadata.thenBlocks;
    const rejectedBranch = negative ? metadata.thenBlocks : metadata.elseBlocks;
    const rejectedTerminates = rejectedBranch.length > 0 &&
      !canReach(rejectedBranch[0], metadata.joinBlock, edges);
    const postDominated = rejectedTerminates
      ? Object.entries(dominators).filter(([, values]) => values.includes(metadata.joinBlock)).map(([blockId]) => blockId)
      : [];
    guard.metadata.guardAppliesToBlocks = [...new Set([...guardedBranch, ...postDominated])];
    guard.metadata.guardDominance = rejectedTerminates ? "branch-and-post-dominance" : "branch-only";
  }
}

function canReach(start, target, edges) {
  if (!start || !target) return false;
  if (start === target) return true;
  return reachableFrom(start, edges).includes(target);
}

function computeDominators(blockIds, edges, entry) {
  const all = new Set(blockIds);
  const predecessors = new Map(blockIds.map(id => [id, []]));
  for (const item of edges) predecessors.get(item.to)?.push(item.from);
  const result = new Map(blockIds.map(id => [id, id === entry ? new Set([entry]) : new Set(all)]));
  let changed = true;
  while (changed) {
    changed = false;
    for (const id of blockIds) {
      if (id === entry) continue;
      const incoming = predecessors.get(id) || [];
      let next = incoming.length ? intersect(incoming.map(parent => result.get(parent))) : new Set();
      next.add(id);
      if (!sameSet(next, result.get(id))) { result.set(id, next); changed = true; }
    }
  }
  return Object.fromEntries([...result].map(([id, values]) => [id, [...values]]));
}

function blocksInRange(operations, range) {
  if (!range) return [];
  return operations.filter(operation => locationWithinRange(operation.location, range))
    .map(operation => `op:${operation.id}`);
}

function blocksInRanges(operations, ranges = []) {
  return [...new Set((ranges || []).flatMap(range => blocksInRange(operations, range)))];
}

function locationWithinRange(value, range) {
  if (hasOffsets(value) && hasRangeOffsets(range)) {
    return value.startOffset >= range.startOffset && value.endOffset <= range.endOffset;
  }
  return value.line >= range.start && value.endLine <= range.end;
}

function isAfterRange(value, rangeEnd) {
  if (hasOffsets(value) && Number.isFinite(rangeEnd.endOffset)) return value.startOffset >= rangeEnd.endOffset;
  return value.line > (rangeEnd.endLine || rangeEnd.end || rangeEnd.line);
}

function laterRangeEnd(current, range) {
  if (Number.isFinite(range.endOffset)) {
    return !Number.isFinite(current.endOffset) || range.endOffset > current.endOffset
      ? { endOffset: range.endOffset, endLine: range.end }
      : current;
  }
  return (range.end || 0) > (current.endLine || current.line || 0) ? { endLine: range.end } : current;
}

function hasOffsets(value) { return Number.isFinite(value?.startOffset) && Number.isFinite(value?.endOffset); }
function hasRangeOffsets(value) { return Number.isFinite(value?.startOffset) && Number.isFinite(value?.endOffset); }

function compareOperations(left, right) {
  if (Number.isFinite(left.location.startOffset) && Number.isFinite(right.location.startOffset)) {
    const leftContainsRight = containsLocation(left.location, right.location);
    const rightContainsLeft = containsLocation(right.location, left.location);
    if (leftContainsRight && !rightContainsLeft) return left.kind === "branch" ? -1 : 1;
    if (rightContainsLeft && !leftContainsRight) return right.kind === "branch" ? 1 : -1;
    return left.location.startOffset - right.location.startOffset || left.location.endOffset - right.location.endOffset || rank(left.kind) - rank(right.kind);
  }
  return left.location.line - right.location.line || rank(left.kind) - rank(right.kind);
}

function containsLocation(parent, child) {
  return parent.startOffset <= child.startOffset && parent.endOffset >= child.endOffset;
}

function connectTail(edges, branchBlocks, joinId, operations, kind = "join") {
  if (!branchBlocks.length) return;
  const tail = branchBlocks.at(-1);
  const operation = operations.find(candidate => `op:${candidate.id}` === tail);
  if (["return", "throw", "break", "continue"].includes(operation?.kind)) return;
  removeOutgoing(edges, tail);
  edges.push(edge(tail, joinId, kind));
}

function reachableFrom(start, edges) {
  const outgoing = new Map();
  for (const item of edges) {
    if (!outgoing.has(item.from)) outgoing.set(item.from, []);
    outgoing.get(item.from).push(item.to);
  }
  const seen = new Set();
  const pending = [start];
  while (pending.length) {
    const current = pending.pop();
    if (seen.has(current)) continue;
    seen.add(current);
    for (const next of outgoing.get(current) || []) pending.push(next);
  }
  return [...seen];
}

function enumerateCFGPaths(cfg, options = {}) {
  if (!cfg?.edges?.length) return [];
  const start = options.startBlock || cfg.entry || "entry";
  if (cfg.reachableBlocks?.length && !cfg.reachableBlocks.includes(start)) return [];
  const maxPaths = Math.max(1, options.maxPaths || 64);
  const maxVisits = Math.max(1, options.maxVisits || 3);
  const outgoing = new Map();
  for (const item of cfg.edges) {
    if (!outgoing.has(item.from)) outgoing.set(item.from, []);
    outgoing.get(item.from).push(item);
  }
  const results = [];
  let truncated = false;
  const exit = cfg.exit || "exit";
  const path = [];
  const visits = new Map();
  const stack = [{ type: "enter", blockId: start }];
  while (stack.length) {
    const frame = stack.pop();
    if (frame.type === "leave") {
      path.pop();
      const remaining = (visits.get(frame.blockId) || 1) - 1;
      if (remaining > 0) visits.set(frame.blockId, remaining);
      else visits.delete(frame.blockId);
      continue;
    }
    if (results.length >= maxPaths) { truncated = true; break; }
    const current = frame.blockId;
    path.push(current);
    visits.set(current, (visits.get(current) || 0) + 1);
    const nextEdges = outgoing.get(current) || [];
    if (current === exit || !nextEdges.length) {
      results.push([...path]);
      path.pop();
      const remaining = (visits.get(current) || 1) - 1;
      if (remaining > 0) visits.set(current, remaining);
      else visits.delete(current);
      continue;
    }
    const eligible = nextEdges.filter(item => (visits.get(item.to) || 0) < maxVisits);
    if (!eligible.length) {
      truncated = true;
      path.pop();
      const remaining = (visits.get(current) || 1) - 1;
      if (remaining > 0) visits.set(current, remaining);
      else visits.delete(current);
      continue;
    }
    stack.push({ type: "leave", blockId: current });
    for (let index = eligible.length - 1; index >= 0; index -= 1) {
      stack.push({ type: "enter", blockId: eligible[index].to });
    }
  }
  Object.defineProperty(results, "truncated", { value: truncated, enumerable: false });
  return results;
}

function removeOutgoing(edges, blockId) {
  for (let index = edges.length - 1; index >= 0; index -= 1) if (edges[index].from === blockId) edges.splice(index, 1);
}

function intersect(sets) {
  if (!sets.length) return new Set();
  return new Set([...sets[0]].filter(value => sets.every(set => set.has(value))));
}

function sameSet(left, right) {
  return left.size === right.size && [...left].every(value => right.has(value));
}

function block(id, kind, operation) {
  return {
    id,
    kind,
    operationIds: operation ? [operation.id] : [],
    line: operation?.location.line,
    startColumn: operation?.location.startColumn,
    startOffset: operation?.location.startOffset,
  };
}

function edge(from, to, kind) { return { from, to, kind }; }
function rank(kind) { return { source: 0, assignment: 1, branch: 2, guard: 3, call: 4, sink: 5, throw: 6, break: 6, continue: 6, return: 7 }[kind] ?? 9; }

module.exports = { applyGuardScopes, buildOperationCFG, compareOperations, computeDominators, enumerateCFGPaths, locationWithinRange, reachableFrom };
