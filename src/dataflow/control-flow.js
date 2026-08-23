"use strict";

const { enumerateCFGPaths } = require("./cfg");
const { isReachableEvent } = require("./propagation");

function eventSequences(fn, options = {}) {
  const startLine = Number(options.startLine) || fn.line || 1;
  const annotations = (fn.events || []).filter(event =>
    event.line <= (fn.line || 1) && (event.type === "control" || event.functionAnnotation));
  if (!fn.cfg?.edges?.length) return withTruncation([uniqueEvents([
    ...annotations,
    ...(fn.events || []).filter(event => event.line >= startLine && isReachableEvent(event)),
  ])], false);

  const startBlock = options.startBlock || fn.cfg.entry;
  const paths = enumerateCFGPaths(fn.cfg, {
    startBlock,
    maxPaths: options.maxPaths || 64,
    maxVisits: options.maxVisits || 3,
  });
  const byBlock = new Map();
  for (const event of fn.events || []) {
    if (!event.blockId) continue;
    if (!byBlock.has(event.blockId)) byBlock.set(event.blockId, []);
    byBlock.get(event.blockId).push(event);
  }
  const targets = new Set(options.targetBlocks || []);
  const selected = targets.size ? paths.filter(path => path.some(blockId => targets.has(blockId))) : paths;
  const sequences = selected.map(path => {
    let blocks = path;
    if (targets.size) {
      const targetIndex = path.findIndex(blockId => targets.has(blockId));
      blocks = path.slice(0, targetIndex + (options.includeTarget === false ? 0 : 1));
    }
    return uniqueEvents([
      ...annotations,
      ...blocks.flatMap(blockId => byBlock.get(blockId) || [])
        .filter(event => event.line >= startLine ||
          (event.line <= (fn.line || 1) && (event.type === "control" || event.functionAnnotation))),
    ]);
  });
  return withTruncation(sequences, paths.truncated);
}

function targetBlocksAtLine(fn, line) {
  return [...new Set((fn.events || [])
    .filter(event => event.line === line && isReachableEvent(event) && event.blockId)
    .map(event => event.blockId))];
}

function uniqueEvents(events) {
  const seen = new Set();
  return events.filter(event => {
    const key = event.id || `${event.type}:${event.blockId}:${event.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function withTruncation(sequences, truncated) {
  Object.defineProperty(sequences, "truncated", { value: Boolean(truncated), enumerable: false });
  return sequences;
}

module.exports = { eventSequences, targetBlocksAtLine };
