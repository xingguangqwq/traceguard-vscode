"use strict";

const { structuralDigest } = require("../analysis/structural-digest");
const { normalizePath } = require("../identity");

// Hash the dependency graph once, including recursive components. Iterative
// traversal avoids a stack overflow on long call chains in large workspaces.
function dependencyFingerprints(records) {
  const byKey = new Map(records.map(record => [record.key, record]));
  const edges = new Map(records.map(record => [record.key, [...new Set(record.dependencies || [])].filter(key => byKey.has(key)).sort()]));
  const reverse = new Map(records.map(record => [record.key, []]));
  for (const [key, dependencies] of edges) for (const dependency of dependencies) reverse.get(dependency).push(key);
  const seen = new Set();
  const order = [];
  for (const key of byKey.keys()) {
    if (seen.has(key)) continue;
    seen.add(key);
    const stack = [{ key, index: 0 }];
    while (stack.length) {
      const frame = stack.at(-1);
      const next = edges.get(frame.key)[frame.index++];
      if (next !== undefined) {
        if (!seen.has(next)) { seen.add(next); stack.push({ key: next, index: 0 }); }
      } else { order.push(frame.key); stack.pop(); }
    }
  }
  const components = [];
  const componentFor = new Map();
  for (const key of order.reverse()) {
    if (componentFor.has(key)) continue;
    const id = components.length;
    const members = [];
    const pending = [key];
    componentFor.set(key, id);
    while (pending.length) {
      const current = pending.pop();
      members.push(current);
      for (const parent of reverse.get(current)) {
        if (!componentFor.has(parent)) { componentFor.set(parent, id); pending.push(parent); }
      }
    }
    components.push(members.sort());
  }
  const hashes = new Map();
  // Kosaraju discovers callers before dependencies; reversing makes every
  // outgoing component fingerprint available before its callers are hashed.
  for (let id = components.length - 1; id >= 0; id -= 1) {
    const members = components[id];
    const dependencies = [...new Set(members.flatMap(key => edges.get(key).map(next => componentFor.get(next))))]
      .filter(next => next !== id).map(next => hashes.get(next)).sort();
    hashes.set(id, structuralDigest(["review-v1", members.map(key => [key, byKey.get(key).digest,
      [...new Set(byKey.get(key).dependencies || [])].sort()]), dependencies]));
  }
  return new Map([...byKey.keys()].map(key => [key, hashes.get(componentFor.get(key))]));
}

function attachReviewFingerprints(model, findings, fileFingerprints) {
  const fingerprint = (paths, identity) => {
    const keys = [...new Set(paths.filter(Boolean).map(value => normalizePath(value)))].sort();
    if (!keys.length || keys.some(key => !fileFingerprints.has(key))) return undefined;
    return structuralDigest([identity, keys.map(key => [key, fileFingerprints.get(key)])]);
  };
  for (const item of model.items || []) {
    item.reviewFingerprint = fingerprint([item.absolutePath], [item.symbolKey, item.title, item.kind]);
  }
  for (const finding of findings || []) {
    const flows = finding.paths?.length ? finding.paths : [finding.path].filter(Boolean);
    finding.reviewFingerprint = fingerprint([finding.absolutePath,
      ...flows.flatMap(flow => (flow.steps || []).map(step => step.absolutePath))],
    [finding.ruleId, finding.sinkKind, finding.confidence]);
  }
}

module.exports = { attachReviewFingerprints, dependencyFingerprints };
