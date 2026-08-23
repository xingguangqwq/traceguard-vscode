"use strict";

const path = require("path");
const { normalizePath } = require("../identity");

function buildFunctionIndex(functions) {
  const index = new Map();
  for (const fn of functions) {
    const key = fn.name.toLowerCase();
    if (!index.has(key)) index.set(key, []);
    index.get(key).push(fn);
  }
  return index;
}

function resolveCandidates(index, event, caller) {
  const reference = findEventReference(caller.references, event);
  const scored = (index.get(event.callee.toLowerCase()) || [])
    .filter(candidate => !event.targetFunctionId || candidate.id === event.targetFunctionId)
    .filter(candidate => languagesCanCall(caller.language, candidate.language))
    .map(candidate => scoreCandidate(candidate, caller, event, reference))
    .sort((left, right) => right.score - left.score || left.fn.relativePath.localeCompare(right.fn.relativePath));
  if (!scored.length) return [];
  const executable = scored.filter(item => item.fn.executable !== false);
  const executablePrecise = executable.filter(item => item.precise);
  const pool = executablePrecise.length ? executable : scored;
  const strong = pool.filter(item => item.strong);
  const precise = pool.filter(item => item.precise);
  const bestScore = pool[0].score;
  const preciseScore = precise[0]?.score;
  const selected = (precise.length
    ? precise.filter(item => item.score === preciseScore)
    : strong.length ? strong : pool.filter(item => item.score === bestScore)).slice(0, 6);
  const ambiguous = selected.length > 1;
  return selected.map(item => ({ ...item, quality: ambiguous ? "review" : item.strong ? "high" : "medium" }));
}

function scoreCandidate(candidate, caller, event, reference) {
  const exactTarget = Boolean(event.targetFunctionId && candidate.id === event.targetFunctionId);
  const sameFile = normalizePath(candidate.absolutePath) === normalizePath(caller.absolutePath);
  const referenceMatch = reference ? referenceCandidateMatch(reference.target, candidate.relativePath) : "none";
  const receiverMatch = event.receiver && candidateFileNames(candidate.relativePath).includes(canonicalName(event.receiver));
  const receiverScopeMatch = receiverMatchesType(event.receiverType, candidate.enclosingScope);
  const receiverContractMatch = (candidate.implementedTypes || []).some(type => receiverMatchesType(event.receiverType, type));
  const receiverTypeMatch = receiverScopeMatch || receiverContractMatch;
  const arityMatch = !event.arguments?.length && !candidate.parameters?.length || event.arguments?.length === candidate.parameters?.length;
  const argumentTypeScore = matchingArgumentTypeScore(event.argumentTypes, candidate.parameterDetails);
  const sameDirectory = directory(candidate.relativePath) === directory(caller.relativePath);
  const strong = Boolean(exactTarget || sameFile || referenceMatch === "exact" || receiverTypeMatch || receiverMatch);
  const reason = exactTarget ? "explicit closure target" : receiverContractMatch ? `receiver contract ${event.receiverType}` : receiverScopeMatch ? `receiver type ${event.receiverType}` : sameFile ? "same file" : referenceMatch !== "none" ? `import ${reference.target}` : receiverMatch ? `receiver ${event.receiver}` : sameDirectory ? "nearest file" : "function name";
  return {
    fn: candidate,
    score: (exactTarget ? 40 : 0) + (receiverTypeMatch ? 24 : 0) + (referenceMatch === "exact" ? 20 : referenceMatch === "name" ? 6 : 0) + (sameFile ? 16 : 0) + (receiverMatch ? 12 : 0) +
      (arityMatch ? 8 : -8) + argumentTypeScore + (sameDirectory ? 3 : 0) + (candidate.language === caller.language ? 2 : 0),
    strong,
    precise: Boolean(exactTarget || receiverTypeMatch || referenceMatch === "exact" || receiverMatch),
    reason,
  };
}

function findEventReference(references = [], event) {
  const names = [event.receiver, event.callee].filter(Boolean).map(canonicalName);
  return references.find(reference => names.includes(canonicalName(reference.local)));
}

function referenceCandidateMatch(target, relativePath) {
  const targetPath = normalizeReferencePath(target);
  const candidatePath = normalizePath(relativePath).replace(/\.[a-z0-9]+$/i, "");
  if (targetPath && (candidatePath === targetPath || candidatePath.endsWith("/" + targetPath) || candidatePath.endsWith("/" + targetPath + "/index"))) return "exact";
  const targetName = canonicalName(referenceTargetName(target));
  return targetName && candidateFileNames(relativePath).includes(targetName) ? "name" : "none";
}

function normalizeReferencePath(target) {
  let normalized = String(target || "").replaceAll("\\", "/").replace(/\.(?:js|jsx|mjs|cjs|ts|tsx|py|php|java|cs|go)$/i, "");
  if (!normalized.includes("/")) normalized = normalized.replaceAll(".", "/");
  return normalizePath(normalized).replace(/^(?:\.\.\/|\.\/)+/, "").replace(/^\/+/, "");
}

function candidateFileNames(relativePath) {
  const normalized = String(relativePath || "").replaceAll("\\", "/");
  const extension = path.posix.extname(normalized);
  const stem = path.posix.basename(normalized, extension);
  const names = [canonicalName(stem)];
  if (stem.toLowerCase() === "index") names.push(canonicalName(path.posix.basename(path.posix.dirname(normalized))));
  return unique(names);
}

function referenceTargetName(target) {
  const normalized = String(target || "").replaceAll("\\", "/").replace(/\.(?:js|jsx|mjs|cjs|ts|tsx|py|php|java|cs|go)$/i, "");
  return normalized.split(/[/.]/).filter(Boolean).at(-1) || "";
}

function languagesCanCall(left, right) {
  if (left === right) return true;
  return ["javascript", "typescript"].includes(left) && ["javascript", "typescript"].includes(right);
}

function matchingArgumentTypeScore(argumentTypes = [], parameters = []) {
  if (!argumentTypes.length || !parameters.length) return 0;
  let score = 0;
  argumentTypes.forEach((actual, index) => {
    const expected = parameters[index]?.type;
    if (!actual || actual === "?" || !expected || expected === "?") return;
    score += receiverMatchesType(actual, expected) ? 3 : -2;
  });
  return score;
}

function receiverMatchesType(receiverType, candidateType) {
  const scope = String(candidateType || "").split(".").filter(Boolean).at(-1);
  if (!receiverType || !scope || scope === "<file>") return false;
  const candidates = String(receiverType).split(/[|&<>,()[\]{}\s]+/).map(canonicalName).filter(Boolean);
  return candidates.includes(canonicalName(scope));
}

function canonicalName(value) { return String(value || "").replace(/^\$/, "").replace(/[^A-Za-z0-9]/g, "").toLowerCase(); }
function directory(relativePath) { return path.posix.dirname(String(relativePath).replaceAll("\\", "/")); }
function unique(values) { return [...new Set(values.filter(Boolean))]; }

module.exports = { buildFunctionIndex, canonicalName, normalizePath, resolveCandidates };
