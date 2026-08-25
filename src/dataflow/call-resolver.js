"use strict";

const path = require("path");
const { normalizePath } = require("../identity");
const { composerPathsForType } = require("../config/project-identity");

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
    .filter(candidate => !caller.workspaceRoot || candidate.workspaceRoot === caller.workspaceRoot)
    .map(candidate => scoreCandidate(candidate, caller, event, reference))
    .filter(candidate => candidate.compatible !== false)
    .sort((left, right) => right.score - left.score || left.fn.relativePath.localeCompare(right.fn.relativePath));
  if (!scored.length) return [];
  const executable = scored.filter(item => item.fn.executable !== false);
  const executablePrecise = executable.filter(item => item.precise);
  const pool = executablePrecise.length ? executable : scored;
  const strong = pool.filter(item => item.strong);
  const precise = pool.filter(item => item.precise);
  const bestScore = pool[0].score;
  const preciseScore = precise[0]?.score;
  const selected = precise.length
    ? precise.filter(item => item.score === preciseScore)
    : strong.length ? strong : pool.filter(item => item.score === bestScore);
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
  const typeResolution = languageTypeResolution(candidate, caller, event, reference);
  const callableParameters = implicitParameterOffset(candidate, event) ? candidate.parameters.slice(1) : candidate.parameters;
  const callableParameterDetails = implicitParameterOffset(candidate, event) ? candidate.parameterDetails.slice(1) : candidate.parameterDetails;
  const arityMatch = !event.arguments?.length && !callableParameters?.length || event.arguments?.length === callableParameters?.length;
  const argumentTypeScore = matchingArgumentTypeScore(event.argumentTypes, callableParameterDetails);
  const sameDirectory = directory(candidate.relativePath) === directory(caller.relativePath);
  const strong = Boolean(exactTarget || sameFile || typeResolution.match || referenceMatch === "exact" || receiverTypeMatch || receiverMatch);
  const reason = exactTarget ? "explicit closure target" : typeResolution.match ? `resolved type ${typeResolution.target}` : receiverContractMatch ? `receiver contract ${event.receiverType}` : receiverScopeMatch ? `receiver type ${event.receiverType}` : sameFile ? "same file" : referenceMatch !== "none" ? `import ${reference.target}` : receiverMatch ? `receiver ${event.receiver}` : sameDirectory ? "nearest file" : "function name";
  return {
    fn: candidate,
    score: (exactTarget ? 40 : 0) + (typeResolution.match ? 36 : 0) + (receiverTypeMatch ? 24 : 0) + (referenceMatch === "exact" ? 20 : referenceMatch === "name" ? 6 : 0) + (sameFile ? 16 : 0) + (receiverMatch ? 12 : 0) +
      (arityMatch ? 8 : -8) + argumentTypeScore + (sameDirectory ? 3 : 0) + (candidate.language === caller.language ? 2 : 0),
    strong,
    precise: Boolean(exactTarget || typeResolution.match || receiverTypeMatch || referenceMatch === "exact" || receiverMatch),
    compatible: typeResolution.compatible,
    reason,
  };
}

function findEventReference(references = [], event) {
  const names = [event.receiver, event.callee].filter(Boolean).map(canonicalName);
  const direct = references.find(reference => names.includes(canonicalName(reference.local)));
  if (direct?.kind !== "type") return direct;
  const importedType = references.find(reference => reference.kind === "import" &&
    canonicalName(reference.local) === canonicalName(referenceTargetName(direct.target)));
  return importedType ? { ...importedType, local: direct.local, declaredType: direct.target } : direct;
}

function languageTypeResolution(candidate, caller, event, reference) {
  if (caller.language === "java" && candidate.language === "java") return javaTypeResolution(candidate, caller, event, reference);
  if (caller.language === "php" && candidate.language === "php") return phpTypeResolution(candidate, caller, event, reference);
  if (caller.language === "python" && candidate.language === "python") return pythonTypeResolution(candidate, caller, event, reference);
  return { compatible: true };
}

function javaTypeResolution(candidate, caller, event, reference) {
  const targets = javaExpectedTypeTargets(caller, event, reference);
  if (!targets.length) return { compatible: true };
  const candidateType = normalizeJavaType(candidate.qualifiedEnclosingScope);
  const matchedTarget = targets.find(target => javaTypeAssignable(candidateType, normalizeJavaType(target), candidate));
  if (matchedTarget) return { compatible: true, match: true, target: matchedTarget };
  const declared = String(reference?.declaredType || (reference?.kind === "type" ? reference.target : "") || event.receiverType || "").trim();
  const explicitImport = (caller.references || []).some(item => item.kind === "import" && item.local !== "*" && canonicalName(item.local) === canonicalName(declared));
  const wildcardImport = (caller.references || []).some(item => item.kind === "import" && item.local === "*");
  if (declared && !declared.includes(".") && !explicitImport && !wildcardImport) return { compatible: true };
  if (!candidate.packageName) return { compatible: true };
  return { compatible: false, target: targets[0] };
}

function javaExpectedTypeTargets(caller, event, reference) {
  if (reference?.kind === "import" && reference.target && !reference.target.endsWith(".*")) return [reference.target];
  const declared = String(reference?.declaredType || (reference?.kind === "type" ? reference.target : "") || event.receiverType || "")
    .replace(/<.*>/g, "").trim();
  if (!declared) return [];
  if (declared.includes(".")) return [declared];
  const explicit = (caller.references || []).find(item => item.kind === "import" && item.local !== "*" && canonicalName(item.local) === canonicalName(declared));
  if (explicit) return [explicit.target];
  const wildcardTargets = (caller.references || [])
    .filter(item => item.kind === "import" && item.local === "*" && item.target.endsWith(".*"))
    .map(item => `${item.target.slice(0, -2)}.${declared}`);
  return unique([...wildcardTargets, caller.packageName ? `${caller.packageName}.${declared}` : declared]);
}

function javaTypeAssignable(candidateType, target, candidate) {
  if (!candidateType || !target) return false;
  const relations = new Map((candidate.typeRelations || []).map(relation => [
    normalizeJavaType(relation.type),
    (relation.extends || []).map(normalizeJavaType),
  ]));
  if (!relations.has(candidateType)) {
    relations.set(candidateType, (candidate.implementedTypes || []).map(type => resolveJavaType(candidate, type)).filter(Boolean));
  }
  const pending = [candidateType];
  const visited = new Set();
  while (pending.length) {
    const current = pending.shift();
    if (!current || visited.has(current)) continue;
    if (current === target) return true;
    visited.add(current);
    pending.push(...(relations.get(current) || []));
  }
  return false;
}

function phpTypeResolution(candidate, caller, event, reference) {
  const declared = String(reference?.declaredType || (reference?.kind === "type" ? reference.target : "") || event.receiverType || "").trim();
  if (!declared) return { compatible: true };
  const simple = referenceTargetName(declared);
  const imported = (caller.references || []).find(item => item.kind === "import" && canonicalName(item.local) === canonicalName(simple));
  const resolvedTarget = imported?.target || (declared.includes("\\") ? declared : caller.namespaceName ? `${caller.namespaceName}\\${declared}` : declared);
  const composerPaths = composerPathsForType(caller.projectIdentity, resolvedTarget);
  if (composerPaths.length) {
    const candidatePath = normalizePath(candidate.absolutePath);
    if (composerPaths.includes(candidatePath)) return { compatible: true, match: true, target: resolvedTarget };
    return { compatible: false, target: resolvedTarget };
  }
  const target = normalizePhpType(resolvedTarget);
  if (!target.includes(".")) return { compatible: true };
  const candidateType = normalizePhpType(candidate.qualifiedEnclosingScope);
  if (candidateType === target) return { compatible: true, match: true, target: imported?.target || declared };
  if (!candidate.namespaceName) return { compatible: true };
  return { compatible: false, target: imported?.target || declared };
}

function pythonTypeResolution(candidate, caller, event, reference) {
  const declared = String(reference?.declaredType || (reference?.kind === "type" ? reference.target : "") || event.receiverType || "").trim();
  if (!declared || declared === "?") return { compatible: true };
  const parts = declared.split(".").filter(Boolean);
  const expectedType = parts.at(-1);
  if (!receiverMatchesType(expectedType, candidate.enclosingScope)) {
    return parts.length > 1 ? { compatible: false, target: declared } : { compatible: true };
  }
  if (parts.length === 1) return { compatible: true, match: true, target: declared };
  const expectedModule = parts.slice(0, -1).join("/");
  const moduleMatch = referenceCandidateMatch(expectedModule, candidate.relativePath);
  return moduleMatch === "exact"
    ? { compatible: true, match: true, target: declared }
    : { compatible: false, target: declared };
}

function resolveJavaType(candidate, type) {
  const value = String(type || "").replace(/<.*>/g, "").trim();
  if (!value) return undefined;
  if (value.includes(".")) return normalizeJavaType(value);
  const imported = (candidate.references || []).find(reference => reference.kind === "import" && canonicalName(reference.local) === canonicalName(value));
  return normalizeJavaType(imported?.target || (candidate.packageName ? `${candidate.packageName}.${value}` : value));
}

function normalizeJavaType(value) {
  return String(value || "").replace(/<.*>/g, "").replace(/\s+/g, "").replace(/\$/g, ".").toLowerCase();
}

function normalizePhpType(value) {
  return String(value || "").replace(/^\\+/, "").replace(/[\\/]+/g, ".").replace(/\.+/g, ".").toLowerCase();
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

function implicitParameterOffset(candidate, event) {
  return candidate.language === "python" && event.receiver && ["self", "cls"].includes(candidate.parameters?.[0]) ? 1 : 0;
}

function canonicalName(value) { return String(value || "").replace(/^\$/, "").replace(/[^A-Za-z0-9]/g, "").toLowerCase(); }
function directory(relativePath) { return path.posix.dirname(String(relativePath).replaceAll("\\", "/")); }
function unique(values) { return [...new Set(values.filter(Boolean))]; }

module.exports = { buildFunctionIndex, canonicalName, normalizePath, resolveCandidates };
