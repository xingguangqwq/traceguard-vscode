"use strict";

const { GuardCapability, SinkKind } = require("./semantics");
const { argumentConstraintRejection } = require("./argument-constraints");
const { SYNTAX_SEMANTIC_MODELS } = require("./syntax-models");
const { SUPPLEMENTAL_SEMANTIC_MODELS } = require("./supplemental-models");
const { COLLECTION_SEMANTIC_MODELS } = require("./collection-models");
const { INJECTION_MODELS } = require("./models/injection");
const { JAVA_RESPONSE_MODELS } = require("./models/java-response");
const { compileCatalogPatterns: compilePatterns } = require("./catalog-pattern-compiler");

const { SemanticRole } = require("./model-factories");

const { JAVASCRIPT_MODELS } = require("./models/javascript");
const { PHP_MODELS } = require("./models/php");
const { PYTHON_MODELS } = require("./models/python");
const { JAVA_MODELS } = require("./models/java");
const { GO_MODELS } = require("./models/go");
const { CSHARP_MODELS } = require("./models/csharp");

const SEMANTIC_MODELS = Object.freeze([
  ...JAVASCRIPT_MODELS,
  ...PHP_MODELS,
  ...PYTHON_MODELS,
  ...JAVA_MODELS,
  ...GO_MODELS,
  ...CSHARP_MODELS,
  ...SYNTAX_SEMANTIC_MODELS,
  ...SUPPLEMENTAL_SEMANTIC_MODELS,
  ...INJECTION_MODELS,
  ...JAVA_RESPONSE_MODELS,
]);

const CATALOG_SCHEMA_VERSION = 1;

const STRUCTURAL_SEMANTIC_MODELS = Object.freeze([
  Object.freeze({
    id: "structural.collection-safe-join",
    role: SemanticRole.GUARD,
    languages: ["php"],
    factKind: "fixed-numeric-collection-join",
    guardCapabilities: [
      GuardCapability.NUMERIC_ONLY,
      GuardCapability.FIXED_COLLECTION,
      GuardCapability.ALL_ELEMENTS,
      GuardCapability.SAFE_JOIN,
    ],
    applicableSinkKinds: [SinkKind.COMMAND_EXEC],
    label: "Validated fixed collection rebuilt with literal separators",
  }),
]);

function resolveSemanticCall(language, call = {}, customModels = [], expectedRole) {
  const identity = call.symbol || {};
  const semanticName = identity.exportName || call.function;
  const registry = [...SEMANTIC_MODELS, ...(Array.isArray(customModels) ? customModels.filter(validCustomModel) : [])];
  let candidates = registry.filter(model =>
    model.languages.includes(language) &&
    (!expectedRole || model.role === expectedRole) &&
    model.callNames.some(name => canonical(name) === canonical(semanticName)));
  if (!candidates.length) return { status: "none" };

  if (identity.shadowed && !candidates.some(model => model.custom && model.customUnqualified)) {
    const reviewCandidate = isDynamicReceiverType(identity.receiverType) &&
      candidates.find(model => model.patternReceiverAgnostic);
    if (reviewCandidate) return resolution(reviewCandidate, "candidate", identity, call);
    return {
      status: "rejected",
      reason: "The call name resolves to a local declaration that shadows a modeled security API.",
      candidates: candidates.map(model => model.id),
    };
  }

  for (const model of candidates) {
    if (call.receiver && model.global) continue;
    if (model.custom && model.customUnqualified && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "syntax", identity, call);
    }
    // A receiver type declared in .traceguard.json is an explicit project contract.
    // It remains authoritative when the frontend can read the declared type name but
    // the corresponding source/dependency is absent from the workspace.
    if (model.custom && identity.receiverType && receiverMatches(model, identity.receiverType)) {
      return resolution(model, "verified", identity, call);
    }
    if (model.global && identity.kind === "global" && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "verified", identity, call);
    }
    if (model.global && !call.receiver && !identity.shadowed && !identity.qualifiedName && !identity.moduleName &&
      [undefined, "unresolved"].includes(identity.kind) && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "syntax", identity, call);
    }
    if (identity.moduleName && moduleMatches(model, identity.moduleName) && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "verified", identity, call);
    }
    // A regular-expression literal receiver is stronger evidence than any
    // inferred type: under noLib the checker reports `{}` for RegExp, so this
    // check runs before type-based resolution for models that opt in.
    if (model.regexLiteralReceiver && call.receiver && isRegexLiteralReceiver(call.receiver)) {
      // WHITELIST_PATTERN models only trust anchored character-class-only
      // patterns (`^[a-z0-9]+$`); anything looser resolves to nothing, so the
      // flow stays reviewable instead of being silently suppressed.
      if (model.requireAnchoredWhitelist && !isAnchoredWhitelistRegex(call.receiver)) continue;
      return resolution(model, "syntax", { ...identity, qualifiedName: `${call.receiver}.${semanticName}` }, call);
    }
    if (!model.requiresModuleIdentity && !identity.unresolvedType && identity.qualifiedName && qualifiedMatches(model, identity.qualifiedName)) {
      return resolution(model, identity.verified ? "verified" : "syntax", identity, call);
    }
    if (!model.requiresModuleIdentity && identity.receiverType && receiverMatches(model, identity.receiverType)) {
      return resolution(model, identity.verified ? "verified" : "syntax", identity, call);
    }
    if (call.receiver && (!identity.receiverType || isDynamicReceiverType(identity.receiverType))) {
      const receiverEvidence = explicitSyntaxReceiverEvidence(model, call.receiver);
      if (receiverEvidence) {
        return resolution(model, receiverEvidence, { ...identity, qualifiedName: `${call.receiver}.${semanticName}` }, call);
      }
    }
    if (!model.requiresModuleIdentity && call.receiver &&
      (!identity.receiverType || isDynamicReceiverType(identity.receiverType)) && inferredSyntaxReceiverMatches(model, call.receiver)) {
      return resolution(model, "syntax", { ...identity, qualifiedName: `${call.receiver}.${semanticName}` }, call);
    }
  }

  const requiredIdentityIds = candidates.filter(model => model.requiresReceiverIdentity).map(model => model.id);
  candidates = candidates.filter(model => !model.requiresReceiverIdentity);
  if (!candidates.length) return {
    status: "rejected",
    reason: "This model requires proven receiver provenance; a matching method name alone is insufficient.",
    candidates: requiredIdentityIds,
  };

  if (expectedRole === SemanticRole.GUARD && identity.receiverType && !isDynamicReceiverType(identity.receiverType)) return {
    status: "rejected",
    reason: "The declared receiver type does not match any catalog or project-configured guard model.",
    candidates: candidates.map(model => model.id),
  };

  if (["java", "php", "python"].includes(language) && identity.receiverType && isDynamicReceiverType(identity.receiverType)) return {
    status: "candidate",
    reason: "The receiver has only a dynamic or top-level type, so the security API identity could not be proven.",
    candidates: candidates.map(model => model.id),
    candidateModels: candidates,
  };

  if (identity.kind === "local" || identity.kind === "import" || identity.kind === "require") return {
    status: "rejected",
    reason: "The resolved symbol does not match the module or receiver type required by the semantic model.",
    candidates: candidates.map(model => model.id),
  };

  if (identity.verified && identity.receiverType) return {
    status: "rejected",
    reason: "The resolved receiver type does not match the semantic model.",
    candidates: candidates.map(model => model.id),
  };

  const patternCandidates = candidates.filter(model => model.patternReceiverAgnostic);
  if (["javascript", "typescript"].includes(language) && call.receiver && patternCandidates.length &&
    (!identity.verified || isDynamicReceiverType(identity.receiverType))) {
    if (patternCandidates.length === 1) return resolution(patternCandidates[0], "candidate", identity, call);
    return {
      status: "candidate",
      reason: "The receiver is unresolved; catalog-declared pattern fallbacks remain review candidates only.",
      candidates: patternCandidates.map(model => model.id),
      candidateModels: patternCandidates,
    };
  }

  if (["javascript", "typescript"].includes(language) && call.receiver) return {
    status: "rejected",
    reason: "A member-call name matched, but TypeScript could not prove the required module or receiver identity.",
    candidates: candidates.map(model => model.id),
  };

  return {
    status: "candidate",
    reason: "A name pattern matched, but module and receiver identity could not be proven.",
    candidates: candidates.map(model => model.id),
    candidateModels: candidates,
  };
}

function validCustomModel(model) {
  return Boolean(model && model.custom && Array.isArray(model.languages) && Array.isArray(model.callNames) && model.role);
}

function resolution(model, status, identity, call) {
  const policyRejection = argumentConstraintRejection(model, call);
  if (policyRejection) return {
    status: "rejected",
    reason: policyRejection,
    model,
    candidates: [model.id],
  };
  const boundedStatus = model.interactiveCertainty === "review" ||
    (model.interactiveCertainty === "verified" && model.role === SemanticRole.GUARD && status !== "verified")
    ? "candidate"
    : status;
  return {
    status: boundedStatus,
    model,
    identity,
    certainty: boundedStatus === "verified" ? "high" : boundedStatus === "candidate" ? "low" : "medium",
  };
}

function moduleMatches(model, value) {
  const actual = normalizeModule(value);
  return model.moduleNames.some(moduleName => normalizeModule(moduleName) === actual);
}

function exportMatches(model, value) {
  return model.callNames.some(name => canonical(name) === canonical(value));
}

function qualifiedMatches(model, value) {
  const actual = canonicalQualified(value);
  return model.qualifiedNames.some(name => canonicalQualified(name) === actual || actual.endsWith(`.${canonicalQualified(name)}`));
}

function receiverMatches(model, value) {
  const actual = canonicalQualified(value);
  return model.receiverTypes.some(type => {
    const expected = canonicalQualified(type);
    return actual === expected || actual.endsWith(`.${expected}`);
  });
}

function explicitSyntaxReceiverEvidence(model, value) {
  const actual = canonicalQualified(value);
  if ((model.verifiedSyntaxReceiverNames || []).some(name => receiverExpressionMatches(actual, canonicalQualified(name)))) {
    return "verified";
  }
  if ((model.syntaxReceiverNames || []).some(name => receiverExpressionMatches(actual, canonicalQualified(name)))) {
    return "syntax";
  }
  return undefined;
}

function inferredSyntaxReceiverMatches(model, value) {
  const actual = canonicalQualified(value);
  const receiverNames = [
    ...model.moduleNames.flatMap(moduleName => {
      const normalized = normalizeModule(moduleName);
      return [normalized, normalized.split("/").at(-1)];
    }),
    ...model.receiverTypes.map(type => canonicalQualified(type)),
    ...model.qualifiedNames.map(name => canonicalQualified(name).split(".").slice(0, -1).join(".")),
  ].filter(Boolean);
  return receiverNames.some(expected => receiverExpressionMatches(actual, expected));
}

function receiverExpressionMatches(actual, expected) {
  return Boolean(expected && (actual === expected || actual.endsWith(`.${expected}`) || actual.startsWith(`${expected}.`)));
}

function normalizeModule(value) {
  return String(value || "").replace(/^node:/, "").replaceAll("\\", "/").toLowerCase();
}

function canonicalQualified(value) {
  return String(value || "").replace(/\s+/g, "").replace(/^[*&]+/, "").replace(/\\|::|->/g, ".").replace(/^\.+/, "").toLowerCase();
}

function canonical(value) {
  return String(value || "").replace(/[^A-Za-z0-9_$]/g, "").toLowerCase();
}

function isDynamicReceiverType(value) {
  return new Set(["?", "any", "mixed", "object", "java.lang.object", "dynamic", "unknown"])
    .has(canonicalQualified(value));
}

// A regular-expression literal receiver (`/^[a-z]+$/.test(value)`) is direct
// evidence that the callee is RegExp.prototype.test — no import resolution
// is required because the literal cannot be anything else.
function isRegexLiteralReceiver(value) {
  return /^\/.+\/[a-z]*$/i.test(String(value || "").trim());
}

// An anchored, character-class-only pattern (`^[a-z0-9_-]+$`) is a real
// whitelist: it cannot match shell metacharacters or SQL operators. Escaped
// classes like \d \w are accepted; `.`, `*`, `?`, groups and alternation are
// rejected because they weaken the guarantee.
function isAnchoredWhitelistRegex(value) {
  const match = /^\/(.+)\/[a-z]*$/.exec(String(value || "").trim());
  if (!match) return false;
  let body = match[1];
  if (!body.startsWith("^") || !body.endsWith("$")) return false;
  body = body.slice(1, -1);
  body = body.replace(/\\./g, "").replace(/\[[^\]]*\]/g, "");
  return !/[.*?()|/]|\{[^}]*\?/.test(body);
}

function validateSemanticCatalog(models = SEMANTIC_MODELS) {
  const issues = [];
  const ids = new Set();
  const roles = new Set(Object.values(SemanticRole));
  for (const [index, model] of (models || []).entries()) {
    const at = model?.id || `catalog[${index}]`;
    if (!model || typeof model !== "object") { issues.push(`${at}: entry must be an object`); continue; }
    if (!model.id || typeof model.id !== "string") issues.push(`${at}: id is required`);
    else if (ids.has(model.id)) issues.push(`${at}: duplicate id`);
    else ids.add(model.id);
    if (!roles.has(model.role)) issues.push(`${at}: unknown role ${model.role}`);
    for (const field of ["languages", "callNames", "qualifiedNames", "moduleNames", "receiverTypes", "taintArguments"]) {
      if (!Array.isArray(model[field])) issues.push(`${at}: ${field} must be an array`);
    }
    if (model.syntaxReceiverNames !== undefined && !Array.isArray(model.syntaxReceiverNames)) {
      issues.push(`${at}: syntaxReceiverNames must be an array when declared`);
    }
    if (model.verifiedSyntaxReceiverNames !== undefined && !Array.isArray(model.verifiedSyntaxReceiverNames)) {
      issues.push(`${at}: verifiedSyntaxReceiverNames must be an array when declared`);
    }
    if (model.regexLiteralReceiver !== undefined && typeof model.regexLiteralReceiver !== "boolean") {
      issues.push(`${at}: regexLiteralReceiver must be a boolean when declared`);
    }
    if (model.requireAnchoredWhitelist !== undefined && typeof model.requireAnchoredWhitelist !== "boolean") {
      issues.push(`${at}: requireAnchoredWhitelist must be a boolean when declared`);
    }
    if (Array.isArray(model.taintArguments) && model.taintArguments.some(value => !Number.isInteger(value) || value < 0)) {
      issues.push(`${at}: taintArguments must contain non-negative integers`);
    }
    if (model.role === SemanticRole.SOURCE && !model.sourceKind) issues.push(`${at}: sourceKind is required for sources`);
    if (model.role === SemanticRole.SINK && !model.sinkKind) issues.push(`${at}: sinkKind is required for sinks`);
    if (model.role === SemanticRole.GUARD && !model.guardCapabilities?.length) issues.push(`${at}: guardCapabilities are required for guards`);
    if (model.role === SemanticRole.GUARD && !model.applicableSinkKinds?.length) issues.push(`${at}: applicableSinkKinds are required for guards`);
    if (model.applicableSinkKinds?.some(value => !Object.values(SinkKind).includes(value))) {
      issues.push(`${at}: applicableSinkKinds contains an unknown sink kind`);
    }
  }
  return issues;
}

function resolveStructuralSemantic(factKind, language) {
  return STRUCTURAL_SEMANTIC_MODELS.find(model => model.factKind === factKind && model.languages.includes(language));
}

function compileCatalogPatterns(language, options = {}) {
  return compilePatterns(options.models || SEMANTIC_MODELS, language, options);
}

const catalogIssues = validateSemanticCatalog();
if (catalogIssues.length) throw new Error(`Invalid TraceGuard semantic catalog: ${catalogIssues.join("; ")}`);

// Conventional request-object root names used to infer that a parameter bound
// from a call-site argument carries request-controlled data. Signals already
// cover exact source shapes (`req.query`, `$_GET`); these roots cover helper
// functions that receive the whole request object and read fields inside.
const CONVENTIONAL_REQUEST_ROOTS = Object.freeze(new Set([
  "req", "request", "_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "ctx", "context",
]));

module.exports = {
  CATALOG_SCHEMA_VERSION,
  COLLECTION_SEMANTIC_MODELS,
  CONVENTIONAL_REQUEST_ROOTS,
  SEMANTIC_MODELS,
  STRUCTURAL_SEMANTIC_MODELS,
  SemanticRole,
  compileCatalogPatterns,
  resolveSemanticCall,
  resolveStructuralSemantic,
  validateSemanticCatalog,
};
