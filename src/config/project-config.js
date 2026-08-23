"use strict";

const { stableHash } = require("../identity");
const { GuardCapability, SinkKind, SourceKind, guardAssociation } = require("../security/semantics");
const { SemanticRole } = require("../security/semantic-models");

const PROJECT_CONFIG_FILENAME = ".traceguard.json";
const PROJECT_CONFIG_VERSION = 1;
const MAX_PROJECT_CONFIG_BYTES = 256 * 1024;
const SUPPORTED_LANGUAGES = new Set(["javascript", "typescript", "java", "python", "php", "csharp", "go"]);
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const SOURCE_KINDS = new Set([
  SourceKind.HTTP_INPUT,
  SourceKind.PROCESS_INPUT,
  SourceKind.FILE_UPLOAD,
  SourceKind.EXTERNAL_INPUT,
]);
const SINK_KINDS = new Set(Object.values(SinkKind));
const GUARD_CAPABILITIES = new Set(Object.values(GuardCapability));
const TOP_LEVEL_KEYS = new Set([
  "$schema", "version", "sources", "sinks", "sanitizers", "propagators", "wrappers",
  "rules", "excludePaths", "severityOverrides",
]);
const MODEL_KEYS = new Set([
  "id", "language", "languages", "function", "module", "qualifiedName", "receiverType",
  "arguments", "restFrom", "returnsTaint", "kind", "capability", "applicableSinks",
  "callForms", "role",
]);

function parseProjectConfigurationText(text, source = PROJECT_CONFIG_FILENAME) {
  if (Buffer.byteLength(String(text || ""), "utf8") > MAX_PROJECT_CONFIG_BYTES) {
    return invalid([issue(source, "$", `Configuration exceeds the ${MAX_PROJECT_CONFIG_BYTES} byte limit.`)]);
  }
  let value;
  try {
    value = JSON.parse(String(text || ""));
  } catch (error) {
    return invalid([jsonIssue(source, text, error)]);
  }
  const issues = [];
  if (!plainObject(value)) return invalid([issue(source, "$", "Configuration root must be a JSON object.")]);
  for (const key of Object.keys(value)) {
    if (!TOP_LEVEL_KEYS.has(key)) issues.push(issue(source, `$.${key}`, `Unknown configuration property “${key}”.`, "warning"));
  }
  if (value.version !== undefined && value.version !== PROJECT_CONFIG_VERSION) {
    issues.push(issue(source, "$.version", `Unsupported configuration version ${JSON.stringify(value.version)}; expected ${PROJECT_CONFIG_VERSION}.`));
  }

  const semanticModels = [];
  compileModelList(value.sources, "sources", SemanticRole.SOURCE, source, issues, semanticModels);
  compileModelList(value.sinks, "sinks", SemanticRole.SINK, source, issues, semanticModels);
  compileModelList(value.sanitizers, "sanitizers", SemanticRole.GUARD, source, issues, semanticModels);
  compileModelList(value.propagators, "propagators", SemanticRole.PROPAGATOR, source, issues, semanticModels);
  compileModelList(value.wrappers, "wrappers", undefined, source, issues, semanticModels);
  const rules = compileRules(value.rules, value.severityOverrides, source, issues);
  const excludePaths = compileExcludePaths(value.excludePaths, source, issues);
  if (issues.some(item => item.severity === "error")) return invalid(issues);
  const config = finalizeConfiguration({
    version: PROJECT_CONFIG_VERSION,
    semanticModels,
    rules,
    excludePaths,
    sources: [source],
  });
  return { valid: true, config, issues };
}

function compileModelList(value, property, defaultRole, source, issues, output) {
  if (value === undefined) return;
  if (!Array.isArray(value)) {
    issues.push(issue(source, `$.${property}`, `${property} must be an array.`));
    return;
  }
  if (value.length > 200) issues.push(issue(source, `$.${property}`, `${property} may contain at most 200 models.`));
  value.slice(0, 200).forEach((input, index) => {
    const configPath = `$.${property}[${index}]`;
    if (!plainObject(input)) {
      issues.push(issue(source, configPath, "Semantic model must be an object."));
      return;
    }
    for (const key of Object.keys(input)) {
      if (!MODEL_KEYS.has(key)) issues.push(issue(source, `${configPath}.${key}`, `Unknown semantic-model property “${key}”.`, "warning"));
    }
    const role = wrapperRole(input.role, defaultRole);
    if (!role) {
      issues.push(issue(source, `${configPath}.role`, "Wrapper role must be source, sink, sanitizer/guard or propagator."));
      return;
    }
    const languages = normalizeLanguages(input, source, configPath, issues);
    const functionName = boundedString(input.function, 300);
    if (!functionName) issues.push(issue(source, `${configPath}.function`, "function is required and must be a non-empty string."));
    const moduleName = optionalString(input.module, 500, source, `${configPath}.module`, issues);
    const receiverType = optionalString(input.receiverType, 500, source, `${configPath}.receiverType`, issues);
    const qualifiedName = optionalString(input.qualifiedName, 500, source, `${configPath}.qualifiedName`, issues);
    const taintArguments = integerArray(input.arguments, `${configPath}.arguments`, source, issues);
    const taintRestFrom = optionalIndex(input.restFrom, `${configPath}.restFrom`, source, issues);
    const callForms = stringArray(input.callForms, `${configPath}.callForms`, source, issues, 20, 80);
    if (!languages.length || !functionName) return;

    const model = {
      id: customModelId(input.id, source, property, index, functionName),
      custom: true,
      configSource: source,
      role,
      languages,
      moduleNames: moduleName ? [moduleName] : [],
      qualifiedNames: [qualifiedName || (moduleName ? `${moduleName}.${functionName}` : receiverType ? `${receiverType}.${functionName}` : functionName)],
      receiverTypes: receiverType ? [receiverType] : [],
      callNames: [lastCallName(functionName)],
      taintArguments: taintArguments === undefined ? defaultTaintArguments(role) : taintArguments,
      returnsTaint: input.returnsTaint === undefined ? role !== SemanticRole.SINK : Boolean(input.returnsTaint),
      callForms: callForms.length ? callForms : ["project-function", "named-import", "namespace-import", "instance-method", "static-method", "package-function"],
      customUnqualified: !moduleName && !receiverType && !qualifiedName && !/[.:#]|->/.test(functionName),
    };
    if (taintRestFrom !== undefined) model.taintRestFrom = taintRestFrom;
    if (role === SemanticRole.SOURCE) {
      model.sourceKind = enumValue(input.kind, SOURCE_KINDS, SourceKind.EXTERNAL_INPUT, source, `${configPath}.kind`, issues);
    }
    if (role === SemanticRole.SINK) {
      model.sinkKind = enumValue(input.kind, SINK_KINDS, undefined, source, `${configPath}.kind`, issues);
      model.category = sinkCategory(model.sinkKind);
      if (!model.sinkKind) return;
    }
    if (role === SemanticRole.GUARD) {
      const capabilities = Array.isArray(input.capability) ? input.capability : input.capability ? [input.capability] : [];
      model.guardCapabilities = capabilities.map((capability, capabilityIndex) =>
        enumValue(capability, GUARD_CAPABILITIES, undefined, source, `${configPath}.capability[${capabilityIndex}]`, issues)).filter(Boolean);
      if (!model.guardCapabilities.length) {
        issues.push(issue(source, `${configPath}.capability`, "Sanitizer capability is required and must be a known GuardCapability."));
        return;
      }
      const explicitSinks = enumArray(input.applicableSinks, SINK_KINDS, source, `${configPath}.applicableSinks`, issues);
      const association = guardAssociation(model.guardCapabilities);
      model.applicableSinkKinds = explicitSinks.length ? explicitSinks : association.applicableSinkKinds;
      model.receiverScoped = association.receiverScoped;
    }
    output.push(model);
  });
}

function compileRules(value, overrides, source, issues) {
  const result = {};
  if (value !== undefined && !plainObject(value)) issues.push(issue(source, "$.rules", "rules must be an object keyed by rule ID."));
  if (plainObject(value)) {
    for (const [ruleId, control] of Object.entries(value).slice(0, 200)) {
      if (!validRuleId(ruleId)) {
        issues.push(issue(source, `$.rules.${ruleId}`, "Rule ID contains unsupported characters."));
        continue;
      }
      if (typeof control === "boolean") result[ruleId] = { enabled: control };
      else if (plainObject(control)) {
        const normalized = {};
        if (control.enabled !== undefined) normalized.enabled = Boolean(control.enabled);
        if (control.severity !== undefined) normalized.severity = enumValue(control.severity, SEVERITIES, undefined, source, `$.rules.${ruleId}.severity`, issues);
        result[ruleId] = normalized;
      } else issues.push(issue(source, `$.rules.${ruleId}`, "Rule control must be a boolean or an object."));
    }
  }
  if (overrides !== undefined && !plainObject(overrides)) issues.push(issue(source, "$.severityOverrides", "severityOverrides must be an object keyed by rule ID."));
  if (plainObject(overrides)) {
    for (const [ruleId, severity] of Object.entries(overrides).slice(0, 200)) {
      if (!validRuleId(ruleId)) {
        issues.push(issue(source, `$.severityOverrides.${ruleId}`, "Rule ID contains unsupported characters."));
        continue;
      }
      const normalized = enumValue(severity, SEVERITIES, undefined, source, `$.severityOverrides.${ruleId}`, issues);
      if (normalized) result[ruleId] = { ...(result[ruleId] || {}), severity: normalized };
    }
  }
  return result;
}

function compileExcludePaths(value, source, issues) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    issues.push(issue(source, "$.excludePaths", "excludePaths must be an array of workspace-relative glob patterns."));
    return [];
  }
  const result = [];
  for (const [index, raw] of value.slice(0, 100).entries()) {
    const pattern = boundedString(raw, 300)?.replaceAll("\\", "/").replace(/^\.\//, "");
    if (!pattern || /^[A-Za-z]:|^\/|(?:^|\/)\.\.(?:\/|$)/.test(pattern)) {
      issues.push(issue(source, `$.excludePaths[${index}]`, "Exclude pattern must be a non-empty workspace-relative glob without parent traversal."));
      continue;
    }
    result.push(pattern);
  }
  if (value.length > 100) issues.push(issue(source, "$.excludePaths", "excludePaths may contain at most 100 patterns."));
  return [...new Set(result)];
}

function mergeProjectConfigurations(configurations) {
  const values = (configurations || []).filter(Boolean);
  return finalizeConfiguration({
    version: PROJECT_CONFIG_VERSION,
    semanticModels: values.flatMap(config => config.semanticModels || []),
    rules: Object.assign({}, ...values.map(config => config.rules || {})),
    excludePaths: [...new Set(values.flatMap(config => config.excludePaths || []))],
    sources: values.flatMap(config => config.sources || []),
  });
}

function emptyProjectConfiguration() {
  return finalizeConfiguration({ version: PROJECT_CONFIG_VERSION, semanticModels: [], rules: {}, excludePaths: [], sources: [] });
}

function finalizeConfiguration(config) {
  const serializable = {
    version: config.version,
    semanticModels: config.semanticModels || [],
    rules: config.rules || {},
    excludePaths: config.excludePaths || [],
    sources: config.sources || [],
  };
  return {
    ...serializable,
    semanticFingerprint: stableHash(JSON.stringify(serializable.semanticModels)),
    ruleFingerprint: stableHash(JSON.stringify(serializable.rules)),
    excludeFingerprint: stableHash(JSON.stringify(serializable.excludePaths)),
    fingerprint: stableHash(JSON.stringify(serializable)),
  };
}

function matchesExcludedPath(relativePath, patterns = []) {
  const value = String(relativePath || "").replaceAll("\\", "/").replace(/^\.\//, "");
  return patterns.some(pattern => globRegex(pattern).test(value));
}

function combinedExcludeGlob(defaultGlob, patterns = []) {
  const normalized = patterns.map(pattern => String(pattern).replaceAll("\\", "/")).filter(Boolean);
  return normalized.length ? `{${[defaultGlob, ...normalized].join(",")}}` : defaultGlob;
}

function globRegex(pattern) {
  let output = "^";
  const value = String(pattern || "");
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "*") {
      if (value[index + 1] === "*") {
        index += 1;
        if (value[index + 1] === "/") { index += 1; output += "(?:.*/)?"; }
        else output += ".*";
      } else output += "[^/]*";
    } else if (character === "?") output += "[^/]";
    else output += character.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
  }
  return new RegExp(`${output}$`, process.platform === "win32" ? "i" : "");
}

function wrapperRole(value, fallback) {
  if (fallback) return fallback;
  return {
    source: SemanticRole.SOURCE,
    sink: SemanticRole.SINK,
    sanitizer: SemanticRole.GUARD,
    guard: SemanticRole.GUARD,
    propagator: SemanticRole.PROPAGATOR,
    wrapper: SemanticRole.PROPAGATOR,
  }[String(value || "propagator").toLowerCase()];
}

function normalizeLanguages(input, source, configPath, issues) {
  const values = Array.isArray(input.languages) ? input.languages : input.language ? [input.language] : [];
  if (!values.length) issues.push(issue(source, `${configPath}.language`, "language or languages is required."));
  return [...new Set(values.map(value => String(value).toLowerCase()).filter(value => {
    if (SUPPORTED_LANGUAGES.has(value)) return true;
    issues.push(issue(source, `${configPath}.language`, `Unsupported language “${value}”.`));
    return false;
  }))];
}

function customModelId(value, source, property, index, functionName) {
  const explicit = boundedString(value, 120);
  return explicit ? `custom.${explicit.replace(/[^A-Za-z0-9_.-]/g, "-")}` : `custom.${stableHash(`${source}:${property}:${index}:${functionName}`, 20)}`;
}

function defaultTaintArguments(role) {
  if (role === SemanticRole.SINK || role === SemanticRole.PROPAGATOR || role === SemanticRole.GUARD) return [0];
  return [];
}

function lastCallName(value) { return String(value).split(/(?:\.|::|->|#)/).filter(Boolean).at(-1); }
function sinkCategory(kind) { return { SQL_QUERY: "database", COMMAND_EXEC: "command", DYNAMIC_EXEC: "expression", FILE_ACCESS: "file", HTTP_REQUEST: "network", REDIRECT: "redirect", RESPONSE_OUTPUT: "output", DESERIALIZATION: "deserialization", DIRECTORY_LOOKUP: "directory" }[kind] || "sensitive"; }
function boundedString(value, maximum) { return typeof value === "string" && value.trim() && value.length <= maximum ? value.trim() : undefined; }
function optionalString(value, maximum, source, configPath, issues) {
  if (value === undefined) return undefined;
  const result = boundedString(value, maximum);
  if (!result) issues.push(issue(source, configPath, `Value must be a non-empty string of at most ${maximum} characters.`));
  return result;
}
function integerArray(value, configPath, source, issues) {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) { issues.push(issue(source, configPath, "arguments must be an array of zero-based parameter indexes.")); return []; }
  const result = [];
  for (const [index, item] of value.entries()) {
    if (!Number.isInteger(item) || item < 0 || item > 63) issues.push(issue(source, `${configPath}[${index}]`, "Argument index must be an integer from 0 to 63."));
    else result.push(item);
  }
  return [...new Set(result)];
}
function optionalIndex(value, configPath, source, issues) {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || value < 0 || value > 63) { issues.push(issue(source, configPath, "restFrom must be an integer from 0 to 63.")); return undefined; }
  return value;
}
function stringArray(value, configPath, source, issues, maximumItems, maximumLength) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) { issues.push(issue(source, configPath, "Value must be an array of strings.")); return []; }
  return value.slice(0, maximumItems).map((item, index) => {
    const result = boundedString(item, maximumLength);
    if (!result) issues.push(issue(source, `${configPath}[${index}]`, `Value must be a non-empty string of at most ${maximumLength} characters.`));
    return result;
  }).filter(Boolean);
}
function enumValue(value, allowed, fallback, source, configPath, issues) {
  if (value === undefined) return fallback;
  const normalized = String(value).toUpperCase();
  const match = [...allowed].find(item => String(item).toUpperCase() === normalized);
  if (!match) issues.push(issue(source, configPath, `Unsupported value “${value}”.`));
  return match;
}
function enumArray(value, allowed, source, configPath, issues) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) { issues.push(issue(source, configPath, "Value must be an array.")); return []; }
  return value.map((item, index) => enumValue(item, allowed, undefined, source, `${configPath}[${index}]`, issues)).filter(Boolean);
}
function validRuleId(value) { return /^[A-Za-z0-9_.-]{1,120}$/.test(value); }
function plainObject(value) { return Boolean(value && typeof value === "object" && !Array.isArray(value)); }
function invalid(issues) { return { valid: false, config: undefined, issues }; }
function issue(source, path, message, severity = "error", line = 1, column = 1) { return { source, path, message, severity, line, column }; }
function jsonIssue(source, text, error) {
  const position = Number(String(error?.message || "").match(/position\s+(\d+)/i)?.[1] || 0);
  const prefix = String(text || "").slice(0, position);
  const lines = prefix.split(/\r?\n/);
  return issue(source, "$", `Invalid JSON: ${String(error?.message || error)}`, "error", lines.length, lines.at(-1).length + 1);
}

module.exports = {
  MAX_PROJECT_CONFIG_BYTES,
  PROJECT_CONFIG_FILENAME,
  PROJECT_CONFIG_VERSION,
  combinedExcludeGlob,
  emptyProjectConfiguration,
  matchesExcludedPath,
  mergeProjectConfigurations,
  parseProjectConfigurationText,
};
