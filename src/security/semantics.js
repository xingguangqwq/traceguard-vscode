"use strict";

const SourceKind = Object.freeze({
  HTTP_INPUT: "HTTP_INPUT",
  PROCESS_INPUT: "PROCESS_INPUT",
  FILE_UPLOAD: "FILE_UPLOAD",
  EXTERNAL_INPUT: "EXTERNAL_INPUT",
  SELECTED_SYMBOL: "SELECTED_SYMBOL",
});

const SourceExposure = Object.freeze({
  REMOTE: "remote",
  LOCAL: "local",
  UNKNOWN: "unknown",
  REVIEWER: "reviewer",
});

const SinkKind = Object.freeze({
  SQL_QUERY: "SQL_QUERY",
  COMMAND_EXEC: "COMMAND_EXEC",
  DYNAMIC_EXEC: "DYNAMIC_EXEC",
  FILE_ACCESS: "FILE_ACCESS",
  HTTP_REQUEST: "HTTP_REQUEST",
  REDIRECT: "REDIRECT",
  RESPONSE_OUTPUT: "RESPONSE_OUTPUT",
  DESERIALIZATION: "DESERIALIZATION",
  DIRECTORY_LOOKUP: "DIRECTORY_LOOKUP",
  SENSITIVE_OPERATION: "SENSITIVE_OPERATION",
});

const GuardCapability = Object.freeze({
  INPUT_VALIDATION: "INPUT_VALIDATION",
  WHITELIST_PATTERN: "WHITELIST_PATTERN",
  VALIDATE_SCHEME: "VALIDATE_SCHEME",
  VALIDATE_IP: "VALIDATE_IP",
  BLOCK_PRIVATE_IP: "BLOCK_PRIVATE_IP",
  URL_POLICY: "URL_POLICY",
  PATH_CANONICALIZATION: "PATH_CANONICALIZATION",
  PATH_CONFINEMENT: "PATH_CONFINEMENT",
  OUTPUT_ENCODING: "OUTPUT_ENCODING",
  SQL_PARAMETERIZATION: "SQL_PARAMETERIZATION",
  SHELL_ESCAPE: "SHELL_ESCAPE",
  AUTHENTICATION: "AUTHENTICATION",
  AUTHORIZATION: "AUTHORIZATION",
  DESERIALIZATION_ALLOWLIST: "DESERIALIZATION_ALLOWLIST",
  NUMERIC_ONLY: "NUMERIC_ONLY",
  FIXED_COLLECTION: "FIXED_COLLECTION",
  ALL_ELEMENTS: "ALL_ELEMENTS",
  SAFE_JOIN: "SAFE_JOIN",
});

const SINK_BY_CATEGORY = Object.freeze({
  database: SinkKind.SQL_QUERY,
  command: SinkKind.COMMAND_EXEC,
  expression: SinkKind.DYNAMIC_EXEC,
  file: SinkKind.FILE_ACCESS,
  network: SinkKind.HTTP_REQUEST,
  redirect: SinkKind.REDIRECT,
  output: SinkKind.RESPONSE_OUTPUT,
  deserialization: SinkKind.DESERIALIZATION,
  directory: SinkKind.DIRECTORY_LOOKUP,
});

const GUARD_SINK_KINDS = Object.freeze({
  [GuardCapability.VALIDATE_SCHEME]: [SinkKind.HTTP_REQUEST, SinkKind.REDIRECT],
  [GuardCapability.VALIDATE_IP]: [SinkKind.HTTP_REQUEST],
  [GuardCapability.BLOCK_PRIVATE_IP]: [SinkKind.HTTP_REQUEST],
  [GuardCapability.URL_POLICY]: [SinkKind.HTTP_REQUEST, SinkKind.REDIRECT],
  [GuardCapability.PATH_CANONICALIZATION]: [SinkKind.FILE_ACCESS],
  [GuardCapability.PATH_CONFINEMENT]: [SinkKind.FILE_ACCESS],
  [GuardCapability.OUTPUT_ENCODING]: [SinkKind.RESPONSE_OUTPUT],
  [GuardCapability.SQL_PARAMETERIZATION]: [SinkKind.SQL_QUERY],
  [GuardCapability.SHELL_ESCAPE]: [SinkKind.COMMAND_EXEC],
  [GuardCapability.DESERIALIZATION_ALLOWLIST]: [SinkKind.DESERIALIZATION],
  [GuardCapability.NUMERIC_ONLY]: [SinkKind.COMMAND_EXEC, SinkKind.SQL_QUERY],
  [GuardCapability.SAFE_JOIN]: [SinkKind.COMMAND_EXEC],
  [GuardCapability.WHITELIST_PATTERN]: [SinkKind.COMMAND_EXEC, SinkKind.SQL_QUERY, SinkKind.FILE_ACCESS, SinkKind.DYNAMIC_EXEC],
});

const OUTPUT_SCOPED_GUARDS = new Set([
  GuardCapability.OUTPUT_ENCODING,
  GuardCapability.PATH_CANONICALIZATION,
  GuardCapability.SHELL_ESCAPE,
  GuardCapability.NUMERIC_ONLY,
  GuardCapability.SAFE_JOIN,
]);

const RECEIVER_SCOPED_GUARDS = new Set([GuardCapability.SQL_PARAMETERIZATION]);
const TRUSTED_OPERAND_GUARDS = new Set([GuardCapability.PATH_CONFINEMENT]);
const SEMANTIC_PROOF_GUARDS = new Set([
  GuardCapability.URL_POLICY,
  GuardCapability.OUTPUT_ENCODING,
  GuardCapability.SQL_PARAMETERIZATION,
  GuardCapability.SHELL_ESCAPE,
  GuardCapability.DESERIALIZATION_ALLOWLIST,
  GuardCapability.NUMERIC_ONLY,
  GuardCapability.SAFE_JOIN,
]);
const INDIRECT_SINK_GUARDS = new Set([GuardCapability.SQL_PARAMETERIZATION]);

function sourceKindFor(signal) {
  const text = `${signal?.label || ""} ${signal?.code || ""}`;
  if (/HTTP|request|Framework-bound|Cookie|Header|route|query|form/i.test(text)) return SourceKind.HTTP_INPUT;
  if (/argv|console|process|event input|environment|Getenv/i.test(text)) return SourceKind.PROCESS_INPUT;
  if (/upload|files?/i.test(text)) return SourceKind.FILE_UPLOAD;
  return SourceKind.EXTERNAL_INPUT;
}

function sourceExposureForKind(sourceKind) {
  if ([SourceKind.HTTP_INPUT, SourceKind.FILE_UPLOAD].includes(sourceKind)) return SourceExposure.REMOTE;
  if (sourceKind === SourceKind.PROCESS_INPUT) return SourceExposure.LOCAL;
  if (sourceKind === SourceKind.SELECTED_SYMBOL) return SourceExposure.REVIEWER;
  return SourceExposure.UNKNOWN;
}

function sinkKindFor(signal) {
  return SINK_BY_CATEGORY[signal?.category] || SinkKind.SENSITIVE_OPERATION;
}

function guardCapabilitiesFor(signal) {
  const text = `${signal?.label || ""} ${signal?.code || ""}`;
  const capabilities = [];
  if (signal?.kind === "auth") {
    capabilities.push(/authentication|identity|session|current.?user|claims/i.test(text) ? GuardCapability.AUTHENTICATION : GuardCapability.AUTHORIZATION);
  }
  if (/prepared|parameterized|bindParam|bindValue|prepareStatement/i.test(text)) capabilities.push(GuardCapability.SQL_PARAMETERIZATION);
  if (/shell argument|escapeshellarg|escapeshellcmd/i.test(text)) capabilities.push(GuardCapability.SHELL_ESCAPE);
  if (/canonical|realpath|normalize|resolve|safe filename|basename|GetFullPath|filepath\.(?:Clean|Abs|Base)/i.test(text)) capabilities.push(GuardCapability.PATH_CANONICALIZATION);
  if (/path confinement|within (?:the )?(?:root|base|directory)|startsWith\s*\(|commonpath|relative\([^)]*\)(?:\s*!==?\s*\.\.|\.startsWith)/i.test(text)) capabilities.push(GuardCapability.PATH_CONFINEMENT);
  if (/deseriali[sz].*(?:allowlist|binder|known type)|allowed (?:class|type)/i.test(text)) capabilities.push(GuardCapability.DESERIALIZATION_ALLOWLIST);
  if (/output encoding|HTML sanit|htmlspecialchars|htmlentities|escapeHtml|EscapeString|Encode\.forHtml/i.test(text)) capabilities.push(GuardCapability.OUTPUT_ENCODING);
  if (/scheme|protocol/i.test(text)) capabilities.push(GuardCapability.VALIDATE_SCHEME);
  if (/private (?:IP|network)|loopback|link-local|127\.0\.0\.1|169\.254/i.test(text)) capabilities.push(GuardCapability.BLOCK_PRIVATE_IP);
  if (/validate.?ip|FILTER_VALIDATE_IP|ipaddress\.ip_address/i.test(text)) capabilities.push(GuardCapability.VALIDATE_IP);
  if (/URL policy|allowed host|allowlist|hostname/i.test(text)) capabilities.push(GuardCapability.URL_POLICY);
  if (signal?.kind === "sanitizer" && !capabilities.length) capabilities.push(GuardCapability.INPUT_VALIDATION);
  return [...new Set(capabilities)];
}

function semanticForSignal(signal) {
  if (signal?.semantic) return { ...signal.semantic, label: signal.semantic.label || signal.label };
  if (signal.kind === "source") {
    const sourceKind = sourceKindFor(signal);
    return { sourceKind, exposure: sourceExposureForKind(sourceKind), label: signal.label };
  }
  if (signal.kind === "sink") return { sinkKind: sinkKindFor(signal), category: signal.category, label: signal.label };
  if (signal.kind === "auth" || signal.kind === "sanitizer") return { guardCapabilities: guardCapabilitiesFor(signal), label: signal.label };
  return { label: signal.label };
}

function guardAssociation(capabilities = [], options = {}) {
  const declaredSinkKinds = Array.isArray(options.applicableSinkKinds) && options.applicableSinkKinds.length
    ? [...new Set(options.applicableSinkKinds)]
    : undefined;
  return {
    applicableSinkKinds: declaredSinkKinds || [...new Set(capabilities.flatMap(capability => GUARD_SINK_KINDS[capability] || []))],
    outputScoped: capabilities.some(capability => OUTPUT_SCOPED_GUARDS.has(capability)),
    receiverScoped: capabilities.some(capability => RECEIVER_SCOPED_GUARDS.has(capability)),
    requiresTrustedOperand: capabilities.some(capability => TRUSTED_OPERAND_GUARDS.has(capability)),
    capabilityScopes: Object.fromEntries(capabilities.map(capability => [capability, {
      applicableSinkKinds: declaredSinkKinds || GUARD_SINK_KINDS[capability] || [],
      outputScoped: OUTPUT_SCOPED_GUARDS.has(capability),
      receiverScoped: RECEIVER_SCOPED_GUARDS.has(capability),
      requiresTrustedOperand: TRUSTED_OPERAND_GUARDS.has(capability),
      requiresSemanticProof: SEMANTIC_PROOF_GUARDS.has(capability),
      forbidsDirectSinkInput: INDIRECT_SINK_GUARDS.has(capability),
    }])),
  };
}

function guardCapabilityAppliesToSink(capability, sinkKind, applicableSinkKinds) {
  const declared = Array.isArray(applicableSinkKinds) && applicableSinkKinds.length
    ? applicableSinkKinds
    : GUARD_SINK_KINDS[capability] || [];
  return !declared.length || declared.includes(sinkKind);
}

module.exports = {
  GuardCapability,
  SinkKind,
  SourceExposure,
  SourceKind,
  guardCapabilitiesFor,
  guardCapabilityAppliesToSink,
  guardAssociation,
  semanticForSignal,
  sinkKindFor,
  sourceExposureForKind,
  sourceKindFor,
};
