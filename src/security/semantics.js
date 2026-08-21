"use strict";

const SourceKind = Object.freeze({
  HTTP_INPUT: "HTTP_INPUT",
  PROCESS_INPUT: "PROCESS_INPUT",
  FILE_UPLOAD: "FILE_UPLOAD",
  EXTERNAL_INPUT: "EXTERNAL_INPUT",
  SELECTED_SYMBOL: "SELECTED_SYMBOL",
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
  VALIDATE_SCHEME: "VALIDATE_SCHEME",
  VALIDATE_IP: "VALIDATE_IP",
  BLOCK_PRIVATE_IP: "BLOCK_PRIVATE_IP",
  URL_POLICY: "URL_POLICY",
  PATH_CONFINEMENT: "PATH_CONFINEMENT",
  OUTPUT_ENCODING: "OUTPUT_ENCODING",
  SQL_PARAMETERIZATION: "SQL_PARAMETERIZATION",
  SHELL_ESCAPE: "SHELL_ESCAPE",
  AUTHENTICATION: "AUTHENTICATION",
  AUTHORIZATION: "AUTHORIZATION",
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

function sourceKindFor(signal) {
  const text = `${signal?.label || ""} ${signal?.code || ""}`;
  if (/HTTP|request|Framework-bound|Cookie|Header|route|query|form/i.test(text)) return SourceKind.HTTP_INPUT;
  if (/argv|console|process|event input|environment|Getenv/i.test(text)) return SourceKind.PROCESS_INPUT;
  if (/upload|files?/i.test(text)) return SourceKind.FILE_UPLOAD;
  return SourceKind.EXTERNAL_INPUT;
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
  if (/canonical|realpath|normalize|safe filename|GetFullPath|filepath\.(?:Clean|Abs|Base)/i.test(text)) capabilities.push(GuardCapability.PATH_CONFINEMENT);
  if (/output encoding|HTML sanit|htmlspecialchars|htmlentities|escapeHtml|EscapeString|Encode\.forHtml/i.test(text)) capabilities.push(GuardCapability.OUTPUT_ENCODING);
  if (/scheme|protocol/i.test(text)) capabilities.push(GuardCapability.VALIDATE_SCHEME);
  if (/private (?:IP|network)|loopback|link-local|127\.0\.0\.1|169\.254/i.test(text)) capabilities.push(GuardCapability.BLOCK_PRIVATE_IP);
  if (/validate.?ip|FILTER_VALIDATE_IP|ipaddress\.ip_address/i.test(text)) capabilities.push(GuardCapability.VALIDATE_IP);
  if (/URL policy|allowed host|allowlist|hostname/i.test(text)) capabilities.push(GuardCapability.URL_POLICY);
  if (signal?.kind === "sanitizer" && !capabilities.length) capabilities.push(GuardCapability.INPUT_VALIDATION);
  return [...new Set(capabilities)];
}

function semanticForSignal(signal) {
  if (signal.kind === "source") return { sourceKind: sourceKindFor(signal), label: signal.label };
  if (signal.kind === "sink") return { sinkKind: sinkKindFor(signal), category: signal.category, label: signal.label };
  if (signal.kind === "auth" || signal.kind === "sanitizer") return { guardCapabilities: guardCapabilitiesFor(signal), label: signal.label };
  return { label: signal.label };
}

module.exports = {
  GuardCapability,
  SinkKind,
  SourceKind,
  guardCapabilitiesFor,
  semanticForSignal,
  sinkKindFor,
  sourceKindFor,
};
