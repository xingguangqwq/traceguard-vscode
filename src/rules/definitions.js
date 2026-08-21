"use strict";

const { GuardCapability, SinkKind, SourceKind } = require("../security/semantics");

const EXTERNAL_SOURCES = Object.freeze([
  SourceKind.HTTP_INPUT,
  SourceKind.PROCESS_INPUT,
  SourceKind.FILE_UPLOAD,
  SourceKind.EXTERNAL_INPUT,
]);

const RULES = Object.freeze([
  {
    id: "potential-ssrf",
    title: "Potential server-side request forgery",
    sourceKinds: EXTERNAL_SOURCES,
    sinkKinds: [SinkKind.HTTP_REQUEST],
    recommendedGuards: [GuardCapability.VALIDATE_SCHEME, GuardCapability.BLOCK_PRIVATE_IP, GuardCapability.URL_POLICY],
    severity: "high",
    impact: "Server-side network access",
    cwe: "CWE-918",
  },
  {
    id: "potential-command-injection",
    title: "Potential command injection",
    sourceKinds: EXTERNAL_SOURCES,
    sinkKinds: [SinkKind.COMMAND_EXEC],
    recommendedGuards: [GuardCapability.SHELL_ESCAPE],
    severity: "critical",
    impact: "Operating-system command execution",
    cwe: "CWE-78",
  },
  {
    id: "potential-sql-injection",
    title: "Potential SQL injection",
    sourceKinds: EXTERNAL_SOURCES,
    sinkKinds: [SinkKind.SQL_QUERY],
    recommendedGuards: [GuardCapability.SQL_PARAMETERIZATION],
    sanitizerCapabilities: [GuardCapability.SQL_PARAMETERIZATION],
    severity: "high",
    impact: "Database query execution",
    cwe: "CWE-89",
  },
  {
    id: "potential-path-traversal",
    title: "Potential path traversal",
    sourceKinds: EXTERNAL_SOURCES,
    sinkKinds: [SinkKind.FILE_ACCESS],
    recommendedGuards: [GuardCapability.PATH_CONFINEMENT],
    severity: "high",
    impact: "Filesystem access",
    cwe: "CWE-22",
  },
  {
    id: "potential-open-redirect",
    title: "Potential untrusted redirect",
    sourceKinds: EXTERNAL_SOURCES,
    sinkKinds: [SinkKind.REDIRECT],
    recommendedGuards: [GuardCapability.URL_POLICY],
    severity: "medium",
    impact: "Browser navigation",
    cwe: "CWE-601",
  },
  {
    id: "potential-unsafe-output",
    title: "Potential unsafe response output",
    sourceKinds: EXTERNAL_SOURCES,
    sinkKinds: [SinkKind.RESPONSE_OUTPUT],
    recommendedGuards: [GuardCapability.OUTPUT_ENCODING],
    severity: "medium",
    impact: "Untrusted response content",
    cwe: "CWE-79",
  },
  {
    id: "potential-unsafe-deserialization",
    title: "Potential unsafe deserialization",
    sourceKinds: EXTERNAL_SOURCES,
    sinkKinds: [SinkKind.DESERIALIZATION],
    recommendedGuards: [GuardCapability.INPUT_VALIDATION],
    severity: "critical",
    impact: "Object construction from untrusted data",
    cwe: "CWE-502",
  },
  {
    id: "potential-dynamic-execution",
    title: "Potential dynamic code execution",
    sourceKinds: EXTERNAL_SOURCES,
    sinkKinds: [SinkKind.DYNAMIC_EXEC],
    recommendedGuards: [GuardCapability.INPUT_VALIDATION],
    severity: "critical",
    impact: "Dynamic expression or code execution",
    cwe: "CWE-95",
  },
]);

module.exports = { EXTERNAL_SOURCES, RULES };
