"use strict";

const { GuardCapability, SinkKind, SourceKind } = require("./semantics");

const SemanticRole = Object.freeze({
  SOURCE: "source",
  SINK: "sink",
  PROPAGATOR: "propagator",
  GUARD: "guard",
});

const SEMANTIC_MODELS = Object.freeze([
  sourceModel({
    id: "javascript.deno.environment",
    languages: ["javascript", "typescript"],
    moduleNames: [],
    qualifiedNames: ["Deno.env.get"],
    receiverTypes: ["Deno.Env"],
    callNames: ["get"],
    taintArguments: [],
    sourceKind: SourceKind.PROCESS_INPUT,
    callForms: ["global-member"],
  }),
  sinkModel({
    id: "node.child_process.command",
    languages: ["javascript", "typescript"],
    moduleNames: ["child_process", "node:child_process"],
    qualifiedNames: ["child_process.exec", "child_process.execSync"],
    callNames: ["exec", "execSync"],
    taintArguments: [0],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["named-import", "namespace-import", "default-import-member", "require-destructure", "require-member"],
  }),
  sinkModel({
    id: "node.child_process.spawn",
    languages: ["javascript", "typescript"],
    moduleNames: ["child_process", "node:child_process"],
    qualifiedNames: ["child_process.spawn", "child_process.spawnSync", "child_process.fork"],
    callNames: ["spawn", "spawnSync", "fork"],
    taintArguments: [0, 1],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["named-import", "namespace-import", "default-import-member", "require-destructure", "require-member"],
  }),
  sinkModel({
    id: "node.fs.file-access",
    languages: ["javascript", "typescript"],
    moduleNames: ["fs", "node:fs", "fs/promises", "node:fs/promises"],
    qualifiedNames: ["fs.readFile", "fs.writeFile", "fs.appendFile", "fs.unlink", "fs.createReadStream", "fs.createWriteStream"],
    callNames: ["readFile", "writeFile", "appendFile", "unlink", "createReadStream", "createWriteStream"],
    taintArguments: [0],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["named-import", "namespace-import", "default-import-member", "require-destructure", "require-member"],
  }),
  sinkModel({
    id: "node.fs.path-transfer",
    languages: ["javascript", "typescript"],
    moduleNames: ["fs", "node:fs", "fs/promises", "node:fs/promises"],
    qualifiedNames: ["fs.rename", "fs.copyFile"],
    callNames: ["rename", "copyFile"],
    taintArguments: [0, 1],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["named-import", "namespace-import", "default-import-member", "require-destructure", "require-member"],
  }),
  sinkModel({
    id: "web.fetch.request",
    languages: ["javascript", "typescript"],
    moduleNames: [],
    qualifiedNames: ["global.fetch", "fetch"],
    callNames: ["fetch"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["global"],
    global: true,
  }),
  propagatorModel({
    id: "javascript.global.string-conversion",
    languages: ["javascript", "typescript"],
    moduleNames: [],
    qualifiedNames: ["global.String", "global.decodeURIComponent", "global.encodeURIComponent"],
    callNames: ["String", "decodeURIComponent", "encodeURIComponent"],
    taintArguments: [0],
    callForms: ["global"],
    global: true,
  }),
  propagatorModel({
    id: "node.path.value-propagation",
    languages: ["javascript", "typescript"],
    moduleNames: ["path", "node:path", "path/posix", "path/win32"],
    qualifiedNames: ["path.join", "path.resolve", "path.normalize", "path.basename"],
    callNames: ["join", "resolve", "normalize", "basename"],
    taintArguments: [],
    taintRestFrom: 0,
    callForms: ["named-import", "namespace-import", "default-import-member", "require-member"],
  }),
  sinkModel({
    id: "java.lang.Runtime.exec",
    languages: ["java"],
    moduleNames: ["java.lang"],
    qualifiedNames: ["java.lang.Runtime.exec", "Runtime.exec"],
    receiverTypes: ["java.lang.Runtime", "Runtime"],
    callNames: ["exec"],
    taintArguments: [0],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "java.lang.ProcessBuilder.command",
    languages: ["java"],
    moduleNames: ["java.lang"],
    qualifiedNames: ["java.lang.ProcessBuilder", "ProcessBuilder"],
    receiverTypes: ["java.lang.ProcessBuilder", "ProcessBuilder"],
    callNames: ["ProcessBuilder", "command"],
    taintArguments: [],
    taintRestFrom: 0,
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["constructor", "instance-method"],
  }),
  sinkModel({
    id: "python.pickle.deserialize",
    languages: ["python"],
    moduleNames: ["pickle", "_pickle", "yaml"],
    qualifiedNames: ["pickle.loads", "pickle.load", "_pickle.loads", "yaml.load", "yaml.unsafe_load"],
    callNames: ["loads", "load", "unsafe_load"],
    taintArguments: [0],
    sinkKind: SinkKind.DESERIALIZATION,
    category: "deserialization",
    callForms: ["module-function"],
  }),
  sinkModel({
    id: "java.sql.Statement.executeQuery",
    languages: ["java"],
    moduleNames: ["java.sql"],
    qualifiedNames: ["java.sql.Statement.executeQuery", "Statement.executeQuery"],
    receiverTypes: ["java.sql.Statement", "Statement"],
    callNames: ["executeQuery", "executeUpdate", "execute"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "java.persistence.EntityManager.dynamic-query",
    languages: ["java"],
    moduleNames: ["jakarta.persistence", "javax.persistence"],
    qualifiedNames: ["jakarta.persistence.EntityManager.createQuery", "jakarta.persistence.EntityManager.createNativeQuery", "javax.persistence.EntityManager.createQuery", "javax.persistence.EntityManager.createNativeQuery", "EntityManager.createQuery", "EntityManager.createNativeQuery"],
    receiverTypes: ["jakarta.persistence.EntityManager", "javax.persistence.EntityManager", "EntityManager"],
    callNames: ["createQuery", "createNativeQuery"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "spring.jdbc.JdbcTemplate.dynamic-query",
    languages: ["java"],
    moduleNames: ["org.springframework.jdbc.core"],
    qualifiedNames: ["org.springframework.jdbc.core.JdbcTemplate.query", "org.springframework.jdbc.core.JdbcTemplate.queryForObject", "org.springframework.jdbc.core.JdbcTemplate.update", "org.springframework.jdbc.core.JdbcTemplate.execute", "JdbcTemplate.query", "JdbcTemplate.queryForObject", "JdbcTemplate.update", "JdbcTemplate.execute"],
    receiverTypes: ["org.springframework.jdbc.core.JdbcTemplate", "JdbcTemplate", "NamedParameterJdbcTemplate"],
    callNames: ["query", "queryForObject", "queryForList", "update", "batchUpdate", "execute"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "spring.web.RestTemplate.request",
    languages: ["java"],
    moduleNames: ["org.springframework.web.client"],
    qualifiedNames: ["RestTemplate.getForObject", "RestTemplate.getForEntity", "RestTemplate.postForObject", "RestTemplate.exchange", "RestTemplate.execute"],
    receiverTypes: ["org.springframework.web.client.RestTemplate", "RestTemplate"],
    callNames: ["getForObject", "getForEntity", "postForObject", "postForEntity", "exchange", "execute"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "spring.web.WebClient.uri",
    languages: ["java"],
    moduleNames: ["org.springframework.web.reactive.function.client"],
    qualifiedNames: ["WebClient.uri", "RequestHeadersUriSpec.uri", "RequestBodyUriSpec.uri"],
    receiverTypes: ["WebClient", "RequestHeadersUriSpec", "RequestBodyUriSpec", "UriSpec"],
    callNames: ["uri"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "go.os_exec.Command",
    languages: ["go"],
    moduleNames: ["os/exec"],
    qualifiedNames: ["os/exec.Command", "exec.Command"],
    callNames: ["Command"],
    taintArguments: [],
    taintRestFrom: 0,
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["package-function"],
  }),
  sinkModel({
    id: "go.os_exec.CommandContext",
    languages: ["go"],
    moduleNames: ["os/exec"],
    qualifiedNames: ["os/exec.CommandContext", "exec.CommandContext"],
    callNames: ["CommandContext"],
    taintArguments: [],
    taintRestFrom: 1,
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["package-function"],
  }),
  sinkModel({
    id: "dotnet.System.Diagnostics.Process.Start",
    languages: ["csharp"],
    moduleNames: ["System.Diagnostics"],
    qualifiedNames: ["System.Diagnostics.Process.Start", "Process.Start"],
    receiverTypes: ["System.Diagnostics.Process", "Process"],
    callNames: ["Start"],
    taintArguments: [0, 1],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["static-method"],
  }),
  guardModel({
    id: "javascript.escape_html.output",
    languages: ["javascript", "typescript"],
    moduleNames: ["escape-html", "html-escaper"],
    qualifiedNames: ["escape-html.escapeHtml", "html-escaper.escape", "html-escaper.escapeHtml"],
    callNames: ["escapeHtml", "escape"],
    taintArguments: [0],
    guardCapabilities: [GuardCapability.OUTPUT_ENCODING],
    applicableSinkKinds: [SinkKind.RESPONSE_OUTPUT],
    callForms: ["default-import", "named-import", "require"],
  }),
  guardModel({
    id: "java.sql.PreparedStatement.bind",
    languages: ["java"],
    moduleNames: ["java.sql"],
    qualifiedNames: ["java.sql.PreparedStatement.setString", "PreparedStatement.setString"],
    receiverTypes: ["java.sql.PreparedStatement", "PreparedStatement"],
    callNames: ["setString", "setInt", "setLong", "setObject"],
    taintArguments: [1],
    guardCapabilities: [GuardCapability.SQL_PARAMETERIZATION],
    applicableSinkKinds: [SinkKind.SQL_QUERY],
    receiverScoped: true,
    callForms: ["instance-method"],
  }),
]);

function sinkModel(input) {
  return Object.freeze({
    role: SemanticRole.SINK,
    returnsTaint: false,
    receiverTypes: [],
    ...input,
  });
}

function sourceModel(input) {
  return Object.freeze({
    role: SemanticRole.SOURCE,
    returnsTaint: true,
    receiverTypes: [],
    ...input,
  });
}

function guardModel(input) {
  return Object.freeze({
    role: SemanticRole.GUARD,
    returnsTaint: false,
    receiverTypes: [],
    ...input,
  });
}

function propagatorModel(input) {
  return Object.freeze({
    role: SemanticRole.PROPAGATOR,
    returnsTaint: true,
    receiverTypes: [],
    ...input,
  });
}

function resolveSemanticCall(language, call = {}, customModels = []) {
  const identity = call.symbol || {};
  const semanticName = identity.exportName || call.function;
  const registry = [...SEMANTIC_MODELS, ...(Array.isArray(customModels) ? customModels.filter(validCustomModel) : [])];
  const candidates = registry.filter(model =>
    model.languages.includes(language) && model.callNames.some(name => canonical(name) === canonical(semanticName)));
  if (!candidates.length) return { status: "none" };

  if (identity.shadowed && !candidates.some(model => model.custom && model.customUnqualified)) return {
    status: "rejected",
    reason: "The call name resolves to a local declaration that shadows a modeled security API.",
    candidates: candidates.map(model => model.id),
  };

  for (const model of candidates) {
    if (model.custom && model.customUnqualified && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "syntax", identity);
    }
    if (model.global && identity.kind === "global" && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "verified", identity);
    }
    if (identity.moduleName && moduleMatches(model, identity.moduleName) && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "verified", identity);
    }
    if (identity.qualifiedName && qualifiedMatches(model, identity.qualifiedName)) {
      return resolution(model, identity.verified ? "verified" : "syntax", identity);
    }
    if (identity.receiverType && receiverMatches(model, identity.receiverType)) {
      return resolution(model, identity.verified ? "verified" : "syntax", identity);
    }
    if (call.receiver && syntaxReceiverMatches(model, call.receiver)) {
      return resolution(model, "syntax", { ...identity, qualifiedName: `${call.receiver}.${semanticName}` });
    }
  }

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

  if (["javascript", "typescript"].includes(language) && call.receiver) return {
    status: "rejected",
    reason: "A member-call name matched, but TypeScript could not prove the required module or receiver identity.",
    candidates: candidates.map(model => model.id),
  };

  return {
    status: "candidate",
    reason: "A name pattern matched, but module and receiver identity could not be proven.",
    candidates: candidates.map(model => model.id),
  };
}

function validCustomModel(model) {
  return Boolean(model && model.custom && Array.isArray(model.languages) && Array.isArray(model.callNames) && model.role);
}

function resolution(model, status, identity) {
  return {
    status,
    model,
    identity,
    certainty: status === "verified" ? "high" : "medium",
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

function syntaxReceiverMatches(model, value) {
  const actual = canonicalQualified(value);
  const receiverNames = [
    ...model.moduleNames.flatMap(moduleName => {
      const normalized = normalizeModule(moduleName);
      return [normalized, normalized.split("/").at(-1)];
    }),
    ...model.receiverTypes.map(type => canonicalQualified(type)),
    ...model.qualifiedNames.map(name => canonicalQualified(name).split(".").slice(0, -1).join(".")),
  ].filter(Boolean);
  return receiverNames.some(expected => actual === expected || actual.endsWith(`.${expected}`) || actual.startsWith(`${expected}.`));
}

function normalizeModule(value) {
  return String(value || "").replace(/^node:/, "").replaceAll("\\", "/").toLowerCase();
}

function canonicalQualified(value) {
  return String(value || "").replace(/\s+/g, "").replace(/::|->/g, ".").toLowerCase();
}

function canonical(value) {
  return String(value || "").replace(/[^A-Za-z0-9_$]/g, "").toLowerCase();
}

module.exports = {
  SEMANTIC_MODELS,
  SemanticRole,
  resolveSemanticCall,
};
