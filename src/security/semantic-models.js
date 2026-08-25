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
  sourceModel({
    id: "php.framework.request-input",
    languages: ["php"],
    moduleNames: ["Illuminate\\Http", "Symfony\\Component\\HttpFoundation"],
    qualifiedNames: ["Request.input", "Request.get", "Request.query", "Request.post", "ParameterBag.get", "InputBag.get"],
    receiverTypes: ["Request", "Illuminate\\Http\\Request", "Symfony\\Component\\HttpFoundation\\Request", "ParameterBag", "InputBag"],
    callNames: ["input", "get", "query", "post", "string", "integer", "boolean"],
    taintArguments: [],
    sourceKind: SourceKind.HTTP_INPUT,
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "php.pdo.dynamic-query",
    languages: ["php"],
    moduleNames: ["PDO"],
    qualifiedNames: ["PDO.query", "PDO.exec", "PDO.prepare"],
    receiverTypes: ["PDO"],
    callNames: ["query", "exec", "prepare"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "php.laravel.dynamic-query",
    languages: ["php"],
    moduleNames: ["Illuminate\\Support\\Facades\\DB", "Illuminate\\Database"],
    qualifiedNames: ["DB.select", "DB.statement", "DB.unprepared", "Builder.selectRaw", "Builder.whereRaw", "Builder.orderByRaw", "Builder.havingRaw"],
    receiverTypes: ["DB", "Connection", "Builder", "Eloquent\\Builder"],
    callNames: ["select", "statement", "unprepared", "selectRaw", "whereRaw", "orderByRaw", "havingRaw"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["static-method", "instance-method"],
  }),
  sinkModel({
    id: "php.runtime.command",
    languages: ["php"],
    moduleNames: [],
    qualifiedNames: ["system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"],
    receiverTypes: [],
    callNames: ["system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"],
    taintArguments: [0],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["function"],
    global: true,
  }),
  sinkModel({
    id: "python.os.command",
    languages: ["python"],
    moduleNames: ["os"],
    qualifiedNames: ["os.system", "os.popen"],
    receiverTypes: [],
    callNames: ["system", "popen"],
    taintArguments: [0],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["module-function"],
  }),
  sinkModel({
    id: "python.subprocess.command",
    languages: ["python"],
    moduleNames: ["subprocess"],
    qualifiedNames: ["subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "subprocess.check_call"],
    receiverTypes: [],
    callNames: ["run", "Popen", "call", "check_output", "check_call"],
    taintArguments: [0],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["module-function"],
    argumentPolicy: "python-subprocess",
  }),
  sinkModel({
    id: "python.dbapi.dynamic-query",
    languages: ["python"],
    moduleNames: ["sqlite3", "sqlalchemy", "sqlalchemy.orm", "sqlalchemy.ext.asyncio", "django.db"],
    qualifiedNames: ["Cursor.execute", "Cursor.executemany", "Connection.execute", "Session.execute"],
    receiverTypes: ["Cursor", "Connection", "Session", "AsyncSession"],
    callNames: ["execute", "executemany"],
    taintArguments: [0],
    taintRestFrom: 0,
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
    requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "python.django.raw-query",
    languages: ["python"],
    moduleNames: ["django.db", "django.db.models"],
    qualifiedNames: ["django.db.models.QuerySet.raw", "django.db.models.RawQuerySet.raw", "django.db.models.Manager.raw"],
    receiverTypes: ["django.db.models.QuerySet", "django.db.models.RawQuerySet", "django.db.models.Manager", "QuerySet", "RawQuerySet", "Manager"],
    callNames: ["raw"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
    requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "python.http.request",
    languages: ["python"],
    moduleNames: ["requests", "httpx", "urllib.request"],
    qualifiedNames: ["requests.get", "requests.post", "requests.request", "httpx.get", "httpx.post", "httpx.request", "httpx.AsyncClient.get", "httpx.AsyncClient.request", "urllib.request.urlopen"],
    receiverTypes: ["Client", "AsyncClient"],
    callNames: ["get", "post", "put", "patch", "delete", "request", "urlopen"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["module-function", "instance-method"],
    requiresModuleIdentity: true,
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
    receiverTypes: ["java.sql.Statement", "Statement", "java.sql.PreparedStatement", "PreparedStatement"],
    callNames: ["executeQuery", "executeUpdate", "execute"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "java.sql.Connection.prepareStatement",
    languages: ["java"],
    moduleNames: ["java.sql"],
    qualifiedNames: [
      "java.sql.Connection.prepareStatement", "Connection.prepareStatement",
      "java.sql.Connection.prepareCall", "Connection.prepareCall",
    ],
    receiverTypes: ["java.sql.Connection", "Connection"],
    callNames: ["prepareStatement", "prepareCall"],
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
    if (identity.moduleName && moduleMatches(model, identity.moduleName) && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "verified", identity, call);
    }
    if (!model.requiresModuleIdentity && !identity.unresolvedType && identity.qualifiedName && qualifiedMatches(model, identity.qualifiedName)) {
      return resolution(model, identity.verified ? "verified" : "syntax", identity, call);
    }
    if (!model.requiresModuleIdentity && !identity.unresolvedType && identity.receiverType && receiverMatches(model, identity.receiverType)) {
      return resolution(model, identity.verified ? "verified" : "syntax", identity, call);
    }
    if (!model.requiresModuleIdentity && call.receiver && (!identity.verified || !identity.receiverType) && syntaxReceiverMatches(model, call.receiver)) {
      return resolution(model, "syntax", { ...identity, qualifiedName: `${call.receiver}.${semanticName}` }, call);
    }
  }

  if (identity.receiverType && !isDynamicReceiverType(identity.receiverType) &&
    candidates.every(model => model.custom && model.role === SemanticRole.GUARD)) return {
    status: "rejected",
    reason: "The declared receiver type does not match the project-configured guard model.",
    candidates: candidates.map(model => model.id),
  };

  if (["java", "php", "python"].includes(language) && identity.receiverType && isDynamicReceiverType(identity.receiverType)) return {
    status: "candidate",
    reason: "The receiver has only a dynamic or top-level type, so the security API identity could not be proven.",
    candidates: candidates.map(model => model.id),
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

function resolution(model, status, identity, call) {
  const policyRejection = callPolicyRejection(model, call);
  if (policyRejection) return {
    status: "rejected",
    reason: policyRejection,
    candidates: [model.id],
  };
  return {
    status,
    model,
    identity,
    certainty: status === "verified" ? "high" : "medium",
  };
}

function callPolicyRejection(model, call = {}) {
  if (model.argumentPolicy !== "python-subprocess") return undefined;
  const argumentsList = call.arguments || [];
  const command = String(argumentsList[0] || "").trim();
  const shellArgument = argumentsList.find(argument => /^shell\s*=/.test(String(argument).trim()));
  const shellEnabled = /^shell\s*=\s*true$/i.test(String(shellArgument || "").trim());
  if (shellEnabled || !/^[[(]/.test(command)) return undefined;
  const firstElement = command.slice(1).trim();
  if (/^(?:[rubf]{0,2})?["'](?:\\.|[^"'])*["']/i.test(firstElement)) {
    return "A constant executable is invoked through an argv list with shell expansion disabled.";
  }
  return undefined;
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

function isDynamicReceiverType(value) {
  return new Set(["?", "any", "mixed", "object", "java.lang.object", "dynamic", "unknown"])
    .has(canonicalQualified(value));
}

module.exports = {
  SEMANTIC_MODELS,
  SemanticRole,
  resolveSemanticCall,
};
