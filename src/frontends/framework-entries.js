"use strict";

const JS_METHODS = new Set(["get", "post", "put", "delete", "patch", "options", "all", "use"]);
const PHP_METHODS = new Set(["get", "post", "put", "delete", "patch", "any"]);
const GO_METHODS = new Set(["get", "post", "put", "delete", "patch", "options", "any"]);
const JS_RECEIVERS = new Set(["app", "router", "server", "fastify"]);
const GENERIC_METHODS = new Set(["ANY", "REQUEST"]);

const EXPRESS_ROLES = ["request", "response", "continuation"];
const EXPRESS_ERROR_ROLES = ["error", "request", "response", "continuation"];
const GO_HTTP_ROLES = ["response", "request"];

const DECLARATION_ROLE_PATTERNS = Object.freeze([
  [/(?:@(?:request)?headers?\b|\[\s*FromHeaders?\b)/i, "header"],
  [/(?:@(?:request)?body\b|\[\s*From(?:Body|Form)\b)/i, "body"],
  [/(?:@query\b|@requestparam\b|\[\s*FromQuery\b)/i, "query"],
  [/(?:@param(?:s)?\b|@pathvariable\b|\[\s*FromRoute\b)/i, "path"],
  [/(?:@req(?:uest)?\b|\[\s*FromRequest\b)/i, "request"],
  [/(?:@res(?:ponse)?\b|\[\s*FromResponse\b)/i, "response"],
  [/\[\s*FromServices?\b/i, "service"],
]);

const EXACT_TYPE_ROLES = Object.freeze({
  request: "request",
  httprequest: "request",
  servletrequest: "request",
  httpserverrequest: "request",
  response: "response",
  httpresponse: "response",
  httpcontext: "context",
  nextfunction: "continuation",
  cancellationtoken: "cancellation",
  ilogger: "logger",
  logger: "logger",
  session: "database",
  asyncsession: "database",
  connection: "database",
  cursor: "database",
});

const TYPE_ROLE_SUFFIXES = Object.freeze([
  [/dbcontext$/i, "database"],
  [/service$/i, "service"],
  [/repository$/i, "service"],
  [/logger$/i, "logger"],
]);

function classifyFrameworkCall(language, call) {
  if (["javascript", "typescript"].includes(language)) return classifyJavaScriptCall(call);
  if (language === "php") return classifyPhpCall(call);
  if (language === "csharp") return classifyCSharpCall(call);
  if (language === "go") return classifyGoCall(call);
  if (language === "python") return classifyPythonCall(call);
  return undefined;
}

function classifyPythonCall(call) {
  const callee = canonical(call.function);
  if (!["path", "repath"].includes(callee)) return undefined;
  return {
    method: "REQUEST",
    route: call.routeValue || staticString(call.arguments?.[0]) || "<dynamic>",
    handlerIndexes: [1],
    framework: "django",
  };
}

function classifyJavaScriptCall(call) {
  const callee = canonical(call.function);
  if (!JS_METHODS.has(callee)) return undefined;
  const receiverNames = receiverNamesFor(call.receiver);
  if (![...JS_RECEIVERS].some(name => receiverNames.has(name))) return undefined;
  const method = callee === "all" || callee === "use" ? "ANY" : callee.toUpperCase();

  if (call.receiverCall && canonical(call.receiverCall.function) === "route") {
    const route = call.receiverCall.routeValue || staticString(call.receiverCall.arguments?.[0]) || "<dynamic>";
    return {
      method,
      route,
      handlerIndexes: handlerArgumentIndexes(call.arguments, 0),
      chained: true,
      framework: "express",
    };
  }
  if (callee === "use") {
    const explicitRoute = call.routeValue || staticString(call.arguments?.[0]);
    const pathless = !explicitRoute && Boolean(call.handlerArguments?.[0]);
    return {
      method,
      route: explicitRoute || (pathless ? "<all>" : "<dynamic>"),
      handlerIndexes: handlerArgumentIndexes(call.arguments, pathless ? 0 : 1),
      framework: "express",
    };
  }
  return {
    method,
    route: call.routeValue || staticString(call.arguments?.[0]) || "<dynamic>",
    handlerIndexes: handlerArgumentIndexes(call.arguments, 1),
    framework: "express",
  };
}

function classifyPhpCall(call) {
  const callee = canonical(call.function);
  if (!PHP_METHODS.has(callee)) return undefined;
  const receiverNames = receiverNamesFor(call.receiver);
  if (!receiverNames.has("route") && !receiverNames.has("app")) return undefined;
  const route = call.routeValue || staticString(call.arguments?.[0]) || "<dynamic>";
  return { method: callee === "any" ? "ANY" : callee.toUpperCase(), route, handlerIndexes: [1], framework: "php-route" };
}

function classifyCSharpCall(call) {
  const callee = canonical(call.function);
  if (!/^map(?:get|post|put|delete|patch|methods?)$/.test(callee)) return undefined;
  const route = call.routeValue || staticString(call.arguments?.[0]) || "<dynamic>";
  if (callee.endsWith("methods") || callee.endsWith("method")) {
    const verbs = stringLiterals(call.arguments?.[1]);
    return {
      method: verbs.length ? verbs.join("|") : "ANY",
      route,
      handlerIndexes: [2],
      framework: "aspnet-minimal-api",
    };
  }
  return { method: callee.slice(3).toUpperCase(), route, handlerIndexes: [1], framework: "aspnet-minimal-api" };
}

function classifyGoCall(call) {
  const callee = canonical(call.function);
  if (callee === "methods" && call.receiverCall) {
    const inner = classifyGoCall(call.receiverCall);
    if (!inner) return undefined;
    const verbs = stringLiterals(call.arguments);
    return { ...inner, method: verbs.length ? verbs.join("|") : inner.method, chained: true };
  }
  const route = call.routeValue || staticString(call.arguments?.[0]) || "<dynamic>";
  if (callee === "handlefunc") return { method: "REQUEST", route, handlerIndexes: [1], framework: "go-http" };
  const original = String(call.function || "");
  if ((original === original.toUpperCase() || original === "Any") && GO_METHODS.has(callee)) {
    return { method: callee === "any" ? "ANY" : callee.toUpperCase(), route, handlerIndexes: [1], framework: "go-http" };
  }
  return undefined;
}

function handlerArgumentIndexes(argumentsList, routeIndex) {
  const total = Array.isArray(argumentsList) ? argumentsList.length : 0;
  const indexes = [];
  for (let index = routeIndex; index < total; index += 1) indexes.push(index);
  return indexes;
}

function frameworkEntry(classification, fn, sourceLocation = {}) {
  const line = sourceLocation.line || fn?.line || 1;
  const entry = {
    title: `${classification.method} ${classification.route}`,
    method: classification.method,
    route: classification.route,
    line,
    endLine: sourceLocation.endLine || line,
    startColumn: sourceLocation.startColumn,
    endColumn: sourceLocation.endColumn,
    startOffset: sourceLocation.startOffset,
    endOffset: sourceLocation.endOffset,
    functionLine: fn?.line,
    functionName: fn?.name,
    functionId: fn?.id,
    symbolKey: fn?.symbolKey,
    handlerIndex: classification.handlerIndex ?? classification.handlerIndexes?.[0],
    framework: classification.framework,
  };
  const roles = frameworkParameterRoles(entry, fn?.parameterDescriptors || []);
  entry.parameterRoles = roles.length ? roles : inferParameterRoles(classification.language, fn?.parameterDescriptors || []);
  return entry;
}

function mergeFrameworkEntries(astEntries, patternEntries) {
  const astFunctions = new Set(astEntries.map(item => item.functionId).filter(Boolean));
  const merged = [
    ...astEntries,
    ...patternEntries.filter(item =>
      !astFunctions.has(item.functionId) &&
      !astEntries.some(ast => ast.method === item.method && ast.route === item.route),
    ),
  ];
  const seen = new Set();
  return merged.filter(item => {
    const key = `${item.method}:${item.route}:${item.functionId || item.functionLine || item.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function dedupeFrameworkEntries(entries) {
  const specificIdentities = new Set();
  for (const entry of entries) {
    if (entry.method && !GENERIC_METHODS.has(entry.method)) specificIdentities.add(entryIdentity(entry));
  }
  const seen = new Set();
  return entries.filter(entry => {
    if (GENERIC_METHODS.has(entry.method) && specificIdentities.has(entryIdentity(entry))) return false;
    const key = `${entry.method}:${entryIdentity(entry)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function entryIdentity(entry) {
  return `${entry.route}:${entry.functionId || entry.functionLine || entry.line}:${entry.handlerIndex ?? ""}`;
}

function frameworkParameterRoles(entry, parameters) {
  if (!Array.isArray(parameters) || !parameters.length || !entry?.framework) return [];
  if (entry.framework === "express") {
    const roles = parameters.length >= 4 ? EXPRESS_ERROR_ROLES : EXPRESS_ROLES;
    return parameters.map((_, index) => roles[index] || "unknown");
  }
  if (entry.framework === "go-http") {
    return parameters.map((_, index) => GO_HTTP_ROLES[index] || "unknown");
  }
  if (entry.framework === "php-route") {
    return parameters.map((parameter, index) =>
      index === 0 && requestLikeParameter(parameter) ? "request" : "path");
  }
  if (["fastapi", "flask", "django"].includes(entry.framework)) {
    return parameters.map((parameter, index) => pythonFrameworkRole(entry.framework, parameter, index));
  }
  return [];
}

function inferParameterRoles(language, parameters) {
  if (!Array.isArray(parameters)) return [];
  return parameters.map(parameter => {
    const raw = String(parameter?.raw || "");
    if (language === "python" && /\bDepends\s*\(/.test(raw)) {
      return databaseType(parameter?.type) ? "database" : "service";
    }
    if (language === "python") {
      const binding = pythonBindingRole(raw);
      if (binding) return binding;
    }
    const declaration = DECLARATION_ROLE_PATTERNS.find(([pattern]) => pattern.test(raw));
    if (declaration) return declaration[1];
    const type = canonicalType(parameter?.type);
    if (EXACT_TYPE_ROLES[type]) return EXACT_TYPE_ROLES[type];
    const suffix = TYPE_ROLE_SUFFIXES.find(([pattern]) => pattern.test(type));
    if (suffix) return suffix[1];
    return "unknown";
  });
}

function pythonFrameworkRole(framework, parameter, index) {
  const raw = String(parameter?.raw || "");
  const type = canonicalType(parameter?.type);
  if (/\bDepends\s*\(/.test(raw)) return databaseType(parameter?.type) ? "database" : "service";
  const binding = pythonBindingRole(raw);
  if (binding) return binding;
  if (/^(?:request|httprequest|starletterequest)$/.test(type) || /^(?:request|req)$/.test(parameter?.name || "")) return "request";
  if (/^(?:response|httpresponse)$/.test(type)) return "response";
  if (databaseType(parameter?.type)) return "database";
  if (/(?:service|repository|client|logger)$/i.test(type)) return /logger$/i.test(type) ? "logger" : "service";
  if (framework === "fastapi") {
    if (/^(?:str|int|float|bool|uuid|date|datetime|decimal)(?:optional)?$/i.test(type)) return "query";
    if (type && type !== "?") return "body";
  }
  if (framework === "django" && index === 0) return "request";
  return "unknown";
}

function pythonBindingRole(raw) {
  const match = String(raw || "").match(/\b(Query|Body|Path|Header|Cookie|Form|File|UploadFile)\b/i)?.[1]?.toLowerCase();
  return { query: "query", body: "body", path: "path", header: "header", cookie: "header", form: "body", file: "body", uploadfile: "body" }[match];
}

function databaseType(value) {
  return /(?:^|[.])(Session|AsyncSession|Connection|Cursor|DbSession|Database)$/i.test(String(value || "").replace(/\s/g, ""));
}

function requestLikeParameter(parameter) {
  return /request/i.test(`${parameter?.type || ""} ${parameter?.name || ""} ${parameter?.raw || ""}`);
}

function staticString(value) {
  const text = String(value || "").trim();
  const match = text.match(/^@?(["'`])([\s\S]*)\1$/);
  if (!match || (match[1] === "`" && /\$\{/.test(match[2]))) return undefined;
  return match[2].replace(/\\([\\"'`])/g, "$1");
}

function stringLiterals(value) {
  return [...String(value || "").matchAll(/(["'])([^"'\\]*(?:\\.[^"'\\]*)*)\1/g)].map(match => match[2]);
}

function canonicalType(value) {
  return String(value || "").replace(/\[\]$/, "").replace(/<[^<>]*>$/, "").replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

function canonical(value) {
  return String(value || "").replace(/^\$/, "").replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

function receiverNamesFor(receiver) {
  const parts = String(receiver || "").replaceAll("->", ".").replaceAll("::", ".").split(".").filter(Boolean);
  return new Set(parts.map(canonical));
}

module.exports = {
  classifyFrameworkCall,
  dedupeFrameworkEntries,
  frameworkEntry,
  frameworkParameterRoles,
  inferParameterRoles,
  mergeFrameworkEntries,
  staticString,
  stringLiterals,
};
