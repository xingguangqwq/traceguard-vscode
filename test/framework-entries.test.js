"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  classifyFrameworkCall,
  dedupeFrameworkEntries,
  frameworkParameterRoles,
  inferParameterRoles,
  staticString,
} = require("../src/frontends/framework-entries");

test("framework classifiers retain dynamic routes and framework-specific methods", () => {
  const dynamic = classifyFrameworkCall("javascript", {
    function: "get", receiver: "app", arguments: ["route", "handler"],
  });
  const dynamicPhp = classifyFrameworkCall("php", {
    function: "get", receiver: "Route", arguments: ["$route", "handler"],
  });
  const dynamicCSharp = classifyFrameworkCall("csharp", {
    function: "MapGet", receiver: "app", arguments: ["route", "handler"],
  });
  const dynamicGo = classifyFrameworkCall("go", {
    function: "HandleFunc", receiver: "http", arguments: ["route", "handler"],
  });
  const php = classifyFrameworkCall("php", {
    function: "post", receiver: "Route", arguments: ["'/users'", "handler"],
  });
  const csharp = classifyFrameworkCall("csharp", {
    function: "MapMethods", receiver: "app", arguments: ["\"/x\"", "new[] { \"GET\", \"POST\" }", "handler"],
  });
  const go = classifyFrameworkCall("go", {
    function: "Methods",
    arguments: ["\"GET\"", "\"POST\""],
    receiverCall: { function: "HandleFunc", receiver: "router", arguments: ["\"/x\"", "handler"] },
  });

  assert.equal(dynamic.route, "<dynamic>");
  assert.deepEqual(dynamic.handlerIndexes, [1]);
  assert.equal(dynamicPhp.route, "<dynamic>");
  assert.equal(dynamicCSharp.route, "<dynamic>");
  assert.equal(dynamicGo.route, "<dynamic>");
  assert.deepEqual({ method: php.method, route: php.route }, { method: "POST", route: "/users" });
  assert.deepEqual({ method: csharp.method, handlerIndexes: csharp.handlerIndexes }, { method: "GET|POST", handlerIndexes: [2] });
  assert.deepEqual({ method: go.method, route: go.route, chained: go.chained }, { method: "GET|POST", route: "/x", chained: true });
});

test("Express use distinguishes pathless middleware from a dynamic path", () => {
  const pathless = classifyFrameworkCall("javascript", {
    function: "use",
    receiver: "app",
    arguments: ["auth", "handler"],
    handlerArguments: [true, true],
  });
  const dynamicPath = classifyFrameworkCall("javascript", {
    function: "use",
    receiver: "app",
    arguments: ["route", "handler"],
    handlerArguments: [false, true],
  });

  assert.deepEqual(
    { route: pathless.route, handlerIndexes: pathless.handlerIndexes },
    { route: "<all>", handlerIndexes: [0, 1] },
  );
  assert.deepEqual(
    { route: dynamicPath.route, handlerIndexes: dynamicPath.handlerIndexes },
    { route: "<dynamic>", handlerIndexes: [1] },
  );
});

test("parameter provenance is positional for callbacks and type-derived elsewhere", () => {
  assert.deepEqual(
    frameworkParameterRoles({ framework: "express" }, Array.from({ length: 4 }, () => ({}))),
    ["error", "request", "response", "continuation"],
  );
  assert.deepEqual(
    frameworkParameterRoles({ framework: "go-http" }, [{}, {}, {}]),
    ["response", "request", "unknown"],
  );
  assert.deepEqual(
    frameworkParameterRoles({ framework: "php-route" }, [{ raw: "$request" }, { raw: "$id" }]),
    ["request", "path"],
  );
  assert.deepEqual(inferParameterRoles("typescript", [
    { raw: "@Body() body" },
    { raw: "@Query() query" },
    { raw: "@Param() id" },
    { raw: "@Headers() headers" },
    { type: "Request" },
    { type: "Response" },
    { type: "HttpContext" },
    { type: "NextFunction" },
    { type: "CancellationToken" },
    { type: "ILogger" },
    { type: "AppDbContext" },
    { type: "CommandService" },
    { raw: "[FromQuery] string command", type: "string" },
    { raw: "[FromRoute] string id", type: "string" },
    { raw: "[FromHeader] string token", type: "string" },
    { raw: "[FromBody] Payload payload", type: "Payload" },
    { raw: "[FromServices] Clock clock", type: "Clock" },
    { type: "string" },
  ]), [
    "body", "query", "path", "header", "request", "response", "context", "continuation",
    "cancellation", "logger", "database", "service", "query", "path", "header", "body", "service", "unknown",
  ]);
});

test("framework entry deduplication prefers explicit HTTP methods", () => {
  const entries = dedupeFrameworkEntries([
    { method: "REQUEST", route: "/x", functionId: "handler", handlerIndex: 1 },
    { method: "POST", route: "/x", functionId: "handler", handlerIndex: 1 },
    { method: "POST", route: "/x", functionId: "handler", handlerIndex: 1 },
  ]);

  assert.deepEqual(entries, [{ method: "POST", route: "/x", functionId: "handler", handlerIndex: 1 }]);
  assert.equal(staticString("`/users`"), "/users");
  assert.equal(staticString("`/users/${id}`"), undefined);
});
