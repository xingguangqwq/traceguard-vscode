"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const {
  normalizeAccessPath,
  pathFeeds,
  pathsOverlap,
  propagatedAssignmentTargets,
  removeAssignedTaint,
} = require("../src/ir/access-path");

test("Access Paths normalize properties, quoted keys, indexes and dynamic collection elements", () => {
  assert.equal(normalizeAccessPath("request?.body['cmd']"), "request.body.cmd");
  assert.equal(normalizeAccessPath("items[index]"), "items[*]");
  assert.equal(normalizeAccessPath("$_GET[command]"), "$_GET.command");
  assert.equal(normalizeAccessPath("map['tenant-key']"), "map[\"tenant-key\"]");
  assert.equal(normalizeAccessPath("factory().value"), "");
});

test("Access Path matching preserves siblings and treats dynamic indexes as one collection element", () => {
  assert.equal(pathFeeds("payload.command", "payload.command.value"), true);
  assert.equal(pathFeeds("payload.command", "payload.safe"), false);
  assert.equal(pathFeeds("items[*]", "items[3]"), true);
  assert.equal(pathsOverlap("items[0]", "items[*]"), true);
  assert.equal(pathsOverlap("items[0]", "items[1]"), false);
});

test("alias assignments rebase tainted descendants without contaminating sibling fields", () => {
  assert.deepEqual(
    propagatedAssignmentTargets("alias", ["payload"], ["payload.command"], "alias"),
    ["alias.command"],
  );
  assert.deepEqual(
    propagatedAssignmentTargets("rendered", ["payload"], ["payload.command"], "aggregate"),
    ["rendered"],
  );
  assert.deepEqual(
    [...removeAssignedTaint(new Set(["value", "value.nested", "sibling"]), "value")],
    ["sibling"],
  );
});
