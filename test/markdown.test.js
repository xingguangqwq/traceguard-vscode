"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { markdownFence } = require("../src/markdown");

test("markdown code fences grow beyond backticks in saved evidence", () => {
  assert.equal(markdownFence("plain code"), "```");
  assert.equal(markdownFence("before ``` injected heading"), "````");
  assert.equal(markdownFence("``````"), "```````");
});
