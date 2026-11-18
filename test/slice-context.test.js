"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { buildSliceContext, formatSliceMarkdown } = require("../src/query/slice-context");
const { TraceReviewState } = require("../src/review/trace-review");

test("slice preserves sibling branches, inherited decisions, and complete deduplicated functions", async () => {
  const text = "function run(value) {\n  const copy = value;\n  send(copy);\n  log(copy);\n}\nfunction unrelated() { return 1; }";
  const location = line => ({ absolutePath: "/workspace/a.js", relativePath: "a.js", line, code: text.split("\n")[line - 1] });
  const chain = { title: "value", kind: "trace-forward", roots: [{ kind: "assignment", location: location(2), children: [
    { kind: "sink", location: location(3) }, { kind: "call", location: location(4) },
  ] }] };
  let reads = 0;
  const slice = await buildSliceContext(chain, { isReviewed: node => node === chain.roots[0], readSource: async () => { reads++; return { text, language: "javascript" }; } });
  assert.equal(reads, 1);
  assert.deepEqual(slice.edges, [{ from: 1, to: 2 }, { from: 1, to: 3 }]);
  assert.equal(slice.functions.length, 1);
  assert.equal(slice.functions[0].code, text.split("\n").slice(0, 5).join("\n"));
  assert.ok(slice.steps.every(step => step.functionId === 1 && step.reviewStatus === "safe/ignored"));
  assert.deepEqual(slice.omissions, []);
  const markdown = formatSliceMarkdown(slice);
  assert.match(markdown, /1 → 3/);
  assert.doesNotMatch(markdown, /2 → 3/);
  assert.match(markdown, /Safe \/ Ignored/);
  assert.match(markdown, /Enclosing functions/);
});

test("slice extracts Java methods and reports missing files without discarding path evidence", async () => {
  const chain = { steps: [{ kind: "source", absolutePath: "/workspace/A.java", line: 3 }, { kind: "sink", absolutePath: "/workspace/missing.java", line: 8, code: "execute(value);" }] };
  const slice = await buildSliceContext(chain, { readSource: async file => {
    if (file.includes("missing")) throw new Error("file unavailable");
    return { language: "java", text: "class A {\n  void run(String value) {\n    execute(value);\n  }\n}" };
  } });
  assert.equal(slice.functions[0].code, "void run(String value) {\n    execute(value);\n  }");
  assert.equal(slice.steps[1].code, "execute(value);");
  assert.match(slice.omissions[0], /file unavailable/);
  assert.deepEqual(slice.edges, [{ from: 1, to: 2 }]);
});

test("slice Markdown fences untrusted code and retains unknown analysis status", async () => {
  const slice = await buildSliceContext({ steps: [{ kind: "sink", code: "```\n# code, not a heading", relativePath: "a`b.js", line: 1 }] });
  const markdown = formatSliceMarkdown(slice);
  assert.match(markdown, /   ````/);
  assert.match(markdown, /unresolved/);
  assert.match(markdown, /a\\`b.js/);
});

test("review decisions restore for the same evidence and invalidate when code changes", () => {
  const chain = { roots: [{ kind: "sink", location: { line: 4, code: "send(value)" } }] };
  const state = new TraceReviewState();
  state.setChain(chain);
  const saved = state.toggle(chain.roots[0]);
  const restored = new TraceReviewState(saved);
  restored.setChain(JSON.parse(JSON.stringify(chain)));
  assert.equal(restored.has(chain.roots[0]), true);
  const changed = { roots: [{ kind: "sink", location: { line: 4, code: "send(other)" } }] };
  restored.setChain(changed);
  assert.equal(restored.has(changed.roots[0]), false);
  state.toggle(chain.roots[0]);
  assert.equal(state.has(chain.roots[0]), false);
});
