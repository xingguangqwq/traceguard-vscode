"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const Module = require("node:module");
const { EventEmitter } = require("node:events");
const originalLoad = Module._load;
Module._load = function(name, ...args) {
  if (name === "vscode") return {
    Uri: { parse: value => ({ toString: () => value }) },
    EventEmitter: class {
      constructor() { this.emitter = new EventEmitter(); this.event = listener => { this.emitter.on("change", listener); return { dispose: () => this.emitter.off("change", listener) }; }; }
      fire(value) { this.emitter.emit("change", value); }
      dispose() { this.emitter.removeAllListeners(); }
    },
  };
  return originalLoad.call(this, name, ...args);
};
let AiReportProvider;
try { ({ AiReportProvider } = require("../src/ai/reportProvider")); } finally { Module._load = originalLoad; }

test("AI report headings and preparation status use the captured editor language", () => {
  const provider = new AiReportProvider();
  const english = provider.create(() => {}, "en-US");
  const chinese = provider.create(() => {}, "zh-TW");
  assert.match(provider.provideTextDocumentContent(english), /TraceGuard AI Review/);
  assert.doesNotMatch(provider.provideTextDocumentContent(english), /[\u4e00-\u9fff]/);
  assert.match(provider.provideTextDocumentContent(chinese), /TraceGuard AI 研判/);
  provider.finish(english, "complete");
  assert.match(provider.provideTextDocumentContent(chinese), /正在准备切片/);
  provider.dispose();
});

test("report updates are throttled, final status flushes, and closing aborts without late events", async () => {
  const provider = new AiReportProvider();
  let events = 0;
  let aborted = 0;
  provider.onDidChange(() => events++);
  const uri = provider.create(() => aborted++);
  for (let i = 0; i < 30; i++) provider.append(uri, "x");
  assert.equal(events, 0);
  await new Promise(resolve => setTimeout(resolve, 130));
  assert.equal(events, 1);
  provider.append(uri, "tail");
  provider.finish(uri, "completed");
  assert.equal(events, 2);
  assert.match(provider.provideTextDocumentContent(uri), /x{30}tail/);
  provider.append(uri, "late");
  provider.close(uri);
  assert.equal(events, 3, "closing the report clears its Inspector view immediately");
  await new Promise(resolve => setTimeout(resolve, 130));
  assert.equal(events, 3);
  assert.equal(aborted, 1);
  assert.equal(provider.reports.size, 0);
  provider.dispose();
});
