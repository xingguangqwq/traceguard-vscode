"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const Module = require("node:module");
const { EventEmitter } = require("node:events");

function createVscodeMock() {
  class MarkdownString {
    constructor(value = "") {
      this.value = value;
      this.supportThemeIcons = false;
      this.isTrusted = false;
    }
    appendMarkdown(text) { this.value += text; return this; }
    appendText(text) { this.value += text; return this; }
    appendCodeblock(code) { this.value += `\n\`\`\`\n${code}\n\`\`\`\n`; return this; }
  }
  class TreeItem {
    constructor(label, collapsibleState) {
      this.label = label;
      this.collapsibleState = collapsibleState;
    }
  }
  class ThemeIcon {
    constructor(id, color) { this.id = id; this.color = color; }
  }
  class ThemeColor {
    constructor(id) { this.id = id; }
  }
  return {
    env: { language: "en" },
    TreeItem,
    TreeItemCollapsibleState: { None: 0, Collapsed: 1, Expanded: 2 },
    ThemeIcon,
    ThemeColor,
    MarkdownString,
    OverviewRulerLane: { Right: 4 },
    Uri: { file: p => ({ fsPath: p, toString: () => `file://${p}` }), parse: value => ({ toString: () => value }) },
    EventEmitter: class {
      constructor() {
        this.emitter = new EventEmitter();
        this.event = listener => {
          this.emitter.on("change", listener);
          return { dispose: () => this.emitter.off("change", listener) };
        };
      }
      fire(value) { this.emitter.emit("change", value); }
      dispose() { this.emitter.removeAllListeners(); }
    },
    workspace: {
      getWorkspaceFolder: () => undefined,
      getConfiguration: () => ({ get: (_k, def) => def }),
    },
    window: {
      activeTextEditor: undefined,
      createTextEditorDecorationType: options => ({ options }),
    },
  };
}

function loadWithMockedVscode(loadFn) {
  const originalLoad = Module._load;
  const mock = createVscodeMock();
  Module._load = function(name, ...args) {
    if (name === "vscode") return mock;
    return originalLoad.call(this, name, ...args);
  };
  try {
    return loadFn(mock);
  } finally {
    Module._load = originalLoad;
  }
}

const {
  buildCsp,
  createNonce,
  readCodeSnippet,
  renderMarkdownToHtml,
} = require("../src/ui/webview/webview-utils");

const {
  buildScopeViewState,
  ScopeViewProvider,
  TraceInspectorPanel,
  AiReportProvider,
  AiController,
  buildTraceInspectorState,
  extractCallMetadata,
  humanizeStepLabel,
  AuditQueryProvider,
  createTracePathDecorations,
  createTraceLineDecorations,
} = loadWithMockedVscode(() => ({
  ...require("../src/ui/webview/scope-view-provider"),
  ...require("../src/ui/webview/trace-inspector-panel"),
  ...require("../src/ai/reportProvider"),
  ...require("../src/ai/controller"),
  ...require("../src/audit-providers"),
  ...require("../src/ui/decorations"),
}));

test("Inspector shows and cancels only the displayed trace's report during concurrent requests", async () => {
  const provider = new AiReportProvider();
  const ai = Object.create(AiController.prototype);
  const requests = new Map();
  const started = new EventEmitter();
  Object.assign(ai, {
    provider, requests,
    onDidStartReport(fn) { started.on("start", fn); return { dispose: () => started.off("start", fn) }; },
  });
  const a = {}, b = {};
  const query = { currentTrace: a };
  const messages = [];
  const panel = new TraceInspectorPanel({}, { ai, queryProvider: query, session: { onDidChange() {} } });
  panel._panel = { webview: { postMessage(message) { messages.push(message); } }, dispose() {} };
  panel.bindAiEvents(ai);
  function start(chain) {
    const abort = new AbortController();
    const uri = provider.create(() => abort.abort(), "en", { chain });
    requests.set(uri.toString(), abort);
    started.emit("start", uri);
    return uri;
  }
  try {
    const first = start(a);
    provider.append(first, "A only");
    query.currentTrace = b;
    const second = start(b);
    provider.append(second, "B only");
    const count = messages.length;
    provider.finish(first, "finished");
    assert.equal(messages.length, count, "a background completion cannot update the active report");
    assert.equal(panel._reportView().markdown, "B only");
    assert.equal(panel._reportView().status, "streaming");
    await panel._handleMessage({ type: "stopAi", uriString: first.toString() });
    await panel._handleMessage({ type: "stopAi", uriString: second.toString() });
    assert.equal(requests.get(first.toString()).signal.aborted, false);
    assert.equal(requests.get(second.toString()).signal.aborted, true);
    query.currentTrace = a;
    assert.equal(panel._reportView().markdown, "A only");
    assert.equal(panel._reportView().status, "complete");
    provider.close(first);
    assert.equal(messages.at(-1).ai.status, "idle");
  } finally { panel.dispose(); provider.dispose(); }
});

test("Scope searches beyond the first page and both generated Webview scripts start", () => {
  const entries = Array.from({ length: 75 }, (_, i) => ({ method: "GET", route: "/route-" + i }));
  const controller = {
    session: { snapshot: { indexed_at: "now", entries }, onDidChange() {} },
    codeProvider: { getFilterState: () => ({}) },
  };
  const scope = new ScopeViewProvider(controller);
  const inspector = new TraceInspectorPanel({}, controller);
  for (const view of [scope, inspector]) {
    const html = view._buildHtml({ cspSource: "vscode-webview://test" });
    const script = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/)[1];
    const root = { innerHTML: "" };
    let onMessage;
    const messages = [];
    const document = { getElementById: id => ["root", "app"].includes(id) ? root : null, querySelectorAll: () => [] };
    require("node:vm").runInNewContext(script, { document, window: { addEventListener: (_, fn) => { onMessage = fn; } },
      acquireVsCodeApi: () => ({ postMessage: msg => messages.push(msg) }) });
    assert.equal(messages.at(-1)?.type, "ready");
    if (view === scope) {
      assert.equal((root.innerHTML.match(/data-open-ep=/g) || []).length, 60);
      const state = buildScopeViewState(controller.session.snapshot, { searchQuery: "route-74" });
      onMessage({ data: { type: "state", state } });
      assert.equal((root.innerHTML.match(/data-open-ep=/g) || []).length, 1);
      assert.match(root.innerHTML, /route-74/);
    }
  }
});

test("Markdown renderer escapes raw HTML/XSS while rendering headings, lists, quotes, and fenced code blocks", () => {
  const html = renderMarkdownToHtml([
    "## Verdict",
    "",
    "> **Note**: `req.query.url` reaches sink <script>alert(1)</script>",
    "",
    "- First *check* item",
    "- Second item",
    "",
    "```python",
    "driver.get(url)",
    "```",
  ].join("\n"));

  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /<h2 class="md-h2">Verdict<\/h2>/);
  assert.match(html, /<blockquote class="md-quote"><strong>Note<\/strong>/);
  assert.match(html, /<code class="md-inline-code">req\.query\.url<\/code>/);
  assert.match(html, /<ul class="md-list"><li>First <em>check<\/em> item<\/li>/);
  assert.match(html, /<span class="md-code-lang">python<\/span>/);
  assert.match(html, /driver\.get\(url\)/);
});

test("CSP builder uses strict default-src none with cryptographic nonce", () => {
  const nonce = createNonce();
  assert.ok(nonce.length >= 16);
  const csp = buildCsp({ cspSource: "vscode-webview://unit" }, nonce);
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, new RegExp(`script-src 'nonce-${nonce.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}'`));
});

test("readCodeSnippet returns 3 contextual lines with normalized indentation and active marker", async () => {
  const source = [
    "def peek_website(url):",
    "    if not url:",
    "        return False",
    "    driver.get(url)",
    "    return True",
  ].join("\n");
  const snippet = await readCodeSnippet("/virtual/app.py", 4, 1, async () => source);
  assert.equal(snippet.lines.length, 3);
  assert.deepEqual(snippet.lines.map(l => l.number), [3, 4, 5]);
  assert.equal(snippet.lines[1].active, true);
  assert.equal(snippet.lines[1].text, "driver.get(url)");
});

test("buildScopeViewState computes posture meters, 3 colored metric pill counts, and grouped endpoints", () => {
  const snapshot = {
    indexed_at: "2026-11-18T00:00:00Z",
    files: 3,
    functions: 18,
    languages: { python: 2, php: 1 },
    analysisCoverage: { indexed: 3, discovered: 4, skipped: 1, complete: false, partialPaths: 2 },
    manualReviewCoverage: { reviewed: 4, total: 10 },
    statusCounts: { unreviewed: 6, reviewed: 4 },
    entries: [
      { id: "e1", method: "GET", route: "/generate", title: "scrape", framework: "flask", relativePath: "app.py", absolutePath: "/ws/app.py", line: 145, functionId: "fn-scrape" },
      { id: "e2", method: "POST", route: "/submit", title: "submit", framework: "flask", relativePath: "app.py", absolutePath: "/ws/app.py", line: 180, functionId: "fn-submit" },
    ],
    findings: [
      {
        id: "f1",
        status: "open",
        severity: "high",
        confidence: "high",
        title: "Potential SSRF",
        path: { verified: true, steps: [{ kind: "source", functionId: "fn-scrape", line: 146, absolutePath: "/ws/app.py" }] },
      },
      {
        id: "f2",
        status: "open",
        severity: "medium",
        confidence: "review",
        reviewOnly: true,
        title: "Unresolved helper",
        path: { verified: false, steps: [{ kind: "call", functionId: "fn-submit", line: 182, absolutePath: "/ws/app.py", analysisStatus: "unresolved" }] },
      },
    ],
  };

  const state = buildScopeViewState(snapshot, { filterId: "verified", filterLabel: "Verified flows", searchQuery: "gen" }, "zh-CN");
  assert.equal(state.locale, "zh");
  assert.equal(state.manualPercent, 40);
  assert.equal(state.coveragePercent, 75);
  assert.equal(state.verifiedCount, 1);
  assert.equal(state.hypothesisCount, 1);
  assert.equal(state.endpointsCount, 2);
  assert.equal(state.filterId, "verified");
  assert.equal(state.searchQuery, "gen");
  assert.equal(state.endpointGroups.length, 2);
  assert.equal(state.endpointGroups[0].items[0].openFlows, 1);
});

test("buildTraceInspectorState builds visual timeline with snippets, humanized labels, and inline call modeling metadata", async () => {
  const source = [
    "def handle(req):",
    "    url = req.args.get('url')",
    "    custom_dispatch(url, timeout=5)",
    "    driver.get(url)",
  ].join("\n");

  const finding = {
    id: "f-ssrf",
    title: "Server-Side Request Forgery",
    cwe: "CWE-918",
    severity: "high",
    confidence: "high",
    status: "open",
    sourceKind: "HTTP_INPUT",
    sinkKind: "HTTP_REQUEST",
    observedGuards: ["URL scheme check"],
    missingGuards: ["Private IP blocklist"],
    paths: [{
      id: "p1",
      steps: [
        { kind: "source", label: "python.framework.request-method", code: "url = req.args.get('url')", functionName: "handle", absolutePath: "/ws/app.py", relativePath: "app.py", line: 2 },
        { kind: "call", label: "custom_dispatch(url, timeout=5)", code: "custom_dispatch(url, timeout=5)", functionName: "handle", absolutePath: "/ws/app.py", relativePath: "app.py", line: 3, analysisStatus: "unresolved", candidateReason: "Dynamic receiver could not be resolved" },
        { kind: "sink", label: "python.browser-navigation", code: "driver.get(url)", functionName: "handle", absolutePath: "/ws/app.py", relativePath: "app.py", line: 4 },
      ],
    }],
  };

  const state = await buildTraceInspectorState({
    finding,
    flowPath: finding.paths[0],
    cursor: 2,
    evidence: [{ id: "n1", type: "Controllability", note: "User controls url", code: "driver.get(url)", absolutePath: "/ws/app.py", relativePath: "app.py", line: 4 }],
    readOpenDocument: async () => source,
  });

  assert.equal(state.mode, "finding");
  assert.equal(state.cwe, "CWE-918");
  assert.equal(state.steps.length, 3);
  assert.equal(state.steps[0].label, "url = req.args.get('url')");
  assert.equal(state.steps[2].label, "driver.get(url)");
  assert.equal(state.steps[2].active, true);
  assert.equal(state.steps[2].snippet.length, 2);
  assert.ok(state.interruption?.modelable);
  assert.equal(state.interruption.functionName, "custom_dispatch");
  assert.deepEqual(state.interruption.arguments, ["url", "timeout=5"]);
  assert.equal(state.notes.length, 1);
});

test("Native UI regressions stay fixed: decorations split cleanly, icons render cleanly, SVG uses currentColor", () => {
  const tokenDecorations = createTracePathDecorations();
  const lineDecorations = createTraceLineDecorations();
  assert.equal(tokenDecorations.sink.options.after, undefined, "token highlight must not split code mid-line");
  assert.equal(lineDecorations.sink.options.isWholeLine, true, "end-of-line badge uses whole-line decoration");
  assert.match(lineDecorations.sink.options.after.contentText, /sink/);

  assert.equal(humanizeStepLabel({ label: "python.framework.request-method", code: "request.args.get('url')" }), "request.args.get('url')");
  assert.equal(humanizeStepLabel({ label: "fetch() reads this.command" }), "fetch() reads this.command");

  const queryProvider = new AuditQueryProvider();
  queryProvider.setResult({
    title: "Trace backward",
    roots: [{
      id: "n1",
      kind: "sink",
      status: "verified",
      label: "exec(cmd)",
      reason: "Verified sink",
      location: { relativePath: "app.ts", absolutePath: "/ws/app.ts", line: 10 },
      children: [],
    }],
  });
  const rootItem = queryProvider.getChildren()[0];
  const nodeItem = queryProvider.getChildren(rootItem)[0];
  assert.doesNotMatch(nodeItem.description, /\$\([^)]+\)/, "TreeItem.description must never leak raw $(icon) syntax");
  assert.equal(nodeItem.tooltip.supportThemeIcons, true, "MarkdownString tooltips must enable ThemeIcon rendering");

  const svg = fs.readFileSync(path.join(__dirname, "..", "resources", "code-trace.svg"), "utf8");
  assert.match(svg, /currentColor/);
  assert.match(svg, /viewBox="0 0 24 24"/);
});
