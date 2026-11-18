"use strict";

const path = require("node:path");
const vscode = require("vscode");
const { findingPool } = require("../../review/finding-pool");
const { findingsTouchingEntry, flowTruncationDescription } = require("../../audit-providers");
const { SVG_ICONS, buildCsp, createNonce, isChineseLocale, safeJsonForHtml } = require("./webview-utils");

const METHOD_RANK = { POST: 0, PUT: 1, PATCH: 2, DELETE: 3, ANY: 4, REQUEST: 5, GET: 6, HEAD: 7, OPTIONS: 8, ENTRY: 9 };

function buildScopeViewState(snapshot = {}, filterState = {}, language = "en") {
  const zh = isChineseLocale(language);
  const indexed = Boolean(snapshot.indexed_at);
  const openFindings = (snapshot.findings || []).filter(finding => finding.status === "open");
  const verifiedCount = openFindings.filter(finding => findingPool(finding) === "verified").length;
  const hypothesisCount = openFindings.filter(finding => findingPool(finding) === "review").length;
  const entries = snapshot.entries || [];

  const manual = snapshot.manualReviewCoverage || {
    reviewed: snapshot.statusCounts?.reviewed || 0,
    total: (snapshot.items || []).length,
  };
  const manualPercent = manual.total ? Math.round((manual.reviewed / manual.total) * 100) : 0;

  const coverage = snapshot.analysisCoverage || {};
  const indexedFiles = coverage.indexed ?? snapshot.files ?? 0;
  const discoveredFiles = Math.max(coverage.discovered ?? indexedFiles, indexedFiles);
  const coveragePercent = discoveredFiles ? Math.round((indexedFiles / discoveredFiles) * 100) : 100;
  const skippedFiles = coverage.skipped || 0;
  const partialPaths = coverage.partialPaths || 0;

  const groupedEndpoints = [];
  const byMethod = new Map();
  for (const entry of entries) {
    const method = String(entry.method || (entry.route ? "ANY" : "ENTRY")).toUpperCase();
    const touched = findingsTouchingEntry(entry, openFindings);
    const verifiedTouched = touched.filter(item => findingPool(item) === "verified").length;
    const route = entry.route && entry.route !== "<dynamic>" ? entry.route : entry.title;
    const item = {
      id: entry.id || `${entry.absolutePath || ""}:${entry.line}:${method}:${route}`,
      method,
      route: route || entry.title || "endpoint",
      title: entry.title || route || "endpoint",
      framework: entry.framework || entry.language || "",
      fileName: path.basename(entry.relativePath || entry.absolutePath || "unknown"),
      relativePath: entry.relativePath || "",
      absolutePath: entry.absolutePath || "",
      line: Number(entry.line) || 1,
      endLine: Number(entry.endLine || entry.line) || 1,
      openFlows: touched.length,
      verifiedFlows: verifiedTouched,
    };
    if (!byMethod.has(method)) byMethod.set(method, []);
    byMethod.get(method).push(item);
  }
  for (const [method, list] of byMethod.entries()) {
    list.sort((a, b) => (b.verifiedFlows - a.verifiedFlows) || (b.openFlows - a.openFlows) || a.route.localeCompare(b.route));
    groupedEndpoints.push({
      method,
      count: list.length,
      withFlows: list.filter(item => item.openFlows > 0).length,
      items: list,
    });
  }
  groupedEndpoints.sort((a, b) => (b.withFlows - a.withFlows) || ((METHOD_RANK[a.method] ?? 10) - (METHOD_RANK[b.method] ?? 10)) || a.method.localeCompare(b.method));

  const languages = Object.keys(snapshot.languages || {});
  const degradedReasons = Object.entries(snapshot.languageCapabilities || {}).flatMap(([lang, cap]) =>
    (cap.reasons || []).map(reason => `${lang}: ${reason}`),
  );
  const projectConfig = snapshot.projectConfiguration || {
    loaded: false,
    semanticModels: 0,
    temporarySemanticModels: 0,
    issues: [],
  };

  return {
    locale: zh ? "zh" : "en",
    indexed,
    indexing: Boolean(snapshot.indexing),
    indexStageMessage: snapshot.indexStage?.message || (zh ? "正在准备分析" : "Preparing analysis"),
    indexError: snapshot.indexError || "",
    indexStale: Boolean(snapshot.indexStale),
    files: indexedFiles,
    discoveredFiles,
    functions: Number(snapshot.functions) || 0,
    coveragePercent,
    coverageComplete: Boolean(coverage.complete ?? !snapshot.indexIncomplete),
    skippedFiles,
    partialPaths,
    partialReason: partialPaths ? flowTruncationDescription(snapshot.findingPathTruncationReasons) : "",
    manualReviewed: manual.reviewed || 0,
    manualTotal: manual.total || 0,
    manualPercent,
    unreviewedCount: snapshot.statusCounts?.unreviewed ?? 0,
    verifiedCount,
    hypothesisCount,
    endpointsCount: entries.length,
    filterId: filterState.filterId || "priority",
    filterLabel: filterState.filterLabel || "P0 / P1 first",
    searchQuery: filterState.searchQuery || "",
    endpointGroups: groupedEndpoints,
    diagnostics: {
      languages,
      degradedReasons,
      semanticModels: projectConfig.semanticModels || 0,
      temporaryModels: projectConfig.temporarySemanticModels || 0,
      configIssues: (projectConfig.issues || []).length,
    },
  };
}

class ScopeViewProvider {
  constructor(controller) {
    this.controller = controller;
    this._view = undefined;
    this._refreshTimer = undefined;
    this._subscription = controller.session.onDidChange(() => this.schedulePush());
  }

  resolveWebviewView(webviewView) {
    this._view = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [],
    };
    webviewView.webview.html = this._buildHtml(webviewView.webview);
    webviewView.onDidDispose(() => {
      if (this._view === webviewView) this._view = undefined;
    });
    webviewView.onDidChangeVisibility(() => {
      if (webviewView.visible) this.pushState();
    });
    webviewView.webview.onDidReceiveMessage(message => {
      void this._handleMessage(message);
    });
    this.pushState();
  }

  schedulePush() {
    clearTimeout(this._refreshTimer);
    this._refreshTimer = setTimeout(() => {
      this._refreshTimer = undefined;
      this.pushState();
    }, 120);
  }

  pushState() {
    if (!this._view) return;
    const state = buildScopeViewState(
      this.controller.session.snapshot,
      this.controller.codeProvider.getFilterState(),
      vscode.env?.language,
    );
    void this._view.webview.postMessage({ type: "state", state });
  }

  async _handleMessage(message) {
    if (!message || typeof message !== "object") return;
    switch (message.type) {
      case "ready":
        this.pushState();
        break;
      case "startAudit":
        await this.controller.startAudit();
        break;
      case "refreshAudit":
        await this.controller.refresh(true);
        break;
      case "openConfig":
        await this.controller.openProjectConfiguration();
        break;
      case "clearTempModels":
        await this.controller.clearTemporaryModels();
        break;
      case "setFilterPill": {
        const nextId = String(message.filterId || "priority");
        const current = this.controller.codeProvider.getFilterState().filterId;
        const toggleToDefault = current === nextId && nextId !== "priority";
        const targetId = toggleToDefault ? "priority" : nextId;
        const labels = {
          priority: "P0 / P1 first",
          verified: "Verified flows",
          hypothesis: "Review hypotheses",
          reachable: "Reachable endpoints",
        };
        this.controller.applyQueueFilter({ id: targetId, label: labels[targetId] || "P0 / P1 first" });
        this.pushState();
        break;
      }
      case "setSearchQuery":
        this.controller.applyQueueSearch(String(message.query || ""));
        break;
      case "clearFilter":
        this.controller.applyQueueFilter({ id: "priority", label: "P0 / P1 first" });
        this.controller.applyQueueSearch("");
        this.pushState();
        break;
      case "openEndpoint":
        if (message.absolutePath) {
          await vscode.commands.executeCommand("traceguard.openAuditLocation", {
            absolutePath: message.absolutePath,
            line: Number(message.line) || 1,
            endLine: Number(message.endLine || message.line) || 1,
          });
        }
        break;
      case "traceEndpoint":
        if (message.absolutePath) {
          await this.controller.traceFromEntry({
            absolutePath: message.absolutePath,
            line: Number(message.line) || 1,
            endLine: Number(message.endLine || message.line) || 1,
            title: message.title || message.route || "endpoint",
          });
        }
        break;
      default:
        break;
    }
  }

  _buildHtml(webview) {
    const nonce = createNonce();
    const csp = buildCsp(webview, nonce);
    const initialState = buildScopeViewState(
      this.controller.session.snapshot,
      this.controller.codeProvider.getFilterState(),
      vscode.env?.language,
    );
    return `<!DOCTYPE html>
<html lang="${initialState.locale === "zh" ? "zh-CN" : "en"}">
<head>
<meta charset="UTF-8"/>
<meta http-equiv="Content-Security-Policy" content="${csp}"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>TraceGuard Scope</title>
<style nonce="${nonce}">
  :root {
    --tg-radius: 6px;
    --tg-radius-sm: 4px;
    --tg-surface: color-mix(in srgb, var(--vscode-editor-background) 55%, var(--vscode-sideBar-background));
    --tg-border: color-mix(in srgb, var(--vscode-panel-border, var(--vscode-widget-border, #808080)) 55%, transparent);
    --tg-muted: var(--vscode-descriptionForeground);
    --tg-red: var(--vscode-errorForeground, #f14c4c);
    --tg-amber: var(--vscode-editorWarning-foreground, #cca700);
    --tg-blue: var(--vscode-editorInfo-foreground, #3794ff);
    --tg-green: var(--vscode-testing-iconPassed, #73c991);
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0;
    padding: 0;
    background: transparent;
    color: var(--vscode-foreground);
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size, 12px);
    line-height: 1.4;
    -webkit-font-smoothing: antialiased;
  }
  .root {
    padding: 8px 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .svg-icon {
    width: 14px;
    height: 14px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }
  .svg-icon svg { width: 100%; height: 100%; display: block; }

  /* Posture Card */
  .card {
    background: var(--tg-surface);
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius);
    padding: 10px;
    display: flex;
    flex-direction: column;
    gap: 9px;
  }
  .card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
  }
  .status-wrap {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }
  .status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
    background: var(--tg-green);
  }
  .status-dot.warn { background: var(--tg-amber); }
  .status-dot.error { background: var(--tg-red); }
  .status-dot.spin {
    background: var(--tg-blue);
    animation: pulse 1.2s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: .45; transform: scale(.82); }
  }
  .status-title {
    font-weight: 600;
    font-size: 11.5px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .status-meta {
    font-size: 10.5px;
    color: var(--tg-muted);
    white-space: nowrap;
  }
  .head-actions {
    display: flex;
    align-items: center;
    gap: 2px;
    flex-shrink: 0;
  }
  .icon-btn {
    border: none;
    background: transparent;
    color: var(--tg-muted);
    width: 22px;
    height: 22px;
    border-radius: var(--tg-radius-sm);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    padding: 0;
    transition: background .12s ease, color .12s ease;
  }
  .icon-btn:hover {
    background: var(--vscode-toolbar-hoverBackground, rgba(128,128,128,.16));
    color: var(--vscode-foreground);
  }
  .icon-btn:focus-visible {
    outline: 1px solid var(--vscode-focusBorder);
    outline-offset: -1px;
  }

  /* Progress Bars */
  .meters {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .meter-row {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .meter-labels {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 6px;
    font-size: 11px;
  }
  .meter-name {
    color: var(--tg-muted);
    white-space: nowrap;
  }
  .meter-val {
    font-variant-numeric: tabular-nums;
    font-weight: 500;
    font-size: 11px;
    white-space: nowrap;
  }
  .meter-val .pct {
    color: var(--tg-muted);
    margin-left: 3px;
    font-weight: 400;
  }
  .track {
    appearance: none;
    width: 100%;
    border: 0;
    height: 4px;
    border-radius: 99px;
    background: color-mix(in srgb, var(--vscode-foreground) 12%, transparent);
    overflow: hidden;
  }
  .track::-webkit-progress-bar { background: transparent; }
  .track.green::-webkit-progress-value { background: var(--tg-green); }
  .track.blue::-webkit-progress-value { background: var(--tg-blue); }
  .track.amber::-webkit-progress-value { background: var(--tg-amber); }

  /* 3 Metric Pills */
  .pills {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 6px;
  }
  .pill {
    appearance: none;
    border: 1px solid transparent;
    border-radius: var(--tg-radius-sm);
    padding: 6px 5px;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1px;
    text-align: center;
    background: color-mix(in srgb, var(--pill-color) 11%, transparent);
    border-color: color-mix(in srgb, var(--pill-color) 28%, transparent);
    color: var(--vscode-foreground);
    transition: transform .1s ease, background .14s ease, border-color .14s ease;
  }
  .pill:hover {
    background: color-mix(in srgb, var(--pill-color) 19%, transparent);
    border-color: color-mix(in srgb, var(--pill-color) 52%, transparent);
  }
  .pill.active {
    background: color-mix(in srgb, var(--pill-color) 24%, transparent);
    border-color: var(--pill-color);
    box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--pill-color) 35%, transparent);
  }
  .pill-verified { --pill-color: var(--tg-red); }
  .pill-hypothesis { --pill-color: var(--tg-amber); }
  .pill-endpoints { --pill-color: var(--tg-blue); }
  .pill-num {
    font-size: 14px;
    font-weight: 700;
    line-height: 1.15;
    font-variant-numeric: tabular-nums;
    color: var(--pill-color);
  }
  .pill-label {
    font-size: 10px;
    color: var(--tg-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 100%;
  }

  /* Live Search Input */
  .search-row {
    display: flex;
    align-items: center;
    gap: 4px;
    background: var(--vscode-input-background);
    border: 1px solid var(--vscode-input-border, var(--tg-border));
    border-radius: var(--tg-radius-sm);
    padding: 0 6px;
    height: 26px;
  }
  .search-row:focus-within {
    border-color: var(--vscode-focusBorder);
  }
  .search-row .svg-icon { color: var(--tg-muted); width: 13px; height: 13px; }
  .search-input {
    flex: 1;
    min-width: 0;
    border: none;
    outline: none;
    background: transparent;
    color: var(--vscode-input-foreground, var(--vscode-foreground));
    font-family: inherit;
    font-size: 11.5px;
    padding: 0;
  }
  .search-input::placeholder {
    color: var(--vscode-input-placeholderForeground, var(--tg-muted));
  }
  .clear-btn {
    width: 18px;
    height: 18px;
    display: none;
  }
  .clear-btn.visible { display: inline-flex; }

  .active-filter-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    font-size: 10.5px;
    color: var(--tg-muted);
    padding: 2px 2px 0;
  }
  .link-btn {
    border: none;
    background: transparent;
    color: var(--vscode-textLink-foreground, var(--tg-blue));
    font-size: 10.5px;
    cursor: pointer;
    padding: 0;
  }
  .link-btn:hover { text-decoration: underline; }

  .warn-strip {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 10.5px;
    padding: 5px 7px;
    border-radius: var(--tg-radius-sm);
    background: color-mix(in srgb, var(--tg-amber) 13%, transparent);
    border: 1px solid color-mix(in srgb, var(--tg-amber) 32%, transparent);
    color: var(--vscode-foreground);
  }
  .warn-strip.error {
    background: color-mix(in srgb, var(--tg-red) 14%, transparent);
    border-color: color-mix(in srgb, var(--tg-red) 35%, transparent);
  }

  /* Idle & Indexing States */
  .empty-card {
    background: var(--tg-surface);
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius);
    padding: 16px 12px;
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: 8px;
  }
  .emblem {
    width: 30px;
    height: 30px;
    border-radius: 8px;
    background: color-mix(in srgb, var(--tg-blue) 14%, transparent);
    color: var(--tg-blue);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .emblem svg { width: 18px; height: 18px; }
  .empty-title { font-weight: 600; font-size: 12.5px; }
  .empty-desc { color: var(--tg-muted); font-size: 11px; line-height: 1.45; }
  .primary-btn {
    width: 100%;
    border: none;
    border-radius: var(--tg-radius-sm);
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
    font-family: inherit;
    font-size: 12px;
    font-weight: 500;
    padding: 6px 10px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
  }
  .primary-btn:hover { background: var(--vscode-button-hoverBackground); }

  .indeterminate-track {
    width: 100%;
    height: 3px;
    border-radius: 99px;
    background: color-mix(in srgb, var(--vscode-foreground) 12%, transparent);
    overflow: hidden;
    position: relative;
  }
  .indeterminate-bar {
    position: absolute;
    inset: 0;
    width: 42%;
    border-radius: 99px;
    background: var(--tg-blue);
    animation: slide 1.15s ease-in-out infinite;
  }
  @keyframes slide {
    0% { transform: translateX(-110%); }
    100% { transform: translateX(260%); }
  }

  /* Collapsible Sections (Endpoints & Diagnostics) */
  .section {
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius);
    background: var(--tg-surface);
    overflow: hidden;
  }
  .section-head {
    width: 100%;
    border: none;
    background: transparent;
    color: var(--vscode-foreground);
    padding: 6px 8px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    cursor: pointer;
    font-family: inherit;
    font-size: 11px;
    font-weight: 600;
  }
  .section-head:hover { background: var(--vscode-list-hoverBackground); }
  .section-left { display: flex; align-items: center; gap: 5px; min-width: 0; }
  .chevron { transition: transform .15s ease; color: var(--tg-muted); }
  .section.open .chevron { transform: rotate(90deg); }
  .count-badge {
    font-size: 10px;
    font-weight: 600;
    padding: 0 5px;
    border-radius: 99px;
    background: var(--vscode-badge-background);
    color: var(--vscode-badge-foreground);
    font-variant-numeric: tabular-nums;
  }
  .section-body {
    display: none;
    border-top: 1px solid var(--tg-border);
    padding: 4px;
    max-height: 220px;
    overflow-y: auto;
  }
  .section.open .section-body { display: block; }

  .ep-row {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 4px 5px;
    border-radius: var(--tg-radius-sm);
    cursor: pointer;
  }
  .ep-row:hover { background: var(--vscode-list-hoverBackground); }
  .method-tag {
    font-size: 9.5px;
    font-weight: 700;
    letter-spacing: .02em;
    padding: 1px 4px;
    border-radius: 3px;
    flex-shrink: 0;
    min-width: 34px;
    text-align: center;
    background: color-mix(in srgb, var(--m-color) 16%, transparent);
    color: var(--m-color);
  }
  .method-GET { --m-color: var(--tg-blue); }
  .method-POST { --m-color: var(--tg-amber); }
  .method-PUT, .method-PATCH { --m-color: #b180d7; }
  .method-DELETE { --m-color: var(--tg-red); }
  .method-OTHER { --m-color: var(--tg-muted); }
  .ep-main {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
  }
  .ep-route {
    font-size: 11.5px;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .ep-loc {
    font-size: 10px;
    color: var(--tg-muted);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .flow-dot {
    font-size: 10px;
    font-weight: 700;
    padding: 0 5px;
    border-radius: 99px;
    background: color-mix(in srgb, var(--tg-red) 18%, transparent);
    color: var(--tg-red);
    font-variant-numeric: tabular-nums;
    flex-shrink: 0;
  }
  .ep-trace {
    opacity: 0;
    transition: opacity .12s ease;
  }
  .ep-row:hover .ep-trace, .ep-trace:focus-visible { opacity: 1; }

  .diag-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 4px 5px;
    font-size: 11px;
  }
  .diag-row {
    display: flex;
    justify-content: space-between;
    gap: 8px;
  }
  .diag-k { color: var(--tg-muted); }
  .diag-v { text-align: right; font-variant-numeric: tabular-nums; }
  .empty-mini {
    color: var(--tg-muted);
    font-size: 11px;
    padding: 8px 6px;
    text-align: center;
  }
</style>
</head>
<body>
  <div id="root" class="root"></div>
  <script nonce="${nonce}">
    (function() {
      const vscode = acquireVsCodeApi();
      const ICONS = ${safeJsonForHtml(SVG_ICONS)};
      let state = ${safeJsonForHtml(initialState)};
      let endpointsOpen = false;
      let endpointLimit = 60;
      let diagOpen = false;
      let searchTimer = null;

      const root = document.getElementById("root");

      function t(zh, en) { return state.locale === "zh" ? zh : en; }
      function esc(v) {
        return String(v ?? "")
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")
          .replaceAll('"', "&quot;")
          .replaceAll("'", "&#39;");
      }
      function icon(name) {
        return '<span class="svg-icon">' + (ICONS[name] || "") + "</span>";
      }
      function methodClass(method) {
        if (["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) return "method-" + method;
        return "method-OTHER";
      }

      function render() {
        const activeSearch = document.getElementById("tg-search");
        const hadFocus = activeSearch && document.activeElement === activeSearch;
        const selStart = hadFocus ? activeSearch.selectionStart : null;
        const selEnd = hadFocus ? activeSearch.selectionEnd : null;

        if (!state.indexed) {
          root.innerHTML = renderIdleOrIndexing();
          bindEvents();
          return;
        }

        const dotClass = state.indexError ? "error"
          : state.indexing ? "spin"
          : (state.indexStale || !state.coverageComplete || state.skippedFiles > 0) ? "warn"
          : "";
        const statusText = state.indexing
          ? t("正在索引…", "Indexing…")
          : state.indexError
            ? t("索引失败", "Index failed")
            : state.indexStale
              ? t("文件已变更", "Pending sync")
              : state.coverageComplete
                ? t("审计态势就绪", "Scope ready")
                : t("部分覆盖", "Partial scope");

        const queryLower = (state.searchQuery || "").toLowerCase();
        const filteredEndpoints = [];
        for (const group of state.endpointGroups || []) {
          for (const ep of group.items || []) {
            if (!queryLower || (ep.method + " " + ep.route + " " + ep.fileName + " " + ep.title + " " + ep.framework).toLowerCase().includes(queryLower)) {
              filteredEndpoints.push(ep);
            }
          }
        }

        const hasActiveFilter = (state.filterId && state.filterId !== "priority") || Boolean(state.searchQuery);
        const coverageFillClass = state.coverageComplete && !state.skippedFiles ? "blue" : "amber";

        const warnHtml = state.indexError
          ? '<div class="warn-strip error">' + esc(state.indexError) + "</div>"
          : (state.skippedFiles > 0 || state.partialPaths > 0)
            ? '<div class="warn-strip">'
              + (state.skippedFiles ? esc(t("跳过 " + state.skippedFiles + " 个文件", state.skippedFiles + " files skipped")) : "")
              + (state.skippedFiles && state.partialPaths ? " · " : "")
              + (state.partialPaths ? esc(t(state.partialPaths + " 条路径受预算截断", state.partialPaths + " partial paths")) : "")
              + "</div>"
            : "";

        root.innerHTML =
          '<div class="card">'
          + '<div class="card-head">'
          +   '<div class="status-wrap">'
          +     '<span class="status-dot ' + dotClass + '"></span>'
          +     '<span class="status-title">' + esc(statusText) + "</span>"
          +     '<span class="status-meta">' + esc(state.files + "f · " + state.functions + "fn") + "</span>"
          +   "</div>"
          +   '<div class="head-actions">'
          +     '<button class="icon-btn" id="btn-refresh" title="' + esc(t("刷新审计索引", "Refresh audit index")) + '">' + icon("refresh") + "</button>"
          +     '<button class="icon-btn" id="btn-config" title="' + esc(t("打开 .traceguard.json", "Open .traceguard.json")) + '">' + icon("settings") + "</button>"
          +   "</div>"
          + "</div>"

          + '<div class="meters">'
          +   '<div class="meter-row">'
          +     '<div class="meter-labels">'
          +       '<span class="meter-name">' + esc(t("人工审计进度", "Manual review")) + "</span>"
          +       '<span class="meter-val">' + state.manualReviewed + " / " + state.manualTotal + '<span class="pct">' + state.manualPercent + "%</span></span>"
          +     "</div>"
          +     '<progress class="track green" aria-label="' + esc(t("人工审计进度", "Manual review")) + '" max="100" value="' + state.manualPercent + '"></progress>'
          +   "</div>"
          +   '<div class="meter-row">'
          +     '<div class="meter-labels">'
          +       '<span class="meter-name">' + esc(t("索引覆盖率", "Index coverage")) + "</span>"
          +       '<span class="meter-val">' + state.files + " / " + state.discoveredFiles + '<span class="pct">' + state.coveragePercent + "%</span></span>"
          +     "</div>"
          +     '<progress class="track ' + coverageFillClass + '" aria-label="' + esc(t("索引覆盖率", "Index coverage")) + '" max="100" value="' + state.coveragePercent + '"></progress>'
          +   "</div>"
          + "</div>"

          + '<div class="pills">'
          +   '<button class="pill pill-verified' + (state.filterId === "verified" ? " active" : "") + '" data-pill="verified" title="' + esc(t("筛选已验证污点流", "Filter verified flows in Review Queue")) + '">'
          +     '<span class="pill-num">' + state.verifiedCount + "</span>"
          +     '<span class="pill-label">' + esc(t("已验证流", "Verified")) + "</span>"
          +   "</button>"
          +   '<button class="pill pill-hypothesis' + (state.filterId === "hypothesis" ? " active" : "") + '" data-pill="hypothesis" title="' + esc(t("筛选待确认假设", "Filter review hypotheses in Review Queue")) + '">'
          +     '<span class="pill-num">' + state.hypothesisCount + "</span>"
          +     '<span class="pill-label">' + esc(t("待复核", "Hypothesis")) + "</span>"
          +   "</button>"
          +   '<button class="pill pill-endpoints' + (state.filterId === "reachable" ? " active" : "") + '" data-pill="reachable" title="' + esc(t("查看接口入口并筛选可达目标", "View endpoints & filter reachable targets")) + '">'
          +     '<span class="pill-num">' + state.endpointsCount + "</span>"
          +     '<span class="pill-label">' + esc(t("接口入口", "Endpoints")) + "</span>"
          +   "</button>"
          + "</div>"

          + '<div class="search-row">'
          +   icon("search")
          +   '<input id="tg-search" class="search-input" type="text" value="' + esc(state.searchQuery) + '" placeholder="' + esc(t("即时筛选目标、漏洞或路由…", "Filter queue, flows, routes…")) + '"/>'
          +   '<button id="btn-clear-search" class="icon-btn clear-btn' + (state.searchQuery ? " visible" : "") + '" title="' + esc(t("清除搜索", "Clear")) + '">' + icon("clear") + "</button>"
          + "</div>"

          + (hasActiveFilter
            ? '<div class="active-filter-bar"><span>' + esc(t("当前筛选：", "Active: ") + state.filterLabel) + '</span><button class="link-btn" id="btn-reset-filter">' + esc(t("重置", "Reset")) + "</button></div>"
            : "")
          + warnHtml
          + "</div>"

          + renderEndpointsSection(filteredEndpoints)
          + renderDiagnosticsSection();

        bindEvents();

        if (hadFocus) {
          const nextSearch = document.getElementById("tg-search");
          if (nextSearch) {
            nextSearch.focus();
            if (selStart !== null && selEnd !== null) nextSearch.setSelectionRange(selStart, selEnd);
          }
        }
      }

      function renderIdleOrIndexing() {
        if (state.indexing) {
          return '<div class="empty-card">'
            + '<div class="emblem">' + icon("shield") + "</div>"
            + '<div class="empty-title">' + esc(t("正在构建白盒审计视图", "Building audit scope")) + "</div>"
            + '<div class="empty-desc">' + esc(state.indexStageMessage) + "</div>"
            + '<div class="indeterminate-track"><div class="indeterminate-bar"></div></div>'
            + "</div>";
        }
        return '<div class="empty-card">'
          + '<div class="emblem">' + icon("shield") + "</div>"
          + '<div class="empty-title">' + esc(t("TraceGuard 白盒代码审计", "TraceGuard Audit Scope")) + "</div>"
          + '<div class="empty-desc">' + esc(t("梳理框架入口、建立跨文件污点索引并生成人工审计优先级队列。", "Inventory framework endpoints, index cross-file data flows, and build a prioritized review queue.")) + "</div>"
          + (state.indexError ? '<div class="warn-strip error" style="width:100%;text-align:left">' + esc(state.indexError) + "</div>" : "")
          + '<button class="primary-btn" id="btn-start">' + icon("play") + "<span>" + esc(t("开始构建审计索引", "Build Audit Scope")) + "</span></button>"
          + "</div>";
      }

      function renderEndpointsSection(endpoints) {
        const listHtml = endpoints.length
          ? endpoints.slice(0, endpointLimit).map(ep =>
              '<div class="ep-row" data-open-ep="' + esc(ep.id) + '" data-path="' + esc(ep.absolutePath) + '" data-line="' + ep.line + '" data-endline="' + ep.endLine + '" data-title="' + esc(ep.title) + '" data-route="' + esc(ep.route) + '" title="' + esc(ep.method + " " + ep.route + " (" + ep.relativePath + ":" + ep.line + ")") + '">'
              + '<span class="method-tag ' + methodClass(ep.method) + '">' + esc(ep.method.slice(0, 6)) + "</span>"
              + '<div class="ep-main">'
              +   '<span class="ep-route">' + esc(ep.route) + "</span>"
              +   '<span class="ep-loc">' + esc(ep.fileName + ":" + ep.line + (ep.framework ? " · " + ep.framework : "")) + "</span>"
              + "</div>"
              + (ep.openFlows ? '<span class="flow-dot" title="' + esc(ep.openFlows + " open flows") + '">' + ep.openFlows + "</span>" : "")
              + '<button class="icon-btn ep-trace" data-trace-ep="1" title="' + esc(t("从此入口追踪污点流", "Trace from this entry")) + '">' + icon("source") + "</button>"
              + "</div>"
            ).join("")
          : '<div class="empty-mini">' + esc(t("未匹配到框架入口", "No matching endpoints indexed")) + "</div>";

        return '<div class="section' + (endpointsOpen ? " open" : "") + '" id="sec-endpoints">'
          + '<button class="section-head" data-toggle="endpoints">'
          +   '<span class="section-left"><span class="svg-icon chevron">' + ICONS.chevron + "</span>" + icon("globe") + "<span>" + esc(t("攻击面入口", "Endpoints")) + "</span></span>"
          +   '<span class="count-badge">' + endpoints.length + "</span>"
          + "</button>"
          + '<div class="section-body">' + listHtml
          + (endpoints.length > endpointLimit ? '<button id="more-endpoints" class="primary-btn">' + esc(t("显示更多入口", "Show more endpoints")) + "</button>" : "") + "</div>"
          + "</div>";
      }

      function renderDiagnosticsSection() {
        const d = state.diagnostics || {};
        const langs = (d.languages || []).join(", ") || "—";
        const modelsLabel = (d.semanticModels || 0) + (d.temporaryModels ? " (+" + d.temporaryModels + " temp)" : "");
        return '<div class="section' + (diagOpen ? " open" : "") + '" id="sec-diag">'
          + '<button class="section-head" data-toggle="diag">'
          +   '<span class="section-left"><span class="svg-icon chevron">' + ICONS.chevron + "</span><span>" + esc(t("索引诊断与模型", "Diagnostics & Models")) + "</span></span>"
          +   '<span class="count-badge">' + (d.languages || []).length + "</span>"
          + "</button>"
          + '<div class="section-body"><div class="diag-list">'
          +   '<div class="diag-row"><span class="diag-k">' + esc(t("语言", "Languages")) + '</span><span class="diag-v">' + esc(langs) + "</span></div>"
          +   '<div class="diag-row"><span class="diag-k">' + esc(t("自定义语义模型", "Semantic models")) + '</span><span class="diag-v">' + esc(modelsLabel) + "</span></div>"
          +   (d.temporaryModels ? '<div class="diag-row"><span class="diag-k"></span><button class="link-btn" id="btn-clear-temp">' + esc(t("清除临时模型", "Clear temporary models")) + "</button></div>" : "")
          +   (d.degradedReasons && d.degradedReasons.length ? '<div class="warn-strip">' + esc(d.degradedReasons.join("; ")) + "</div>" : "")
          + "</div></div>"
          + "</div>";
      }

      function bindEvents() {
        const startBtn = document.getElementById("btn-start");
        if (startBtn) startBtn.addEventListener("click", () => vscode.postMessage({ type: "startAudit" }));

        const refreshBtn = document.getElementById("btn-refresh");
        if (refreshBtn) refreshBtn.addEventListener("click", () => vscode.postMessage({ type: "refreshAudit" }));

        const configBtn = document.getElementById("btn-config");
        if (configBtn) configBtn.addEventListener("click", () => vscode.postMessage({ type: "openConfig" }));

        const clearTempBtn = document.getElementById("btn-clear-temp");
        if (clearTempBtn) clearTempBtn.addEventListener("click", () => vscode.postMessage({ type: "clearTempModels" }));

        const resetFilter = document.getElementById("btn-reset-filter");
        if (resetFilter) resetFilter.addEventListener("click", () => vscode.postMessage({ type: "clearFilter" }));

        for (const pill of document.querySelectorAll("[data-pill]")) {
          pill.addEventListener("click", () => {
            const id = pill.getAttribute("data-pill");
            if (id === "reachable") endpointsOpen = true;
            vscode.postMessage({ type: "setFilterPill", filterId: id });
          });
        }

        const search = document.getElementById("tg-search");
        const clearSearch = document.getElementById("btn-clear-search");
        if (search) {
          search.addEventListener("input", () => {
            const val = search.value;
            state.searchQuery = val;
            endpointLimit = 60;
            if (val) endpointsOpen = true;
            render();
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => {
              searchTimer = null;
              vscode.postMessage({ type: "setSearchQuery", query: val });
            }, 110);
          });
        }
        if (clearSearch) {
          clearSearch.addEventListener("click", () => {
            clearTimeout(searchTimer);
            searchTimer = null;
            state.searchQuery = "";
            if (search) search.value = "";
            clearSearch.classList.remove("visible");
            vscode.postMessage({ type: "setSearchQuery", query: "" });
            render();
          });
        }

        document.getElementById("more-endpoints")?.addEventListener("click", () => {
          endpointLimit += 60;
          render();
        });
        for (const toggle of document.querySelectorAll("[data-toggle]")) {
          toggle.addEventListener("click", () => {
            const kind = toggle.getAttribute("data-toggle");
            if (kind === "endpoints") endpointsOpen = !endpointsOpen;
            if (kind === "diag") diagOpen = !diagOpen;
            render();
          });
        }

        for (const row of document.querySelectorAll("[data-open-ep]")) {
          row.addEventListener("click", event => {
            const traceBtn = event.target.closest("[data-trace-ep]");
            const payload = {
              absolutePath: row.getAttribute("data-path"),
              line: Number(row.getAttribute("data-line")) || 1,
              endLine: Number(row.getAttribute("data-endline")) || 1,
              title: row.getAttribute("data-title") || "",
              route: row.getAttribute("data-route") || "",
            };
            vscode.postMessage({ type: traceBtn ? "traceEndpoint" : "openEndpoint", ...payload });
          });
        }
      }

      window.addEventListener("message", event => {
        const msg = event.data;
        if (msg && msg.type === "state" && msg.state) {
          if (searchTimer) msg.state.searchQuery = state.searchQuery;
          state = msg.state;
          render();
        }
      });

      render();
      vscode.postMessage({ type: "ready" });
    })();
  </script>
</body>
</html>`;
  }

  dispose() {
    clearTimeout(this._refreshTimer);
    this._subscription?.dispose();
  }
}

module.exports = { ScopeViewProvider, buildScopeViewState };
