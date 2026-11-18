"use strict";

const path = require("node:path");
const vscode = require("vscode");
const { findingPaths, findingPool, pathVerificationStatus } = require("../../review/finding-pool");
const {
  findingStatusLabel,
  humanizeStepLabel,
  queryNodeInterruption,
  stepAnalysisStatus,
  traceInterruption,
} = require("../../audit-providers");
const { callDetailsAtPosition, selectedCallName } = require("../../config/interactive-model");
const { languageForPath } = require("../../language-support");
const { normalizePath } = require("../../identity");
const {
  SVG_ICONS,
  buildCsp,
  createNonce,
  isChineseLocale,
  readCodeSnippet,
  renderMarkdownToHtml,
  safeJsonForHtml,
} = require("./webview-utils");

const SINK_OPTIONS = [
  { kind: "SQL_QUERY", label: "SQL query" },
  { kind: "COMMAND_EXEC", label: "Command execution" },
  { kind: "DYNAMIC_EXEC", label: "Dynamic execution" },
  { kind: "FILE_ACCESS", label: "File access" },
  { kind: "HTTP_REQUEST", label: "Outbound HTTP request" },
  { kind: "REDIRECT", label: "Redirect" },
  { kind: "RESPONSE_OUTPUT", label: "Response output" },
  { kind: "DESERIALIZATION", label: "Deserialization" },
  { kind: "DIRECTORY_LOOKUP", label: "Directory lookup" },
  { kind: "LDAP_QUERY", label: "LDAP filter" },
  { kind: "TEMPLATE_RENDER", label: "Template render" },
  { kind: "SENSITIVE_OPERATION", label: "Sensitive operation" },
];

const SANITIZER_OPTIONS = [
  { kind: "SQL_PARAMETERIZATION", label: "SQL parameterization" },
  { kind: "SHELL_ESCAPE", label: "Shell argument escaping" },
  { kind: "OUTPUT_ENCODING", label: "Output encoding" },
  { kind: "PATH_CONFINEMENT", label: "Path confinement" },
  { kind: "PATH_CANONICALIZATION", label: "Path canonicalization" },
  { kind: "URL_POLICY", label: "URL policy" },
  { kind: "LDAP_FILTER_ESCAPE", label: "LDAP filter escaping" },
  { kind: "DESERIALIZATION_ALLOWLIST", label: "Deserialization allowlist" },
  { kind: "INPUT_VALIDATION", label: "General input validation" },
];

const SOURCE_OPTIONS = [
  { kind: "HTTP_INPUT", label: "HTTP input" },
  { kind: "EXTERNAL_INPUT", label: "External input" },
  { kind: "PROCESS_INPUT", label: "Process / env input" },
  { kind: "FILE_UPLOAD", label: "File upload" },
];

const NOTE_TYPES = [
  "Controllability",
  "Exploit Condition",
  "Missing Context",
  "False Positive Reason",
  "Authorization",
  "Validation",
  "Remediation",
  "Observation",
];

function extractCallMetadata(targetLineText, fallbackLabel) {
  const line = String(targetLineText || "");
  const details = callDetailsAtPosition(line, 0) || callDetailsAtPosition(line, Math.floor(line.length / 2));
  const fallbackName = selectedCallName(fallbackLabel || line);
  return {
    functionName: details?.functionName || fallbackName || "",
    arguments: details?.arguments || [],
  };
}

async function buildTraceInspectorState(input, options = {}) {
  const {
    finding,
    flowPath,
    pathIndex = 0,
    cursor = 0,
    queryResult,
    isReviewed = () => false,
    evidence = [],
    language = "en",
    readOpenDocument,
  } = { ...input, ...options };

  const zh = isChineseLocale(language);
  const paths = finding ? findingPaths(finding) : (flowPath ? [flowPath] : []);
  const activeFlow = flowPath || paths[Math.max(0, Math.min(pathIndex, Math.max(0, paths.length - 1)))];

  const snippetCache = new Map();
  const getSnippet = async (absolutePath, line) => {
    if (!absolutePath || !line) return undefined;
    const key = `${absolutePath}:${line}`;
    if (!snippetCache.has(key)) {
      snippetCache.set(key, await readCodeSnippet(absolutePath, line, 1, readOpenDocument));
    }
    return snippetCache.get(key);
  };

  let mode = "empty";
  let title = zh ? "尚未选择污点链路" : "No active trace selected";
  let subtitle = "";
  let pool = "";
  let severity = "";
  let cwe = "";
  let confidence = "";
  let findingStatus = "";
  let findingId = "";
  let observedGuards = [];
  let missingGuards = [];
  let pathSummaries = [];
  let timelineSteps = [];
  let interruption = undefined;
  const touchedFiles = new Set();

  if (activeFlow?.steps?.length) {
    mode = finding ? "finding" : "trace";
    const steps = activeFlow.steps || [];
    const sourceStep = steps.find(s => s.kind === "source") || activeFlow.source;
    const sinkStep = [...steps].reverse().find(s => s.kind === "sink") || activeFlow.sink;
    if (finding) {
      findingId = finding.id;
      pool = findingPool(finding);
      severity = String(finding.severity || "medium").toLowerCase();
      cwe = finding.cwe || "";
      confidence = finding.confidence || "";
      findingStatus = finding.status || "open";
      title = finding.title || `${humanizeStepLabel(sourceStep)} → ${humanizeStepLabel(sinkStep)}`;
      subtitle = `${finding.sourceKind || "Source"} → ${finding.sinkKind || "Sink"}`;
      observedGuards = finding.observedGuards || [];
      missingGuards = finding.missingGuards || [];
      pathSummaries = paths.map((candidate, idx) => ({
        index: idx,
        status: pathVerificationStatus(candidate),
        steps: (candidate.steps || []).length,
      }));
    } else {
      pool = pathVerificationStatus(activeFlow);
      title = `${humanizeStepLabel(sourceStep) || "Source"} → ${humanizeStepLabel(sinkStep) || "Sink"}`;
      subtitle = `${steps.length} ${zh ? "步" : "steps"}`;
    }

    for (let index = 0; index < steps.length; index += 1) {
      const step = steps[index];
      if (step.absolutePath) touchedFiles.add(normalizePath(step.absolutePath));
      const snippet = await getSnippet(step.absolutePath, step.line);
      const status = stepAnalysisStatus(step);
      timelineSteps.push({
        kind: "trace-step",
        index,
        depth: 0,
        active: index === cursor,
        role: String(step.kind || "flow").toLowerCase(),
        label: humanizeStepLabel(step) || step.label || "Step",
        rawLabel: step.label || "",
        functionName: step.functionName || "",
        status,
        fileName: path.basename(step.relativePath || step.absolutePath || "unknown"),
        relativePath: step.relativePath || "",
        absolutePath: step.absolutePath || "",
        line: Number(step.line) || 1,
        code: step.code || "",
        snippet: snippet?.lines || (step.code ? [{ number: Number(step.line) || 1, text: step.code, active: true }] : []),
        reason: step.candidateReason || step.reason || "",
        reviewed: Boolean(isReviewed(step)),
      });
    }

    const rawInterruption = traceInterruption(activeFlow);
    if (rawInterruption) {
      const loc = rawInterruption.location || {};
      const snippet = await getSnippet(loc.absolutePath, loc.line);
      const callMeta = extractCallMetadata(snippet?.targetLineText || loc.code, loc.label);
      interruption = {
        status: rawInterruption.status,
        modelable: Boolean(loc.absolutePath && rawInterruption.status !== "partial"),
        reason: rawInterruption.reason,
        next: rawInterruption.next,
        fileName: path.basename(loc.relativePath || loc.absolutePath || "unknown"),
        relativePath: loc.relativePath || "",
        absolutePath: loc.absolutePath || "",
        line: Number(loc.line) || 1,
        language: languageForPath(loc.absolutePath || "") || "",
        functionName: callMeta.functionName,
        arguments: callMeta.arguments,
      };
    }
  } else if (queryResult?.roots?.length) {
    mode = "query";
    title = queryResult.title || (zh ? "交互式分析查询" : "Interactive Audit Query");
    subtitle = queryResult.truncated
      ? (zh ? "已达到节点预算上限（部分结果）" : "Truncated at configured node budget")
      : `${queryResult.kind || "query"}`;

    let seq = 0;
    const flattenNodes = async (nodes, depth, inheritedReviewed) => {
      for (const node of nodes || []) {
        if (seq >= 80) break;
        const loc = node.location || {};
        if (loc.absolutePath) touchedFiles.add(normalizePath(loc.absolutePath));
        const snippet = await getSnippet(loc.absolutePath, loc.line);
        const reviewed = inheritedReviewed || Boolean(isReviewed(node));
        const nodeIndex = seq++;
        const nodeInterruption = queryNodeInterruption(node);
        let inlineInterruption;
        if (nodeInterruption) {
          const callMeta = extractCallMetadata(snippet?.targetLineText || loc.code, node.label);
          inlineInterruption = {
            status: nodeInterruption.status,
            modelable: Boolean(loc.absolutePath && nodeInterruption.status !== "partial"),
            reason: nodeInterruption.reason,
            next: nodeInterruption.next,
            fileName: path.basename(loc.relativePath || loc.absolutePath || "unknown"),
            relativePath: loc.relativePath || "",
            absolutePath: loc.absolutePath || "",
            line: Number(loc.line) || 1,
            language: languageForPath(loc.absolutePath || "") || "",
            functionName: callMeta.functionName,
            arguments: callMeta.arguments,
          };
        }
        timelineSteps.push({
          kind: "query-node",
          index: nodeIndex,
          nodeId: node.id || `q-${nodeIndex}`,
          depth,
          active: nodeIndex === cursor,
          role: String(node.kind || "flow").toLowerCase(),
          label: humanizeStepLabel(node) || node.label || "Step",
          rawLabel: node.label || "",
          functionName: node.details?.functionName || "",
          status: node.status || "heuristic",
          fileName: loc.relativePath || loc.absolutePath ? path.basename(loc.relativePath || loc.absolutePath) : "",
          relativePath: loc.relativePath || "",
          absolutePath: loc.absolutePath || "",
          line: Number(loc.line) || 0,
          code: loc.code || "",
          snippet: snippet?.lines || (loc.code ? [{ number: Number(loc.line) || 1, text: loc.code, active: true }] : []),
          reason: node.reason || "",
          reviewed,
          inheritedReview: inheritedReviewed,
          interruption: inlineInterruption,
        });
        await flattenNodes(node.children || [], Math.min(depth + 1, 5), reviewed);
      }
    };
    await flattenNodes(queryResult.roots, 0, false);
  }

  const relevantNotes = (evidence || [])
    .filter(item => !touchedFiles.size || touchedFiles.has(normalizePath(item.absolutePath || "")))
    .slice(0, 30)
    .map(item => ({
      id: item.id,
      type: item.type,
      note: item.note || "",
      code: item.code || "",
      fileName: path.basename(item.relativePath || item.absolutePath || "unknown"),
      relativePath: item.relativePath || "",
      absolutePath: item.absolutePath || "",
      line: Number(item.line) || 1,
      stale: item.locationStatus === "stale",
    }));

  const activeStep = timelineSteps.find(step => step.active) || timelineSteps[0];

  return {
    locale: zh ? "zh" : "en",
    mode,
    findingId,
    pool,
    severity,
    cwe,
    confidence,
    findingStatus,
    findingStatusLabel: findingStatus ? findingStatusLabel(findingStatus) : "",
    title,
    subtitle,
    observedGuards,
    missingGuards,
    pathIndex,
    pathSummaries,
    cursor,
    stepCount: timelineSteps.length,
    steps: timelineSteps,
    interruption,
    activeStep: activeStep ? {
      fileName: activeStep.fileName,
      relativePath: activeStep.relativePath,
      absolutePath: activeStep.absolutePath,
      line: activeStep.line,
      code: activeStep.code || activeStep.snippet?.find(l => l.active)?.text || "",
    } : undefined,
    notes: relevantNotes,
    catalogs: {
      sinks: SINK_OPTIONS,
      sanitizers: SANITIZER_OPTIONS,
      sources: SOURCE_OPTIONS,
      noteTypes: NOTE_TYPES,
    },
  };
}

class TraceInspectorPanel {
  constructor(context, controller) {
    this.context = context;
    this.controller = controller;
    this._panel = undefined;
    this._findingId = undefined;
    this._pathIndex = 0;
    this._queryNodeMap = new Map();
    this._refreshVersion = 0;
    this._sessionSub = controller.session.onDidChange(() => {
      if (this._panel) void this.refresh();
    });
  }

  get isOpen() {
    return Boolean(this._panel);
  }

  bindAiEvents(aiController) {
    this._startSub = aiController.onDidStartReport(uri => this._postAiUpdate(uri, true));
    this._aiSub = aiController.provider.onDidChange(uri => this._postAiUpdate(uri, false));
  }

  _reportUri() {
    const query = this.controller.queryProvider;
    return this.controller.ai?.provider.latestByChain.get(query.current || query.currentTrace);
  }

  _reportView() {
    const entry = this.controller.ai?.provider.reports.get(this._reportUri());
    if (!entry) return { ...this._safeAiSettings(), status: "idle", markdown: "", html: "" };
    return {
      status: entry.outcome, statusText: entry.status, model: entry.model, endpointHost: entry.endpointHost,
      markdown: entry.text, html: renderMarkdownToHtml(entry.text), uriString: entry.uri.toString(),
    };
  }

  _postAiUpdate(uri, switchTab) {
    if (this._panel && uri.toString() === this._reportUri()) {
      void this._panel.webview.postMessage({ type: "ai", switchTab, ai: this._reportView() });
    }
  }

  async show({ finding, pathIndex = 0, preserveFocus = true } = {}) {
    if (finding?.id) {
      this._findingId = finding.id;
      this._pathIndex = pathIndex;
    } else if (finding === null) {
      this._findingId = undefined;
      this._pathIndex = 0;
    }
    this._ensurePanel(preserveFocus);
    await this.refresh();
  }

  setContext({ finding, pathIndex } = {}) {
    if (finding !== undefined) this._findingId = finding?.id;
    if (pathIndex !== undefined) this._pathIndex = pathIndex;
  }

  _ensurePanel(preserveFocus) {
    if (this._panel) {
      this._panel.reveal(vscode.ViewColumn.Beside, preserveFocus);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "traceguard.traceInspector",
      "TraceGuard Inspector",
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus },
      { enableScripts: true, retainContextWhenHidden: true, localResourceRoots: [] },
    );
    this._panel = panel;
    panel.webview.html = this._buildHtml(panel.webview);
    panel.onDidDispose(() => {
      if (this._panel === panel) this._panel = undefined;
    });
    panel.webview.onDidReceiveMessage(message => {
      void this._handleMessage(message);
    });
  }

  async refresh() {
    if (!this._panel) return;
    const panel = this._panel;
    const version = ++this._refreshVersion;
    const snapshot = this.controller.session.snapshot;
    const finding = this._findingId
      ? (snapshot.findings || []).find(item => item.id === this._findingId)
      : undefined;
    const flowPath = this.controller.queryProvider.currentTrace;
    const queryResult = this.controller.queryProvider.current;
    const cursor = this.controller.queryProvider.traceCursor || 0;

    const queryNodeMap = new Map();
    if (queryResult?.roots?.length) {
      let seq = 0;
      const collect = nodes => {
        for (const node of nodes || []) {
          if (seq >= 80) break;
          const id = node.id || `q-${seq}`;
          queryNodeMap.set(id, node);
          seq += 1;
          collect(node.children || []);
        }
      };
      collect(queryResult.roots);
    }

    const state = await buildTraceInspectorState({
      finding,
      flowPath,
      pathIndex: this._pathIndex,
      cursor,
      queryResult,
      isReviewed: node => this.controller.queryProvider.isReviewed(node),
      evidence: snapshot.evidence || [],
      language: vscode.env?.language,
      readOpenDocument: async absPath => {
        const normalized = normalizePath(absPath);
        const openDoc = vscode.workspace.textDocuments.find(doc => normalizePath(doc.uri.fsPath) === normalized);
        return openDoc ? openDoc.getText() : undefined;
      },
    });

    if (panel === this._panel && version === this._refreshVersion) {
      this._queryNodeMap = queryNodeMap;
      state.ai = this._reportView();
      const shortTitle = state.mode === "empty" ? "TraceGuard Inspector" : `Inspector · ${state.title.slice(0, 32)}`;
      this._panel.title = shortTitle;
      void this._panel.webview.postMessage({ type: "state", state });
    }
  }

  _safeAiSettings() {
    try {
      const settings = this.controller.ai?.settings?.();
      if (!settings) return { model: "", endpointHost: "" };
      let host = settings.baseUrl || "";
      try { host = new URL(settings.endpoint).host; } catch {}
      return { model: settings.model || "", endpointHost: host };
    } catch {
      return { model: "", endpointHost: "" };
    }
  }

  async _handleMessage(message) {
    if (!message || typeof message !== "object") return;
    switch (message.type) {
      case "ready":
        await this.refresh();
        break;
      case "selectStep":
        if (message.kind === "trace-step") {
          await this.controller.selectTraceStep(Number(message.index) || 0);
          await this.refresh();
        } else if (message.kind === "query-node") {
          const node = this._queryNodeMap.get(message.nodeId);
          if (node) await this.controller.selectQueryNode(node);
        }
        break;
      case "prevStep":
        await this.controller.moveTraceStep(-1);
        await this.refresh();
        break;
      case "nextStep":
        await this.controller.moveTraceStep(1);
        await this.refresh();
        break;
      case "clearHighlights":
        this.controller.clearTraceHighlights();
        break;
      case "switchPath": {
        const snapshot = this.controller.session.snapshot;
        const finding = this._findingId ? snapshot.findings.find(item => item.id === this._findingId) : undefined;
        const paths = finding ? findingPaths(finding) : [];
        const idx = Math.max(0, Math.min(paths.length - 1, Number(message.pathIndex) || 0));
        if (paths[idx]) {
          this._pathIndex = idx;
          await this.controller.startInteractiveTrace(paths[idx], { finding, pathIndex: idx, preserveFocus: true });
        }
        break;
      }
      case "setFindingStatus":
        if (this._findingId && message.status) {
          await this.controller.session.setFindingStatus(this._findingId, message.status);
          await this.refresh();
        }
        break;
      case "toggleStepReviewed": {
        if (message.kind === "trace-step") {
          const step = this.controller.queryProvider.currentTrace?.steps?.[Number(message.index)];
          if (step) await this.controller.toggleTraceReviewed({ step });
        } else if (message.kind === "query-node") {
          const node = this._queryNodeMap.get(message.nodeId);
          if (node) await this.controller.toggleTraceReviewed({ node });
        }
        await this.refresh();
        break;
      }
      case "openLocation":
        if (message.absolutePath) {
          await vscode.commands.executeCommand("traceguard.openAuditLocation", {
            absolutePath: message.absolutePath,
            line: Number(message.line) || 1,
            endLine: Number(message.line) || 1,
          });
        }
        break;
      case "inspectCallees":
        if (message.absolutePath) {
          await vscode.commands.executeCommand("traceguard.openAuditLocation", {
            absolutePath: message.absolutePath,
            line: Number(message.line) || 1,
            endLine: Number(message.line) || 1,
          });
          await vscode.commands.executeCommand("traceguard.findCallees");
        }
        break;
      case "saveModel": {
        const result = await this.controller.saveSemanticModelFromInspector(message.payload || {});
        if (this._panel) {
          void this._panel.webview.postMessage({ type: "modelSaved", ...result });
        }
        if (result?.ok) await this.refresh();
        break;
      }
      case "saveNote": {
        const result = await this.controller.addNoteFromInspector(message.payload || {});
        if (this._panel) {
          void this._panel.webview.postMessage({ type: "noteSaved", ...result });
        }
        if (result?.ok) await this.refresh();
        break;
      }
      case "removeNote":
        if (message.id) {
          await this.controller.session.removeEvidence(message.id);
          await this.refresh();
        }
        break;
      case "openNote":
        if (message.id) await this.controller.openEvidenceById(message.id);
        break;
      case "verifyAi":
        if (this.controller.ai) {
          void this.controller.ai.verify(undefined, { openDocument: false });
        }
        break;
      case "stopAi":
        if (message.uriString === this._reportUri()) this.controller.ai?.cancelReport(message.uriString);
        break;
      case "copyAiPrompt":
        await vscode.commands.executeCommand("traceguard.copyAiPrompt");
        break;
      case "copyMarkdown":
        await vscode.commands.executeCommand("traceguard.copyAuditQueryMarkdown");
        break;
      case "copyText":
        if (typeof message.text === "string") {
          await vscode.env.clipboard.writeText(message.text);
          vscode.window.setStatusBarMessage("$(copy) Copied to clipboard", 2000);
        }
        break;
      case "openRawAiReport":
        if (message.uriString && message.uriString === this._reportUri()) {
          try {
            const doc = await vscode.workspace.openTextDocument(vscode.Uri.parse(message.uriString));
            await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.Beside, preview: true });
          } catch {}
        }
        break;
      case "setAiApiKey":
        await vscode.commands.executeCommand("traceguard.setAiApiKey");
        break;
      default:
        break;
    }
  }

  _buildHtml(webview) {
    const nonce = createNonce();
    const csp = buildCsp(webview, nonce);
    const zh = isChineseLocale(vscode.env?.language);
    return `<!DOCTYPE html>
<html lang="${zh ? "zh-CN" : "en"}">
<head>
<meta charset="UTF-8"/>
<meta http-equiv="Content-Security-Policy" content="${csp}"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>TraceGuard Inspector</title>
<style nonce="${nonce}">
  :root {
    --tg-bg: var(--vscode-editor-background);
    --tg-surface: color-mix(in srgb, var(--vscode-sideBar-background, var(--vscode-editor-background)) 70%, var(--vscode-editor-background));
    --tg-card: color-mix(in srgb, var(--vscode-editorWidget-background, var(--vscode-sideBar-background)) 72%, var(--vscode-editor-background));
    --tg-border: color-mix(in srgb, var(--vscode-panel-border, var(--vscode-widget-border, #808080)) 55%, transparent);
    --tg-muted: var(--vscode-descriptionForeground);
    --tg-red: var(--vscode-errorForeground, #f14c4c);
    --tg-amber: var(--vscode-editorWarning-foreground, #cca700);
    --tg-blue: var(--vscode-editorInfo-foreground, #3794ff);
    --tg-green: var(--vscode-testing-iconPassed, #73c991);
    --tg-purple: #b180d7;
    --tg-mono: var(--vscode-editor-font-family, Consolas, "Courier New", monospace);
    --tg-radius: 7px;
    --tg-radius-sm: 4px;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0;
    padding: 0;
    background: var(--tg-bg);
    color: var(--vscode-foreground);
    font-family: var(--vscode-font-family);
    font-size: var(--vscode-font-size, 13px);
    line-height: 1.45;
    -webkit-font-smoothing: antialiased;
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

  .shell {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }

  /* Sticky Overview Header */
  .header {
    position: sticky;
    top: 0;
    z-index: 20;
    background: color-mix(in srgb, var(--tg-bg) 94%, transparent);
    backdrop-filter: blur(8px);
    border-bottom: 1px solid var(--tg-border);
    padding: 12px 16px 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .badges-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 10.5px;
    font-weight: 600;
    letter-spacing: .02em;
    padding: 2px 7px;
    border-radius: 99px;
    background: color-mix(in srgb, var(--b-color, var(--tg-muted)) 15%, transparent);
    border: 1px solid color-mix(in srgb, var(--b-color, var(--tg-muted)) 34%, transparent);
    color: var(--b-color, var(--vscode-foreground));
  }
  .badge-red { --b-color: var(--tg-red); }
  .badge-amber { --b-color: var(--tg-amber); }
  .badge-blue { --b-color: var(--tg-blue); }
  .badge-green { --b-color: var(--tg-green); }
  .badge-purple { --b-color: var(--tg-purple); }
  .badge-neutral { --b-color: var(--tg-muted); color: var(--vscode-foreground); }

  .title-block { display: flex; flex-direction: column; gap: 2px; }
  .main-title {
    margin: 0;
    font-size: 15px;
    font-weight: 650;
    line-height: 1.3;
    word-break: break-word;
  }
  .sub-title {
    font-size: 11.5px;
    color: var(--tg-muted);
    font-family: var(--tg-mono);
  }

  .guards-row {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
  }
  .guard-chip {
    font-size: 10.5px;
    padding: 2px 7px;
    border-radius: var(--tg-radius-sm);
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .guard-ok {
    background: color-mix(in srgb, var(--tg-green) 12%, transparent);
    border: 1px solid color-mix(in srgb, var(--tg-green) 32%, transparent);
    color: var(--tg-green);
  }
  .guard-miss {
    background: color-mix(in srgb, var(--tg-amber) 10%, transparent);
    border: 1px dashed color-mix(in srgb, var(--tg-amber) 45%, transparent);
    color: var(--tg-amber);
  }

  /* Action Bar */
  .actions-bar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
  }
  .btn-group {
    display: inline-flex;
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius-sm);
    overflow: hidden;
  }
  .btn-group .btn {
    border: none;
    border-radius: 0;
    border-right: 1px solid var(--tg-border);
  }
  .btn-group .btn:last-child { border-right: none; }

  .btn {
    appearance: none;
    border: 1px solid var(--tg-border);
    background: var(--tg-card);
    color: var(--vscode-foreground);
    font-family: inherit;
    font-size: 11.5px;
    font-weight: 500;
    padding: 4px 9px;
    border-radius: var(--tg-radius-sm);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    transition: background .12s ease, border-color .12s ease;
  }
  .btn:hover { background: var(--vscode-list-hoverBackground); }
  .btn.active {
    background: color-mix(in srgb, var(--tg-blue) 22%, transparent);
    border-color: var(--tg-blue);
    color: var(--vscode-foreground);
  }
  .btn.primary {
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
    border-color: transparent;
  }
  .btn.primary:hover { background: var(--vscode-button-hoverBackground); }
  .btn.danger {
    background: color-mix(in srgb, var(--tg-red) 18%, transparent);
    border-color: color-mix(in srgb, var(--tg-red) 48%, transparent);
    color: var(--tg-red);
  }
  .btn.sm { padding: 2px 7px; font-size: 11px; }

  /* Path switcher */
  .path-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
  }
  .path-pill {
    border: 1px solid var(--tg-border);
    background: transparent;
    color: var(--tg-muted);
    font-family: inherit;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 99px;
    cursor: pointer;
  }
  .path-pill:hover { color: var(--vscode-foreground); background: var(--vscode-list-hoverBackground); }
  .path-pill.active {
    background: color-mix(in srgb, var(--tg-blue) 18%, transparent);
    border-color: var(--tg-blue);
    color: var(--vscode-foreground);
    font-weight: 600;
  }

  /* Main Tabs */
  .nav-tabs {
    display: flex;
    gap: 16px;
    margin-top: 2px;
  }
  .nav-tab {
    appearance: none;
    border: none;
    border-bottom: 2px solid transparent;
    background: transparent;
    color: var(--tg-muted);
    font-family: inherit;
    font-size: 12px;
    font-weight: 600;
    padding: 6px 2px 8px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .nav-tab:hover { color: var(--vscode-foreground); }
  .nav-tab.active {
    color: var(--vscode-foreground);
    border-bottom-color: var(--vscode-focusBorder, var(--tg-blue));
  }
  .tab-count {
    font-size: 10px;
    padding: 0 5px;
    border-radius: 99px;
    background: var(--vscode-badge-background);
    color: var(--vscode-badge-foreground);
    font-variant-numeric: tabular-nums;
  }
  .live-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--tg-blue);
    animation: pulse 1.1s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: .35; transform: scale(.75); }
  }

  /* Main Content */
  .content {
    padding: 14px 16px 28px;
    flex: 1;
  }

  /* Stepper Bar */
  .stepper-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 12px;
    font-size: 11.5px;
    color: var(--tg-muted);
  }
  .stepper-controls { display: flex; align-items: center; gap: 5px; }

  /* Vertical Flow Timeline */
  .timeline {
    display: flex;
    flex-direction: column;
    gap: 0;
  }
  .tl-item {
    display: flex;
    gap: 11px;
    position: relative;
    padding-bottom: 12px;
  }
  .tl-item:last-child { padding-bottom: 0; }
  .tl-rail {
    width: 24px;
    flex-shrink: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    position: relative;
  }
  .tl-node {
    width: 24px;
    height: 24px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 10.5px;
    font-weight: 700;
    background: color-mix(in srgb, var(--node-color, var(--tg-blue)) 18%, var(--tg-bg));
    border: 1.5px solid var(--node-color, var(--tg-blue));
    color: var(--node-color, var(--tg-blue));
    z-index: 2;
    flex-shrink: 0;
  }
  .tl-line {
    width: 2px;
    flex: 1;
    margin-top: 3px;
    margin-bottom: -15px;
    background: color-mix(in srgb, var(--vscode-foreground) 16%, transparent);
    z-index: 1;
  }
  .tl-item:last-child .tl-line { display: none; }

  .role-source { --node-color: var(--tg-blue); }
  .role-sink { --node-color: var(--tg-red); }
  .role-guard, .role-validation, .role-authorization, .role-sanitizer { --node-color: var(--tg-green); }
  .role-unresolved { --node-color: var(--tg-amber); }
  .role-flow { --node-color: var(--tg-purple); }

  .step-card {
    flex: 1;
    min-width: 0;
    background: var(--tg-card);
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius);
    overflow: hidden;
    cursor: pointer;
    transition: border-color .14s ease, box-shadow .14s ease, opacity .14s ease;
  }
  .step-card:hover {
    border-color: color-mix(in srgb, var(--vscode-focusBorder, var(--tg-blue)) 65%, transparent);
  }
  .step-card.active {
    border-color: var(--vscode-focusBorder, var(--tg-blue));
    box-shadow: 0 0 0 1px color-mix(in srgb, var(--vscode-focusBorder, var(--tg-blue)) 35%, transparent);
  }
  .step-card.reviewed {
    opacity: .6;
  }
  .step-card.reviewed .step-title { text-decoration: line-through; }

  .step-head {
    padding: 8px 10px;
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 8px;
  }
  .step-head-left {
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .step-meta-row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 5px;
  }
  .role-tag {
    font-size: 9.5px;
    font-weight: 700;
    letter-spacing: .04em;
    text-transform: uppercase;
    padding: 1px 5px;
    border-radius: 3px;
    background: color-mix(in srgb, var(--node-color, var(--tg-blue)) 16%, transparent);
    color: var(--node-color, var(--tg-blue));
  }
  .proof-tag {
    font-size: 10px;
    font-weight: 600;
    padding: 1px 5px;
    border-radius: 3px;
  }
  .proof-verified { background: color-mix(in srgb, var(--tg-green) 15%, transparent); color: var(--tg-green); }
  .proof-syntax-only { background: color-mix(in srgb, var(--tg-blue) 15%, transparent); color: var(--tg-blue); }
  .proof-heuristic { background: color-mix(in srgb, var(--tg-amber) 16%, transparent); color: var(--tg-amber); }
  .proof-unresolved { background: color-mix(in srgb, var(--tg-red) 16%, transparent); color: var(--tg-red); }

  .step-title {
    font-size: 12.5px;
    font-weight: 600;
    word-break: break-word;
  }
  .step-fn {
    font-size: 11px;
    color: var(--tg-muted);
    font-family: var(--tg-mono);
  }
  .step-head-right {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  }
  .loc-chip {
    font-family: var(--tg-mono);
    font-size: 10.5px;
    color: var(--vscode-textLink-foreground, var(--tg-blue));
    background: color-mix(in srgb, var(--tg-blue) 10%, transparent);
    padding: 2px 6px;
    border-radius: 3px;
    white-space: nowrap;
  }
  .icon-btn {
    border: 1px solid transparent;
    background: transparent;
    color: var(--tg-muted);
    width: 24px;
    height: 24px;
    border-radius: var(--tg-radius-sm);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    padding: 0;
  }
  .icon-btn:hover {
    background: var(--vscode-toolbar-hoverBackground, rgba(128,128,128,.16));
    color: var(--vscode-foreground);
  }
  .icon-btn.on { color: var(--tg-green); background: color-mix(in srgb, var(--tg-green) 14%, transparent); }

  /* Code Snippet Block */
  .code-box {
    border-top: 1px solid var(--tg-border);
    background: var(--tg-bg);
    font-family: var(--tg-mono);
    font-size: 11.5px;
    line-height: 1.5;
    overflow-x: auto;
    padding: 4px 0;
  }
  .code-line {
    display: flex;
    padding: 0 10px 0 0;
    white-space: pre;
  }
  .code-line.active {
    background: color-mix(in srgb, var(--node-color, var(--tg-blue)) 14%, transparent);
    box-shadow: inset 3px 0 0 var(--node-color, var(--tg-blue));
  }
  .ln {
    width: 40px;
    padding-right: 10px;
    text-align: right;
    color: var(--vscode-editorLineNumber-foreground, var(--tg-muted));
    user-select: none;
    flex-shrink: 0;
    font-variant-numeric: tabular-nums;
  }
  .code-line.active .ln { color: var(--vscode-foreground); font-weight: 600; }
  .lc { flex: 1; }
  .step-reason {
    border-top: 1px solid var(--tg-border);
    padding: 6px 10px;
    font-size: 11px;
    color: var(--tg-muted);
    background: color-mix(in srgb, var(--tg-surface) 50%, transparent);
  }

  /* Interruption & Inline Modeling Mini-Form */
  .interrupt-card {
    flex: 1;
    min-width: 0;
    background: color-mix(in srgb, var(--tg-amber) 8%, var(--tg-card));
    border: 1px solid color-mix(in srgb, var(--tg-amber) 45%, transparent);
    border-radius: var(--tg-radius);
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .interrupt-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    flex-wrap: wrap;
  }
  .interrupt-title {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-weight: 650;
    font-size: 12.5px;
    color: var(--tg-amber);
  }
  .interrupt-text { font-size: 11.5px; color: var(--vscode-foreground); }
  .interrupt-next { font-size: 11px; color: var(--tg-muted); }

  .model-form {
    border-top: 1px solid color-mix(in srgb, var(--tg-amber) 30%, transparent);
    padding-top: 10px;
    display: flex;
    flex-direction: column;
    gap: 9px;
  }
  .form-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 8px;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .field label {
    font-size: 10.5px;
    font-weight: 600;
    color: var(--tg-muted);
  }
  .text-input, .select-input, .textarea-input {
    width: 100%;
    background: var(--vscode-input-background);
    color: var(--vscode-input-foreground, var(--vscode-foreground));
    border: 1px solid var(--vscode-input-border, var(--tg-border));
    border-radius: var(--tg-radius-sm);
    font-family: inherit;
    font-size: 12px;
    padding: 5px 8px;
    outline: none;
  }
  .text-input:focus, .select-input:focus, .textarea-input:focus {
    border-color: var(--vscode-focusBorder);
  }
  .select-input {
    background: var(--vscode-dropdown-background, var(--vscode-input-background));
    color: var(--vscode-dropdown-foreground, var(--vscode-foreground));
  }
  .role-seg {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 4px;
  }
  .seg-btn {
    border: 1px solid var(--tg-border);
    background: var(--tg-bg);
    color: var(--tg-muted);
    font-family: inherit;
    font-size: 11px;
    font-weight: 600;
    padding: 5px 4px;
    border-radius: var(--tg-radius-sm);
    cursor: pointer;
    text-align: center;
  }
  .seg-btn.active {
    background: color-mix(in srgb, var(--tg-blue) 22%, transparent);
    border-color: var(--tg-blue);
    color: var(--vscode-foreground);
  }
  .arg-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
  }
  .arg-chip {
    border: 1px solid var(--tg-border);
    background: var(--tg-bg);
    color: var(--vscode-foreground);
    font-family: var(--tg-mono);
    font-size: 11px;
    padding: 3px 8px;
    border-radius: 99px;
    cursor: pointer;
  }
  .arg-chip.selected {
    background: color-mix(in srgb, var(--tg-blue) 24%, transparent);
    border-color: var(--tg-blue);
    font-weight: 600;
  }
  .json-preview {
    font-family: var(--tg-mono);
    font-size: 10.5px;
    color: var(--tg-muted);
    background: var(--tg-bg);
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius-sm);
    padding: 6px 8px;
    overflow-x: auto;
    white-space: pre;
  }
  .form-feedback {
    font-size: 11.5px;
    padding: 5px 8px;
    border-radius: var(--tg-radius-sm);
  }
  .form-feedback.ok { background: color-mix(in srgb, var(--tg-green) 16%, transparent); color: var(--tg-green); }
  .form-feedback.err { background: color-mix(in srgb, var(--tg-red) 16%, transparent); color: var(--tg-red); }

  /* AI Drawer */
  .ai-toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 12px;
    padding: 8px 10px;
    background: var(--tg-card);
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius);
  }
  .ai-model-meta {
    font-size: 11px;
    color: var(--tg-muted);
    font-family: var(--tg-mono);
  }
  .ai-body {
    background: var(--tg-card);
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius);
    padding: 14px 16px;
    min-height: 200px;
  }
  .ai-status-foot {
    margin-top: 10px;
    padding-top: 8px;
    border-top: 1px solid var(--tg-border);
    font-size: 11px;
    color: var(--tg-muted);
    display: flex;
    align-items: center;
    gap: 6px;
  }

  /* Markdown Styles */
  .md-h1, .md-h2, .md-h3, .md-h4 { margin: 12px 0 6px; font-weight: 650; line-height: 1.3; }
  .md-h1 { font-size: 16px; }
  .md-h2 { font-size: 14px; border-bottom: 1px solid var(--tg-border); padding-bottom: 4px; }
  .md-h3 { font-size: 13px; }
  .md-p { margin: 6px 0; }
  .md-list { margin: 6px 0; padding-left: 20px; }
  .md-list li { margin: 3px 0; }
  .md-quote {
    margin: 8px 0;
    padding: 6px 10px;
    border-left: 3px solid var(--tg-blue);
    background: color-mix(in srgb, var(--tg-blue) 9%, transparent);
    color: var(--tg-muted);
    border-radius: 0 var(--tg-radius-sm) var(--tg-radius-sm) 0;
  }
  .md-hr { border: none; border-top: 1px solid var(--tg-border); margin: 12px 0; }
  .md-inline-code {
    font-family: var(--tg-mono);
    font-size: 11.5px;
    background: color-mix(in srgb, var(--vscode-foreground) 10%, transparent);
    padding: 1px 4px;
    border-radius: 3px;
  }
  .md-code-wrap {
    margin: 8px 0;
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius-sm);
    overflow: hidden;
    background: var(--tg-bg);
  }
  .md-code-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 3px 8px;
    border-bottom: 1px solid var(--tg-border);
    background: var(--tg-surface);
    font-size: 10.5px;
    color: var(--tg-muted);
  }
  .md-copy-code { width: auto; height: 20px; padding: 0 6px; font-size: 10.5px; }
  .md-pre {
    margin: 0;
    padding: 8px 10px;
    overflow-x: auto;
    font-family: var(--tg-mono);
    font-size: 11.5px;
    line-height: 1.45;
  }

  /* Notes Drawer */
  .note-composer {
    background: var(--tg-card);
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius);
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-bottom: 12px;
  }
  .note-list { display: flex; flex-direction: column; gap: 8px; }
  .note-card {
    background: var(--tg-card);
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius);
    padding: 9px 11px;
    display: flex;
    flex-direction: column;
    gap: 5px;
  }
  .note-card-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .note-code {
    font-family: var(--tg-mono);
    font-size: 11px;
    background: var(--tg-bg);
    border: 1px solid var(--tg-border);
    border-radius: var(--tg-radius-sm);
    padding: 5px 8px;
    overflow-x: auto;
    white-space: pre;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    text-align: center;
    gap: 8px;
    padding: 44px 20px;
    color: var(--tg-muted);
  }
  .empty-state .svg-icon { width: 28px; height: 28px; color: var(--tg-blue); opacity: .85; }
  .empty-state h3 { margin: 0; font-size: 14px; color: var(--vscode-foreground); }
  .empty-state p { margin: 0; max-width: 380px; font-size: 12px; }
</style>
</head>
<body>
  <div id="app" class="shell"></div>
  <script nonce="${nonce}">
    (function() {
      const vscode = acquireVsCodeApi();
      const ICONS = ${safeJsonForHtml(SVG_ICONS)};
      let state = { mode: "empty", locale: ${safeJsonForHtml(zh ? "zh" : "en")}, steps: [], notes: [], ai: { status: "idle", html: "" }, catalogs: { sinks: [], sanitizers: [], sources: [], noteTypes: [] } };
      let activeTab = "timeline";
      let openModelKey = null;
      let modelDraft = { role: "sink", functionName: "", kind: "SQL_QUERY", arguments: [0], extraArgs: 0 };
      let modelFeedback = null;
      let noteDraft = { type: "Controllability", note: "", absolutePath: "", relativePath: "", line: 1, code: "" };
      let noteFeedback = null;

      const app = document.getElementById("app");
      function t(zhText, enText) { return state.locale === "zh" ? zhText : enText; }
      function esc(v) {
        return String(v ?? "")
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")
          .replaceAll('"', "&quot;")
          .replaceAll("'", "&#39;");
      }
      function icon(name) { return '<span class="svg-icon">' + (ICONS[name] || "") + "</span>"; }

      function roleClass(role) {
        if (role === "source" || role === "entry") return "role-source";
        if (role === "sink") return "role-sink";
        if (["guard", "validation", "authorization", "sanitizer"].includes(role)) return "role-guard";
        if (role === "unresolved") return "role-unresolved";
        return "role-flow";
      }
      function roleIcon(role) {
        if (role === "source") return "source";
        if (role === "entry") return "globe";
        if (role === "sink") return "sink";
        if (["guard", "validation", "authorization", "sanitizer"].includes(role)) return "guard";
        if (role === "unresolved") return "disconnect";
        return "call";
      }
      function severityBadgeClass(sev) {
        if (sev === "critical" || sev === "high") return "badge-red";
        if (sev === "medium") return "badge-amber";
        return "badge-blue";
      }

      function initModelDraft(interruption) {
        const args = interruption.arguments || [];
        modelDraft = {
          role: "sink",
          functionName: interruption.functionName || "",
          kind: "SQL_QUERY",
          arguments: args.length ? [0] : [0],
          rawArguments: args,
          extraArgs: 0,
          absolutePath: interruption.absolutePath || "",
          line: interruption.line || 1,
          language: interruption.language || "",
        };
        modelFeedback = null;
      }

      function syncNoteDraftFromActiveStep(force) {
        if (!state.activeStep) return;
        if (force || !noteDraft.absolutePath) {
          noteDraft.absolutePath = state.activeStep.absolutePath || "";
          noteDraft.relativePath = state.activeStep.relativePath || "";
          noteDraft.line = state.activeStep.line || 1;
          noteDraft.code = state.activeStep.code || "";
        }
      }

      function render() {
        syncNoteDraftFromActiveStep(false);
        if (state.mode === "empty") {
          app.innerHTML =
            '<div class="empty-state">'
            + icon("shield")
            + "<h3>" + esc(t("TraceGuard 可视化审计工作台", "TraceGuard Trace Inspector")) + "</h3>"
            + "<p>" + esc(t("在 Review Queue 中点击任意漏洞流，或在代码中选中变量按 Ctrl+Alt+↑/↓ 追踪污点路径，此处将实时展示可视化数据流时间线、上下文源码、内联建模与 AI 研判。", "Select any finding in Review Queue or trace a variable (Ctrl+Alt+Up/Down) to inspect the Source → Sink timeline, contextual snippets, inline call modeling, and live AI verification.")) + "</p>"
            + "</div>";
          return;
        }

        app.innerHTML = renderHeader() + '<div class="content">' + renderActiveTab() + "</div>";
        bindEvents();
      }

      function renderHeader() {
        const poolBadge = state.mode === "finding"
          ? (state.pool === "verified"
            ? '<span class="badge badge-red">' + esc(t("已验证流", "VERIFIED FLOW")) + "</span>"
            : state.pool === "review"
              ? '<span class="badge badge-amber">' + esc(t("待复核假设", "REVIEW HYPOTHESIS")) + "</span>"
              : '<span class="badge badge-neutral">' + esc(t("已处置", "RESOLVED")) + "</span>")
          : state.mode === "trace"
            ? '<span class="badge badge-blue">' + esc(t("交互追踪", "INTERACTIVE TRACE")) + "</span>"
            : '<span class="badge badge-purple">' + esc(t("分析查询", "AUDIT QUERY")) + "</span>";

        const sevBadge = state.severity
          ? '<span class="badge ' + severityBadgeClass(state.severity) + '">' + esc(state.severity.toUpperCase()) + "</span>"
          : "";
        const cweBadge = state.cwe
          ? '<span class="badge badge-neutral">' + esc(state.cwe) + "</span>"
          : "";
        const confBadge = state.confidence
          ? '<span class="badge badge-neutral">' + esc(state.confidence + " confidence") + "</span>"
          : "";
        const statusBadge = state.findingStatusLabel
          ? '<span class="badge ' + (state.findingStatus === "open" ? "badge-amber" : "badge-green") + '">' + esc(state.findingStatusLabel) + "</span>"
          : "";

        const guardsHtml = (state.observedGuards?.length || state.missingGuards?.length)
          ? '<div class="guards-row">'
            + (state.observedGuards || []).map(g => '<span class="guard-chip guard-ok">' + icon("guard") + esc(g) + "</span>").join("")
            + (state.missingGuards || []).map(g => '<span class="guard-chip guard-miss">' + esc(t("需确认: ", "Check: ") + g) + "</span>").join("")
            + "</div>"
          : "";

        const triageButtons = state.findingId
          ? '<div class="btn-group">'
            + '<button class="btn' + (state.findingStatus === "reviewed" ? " active" : "") + '" data-status="reviewed">' + icon("check") + esc(t("已审", "Reviewed")) + "</button>"
            + '<button class="btn' + (state.findingStatus === "false_positive" ? " active" : "") + '" data-status="false_positive">' + icon("slash") + esc(t("误报", "False Positive")) + "</button>"
            + '<button class="btn' + (state.findingStatus === "accepted_risk" ? " active" : "") + '" data-status="accepted_risk">' + icon("shield") + esc(t("接受风险", "Accept Risk")) + "</button>"
            + (state.findingStatus !== "open" ? '<button class="btn" data-status="open">' + esc(t("重开", "Reopen")) + "</button>" : "")
            + "</div>"
          : "";

        const pathTabsHtml = state.pathSummaries && state.pathSummaries.length > 1
          ? '<div class="path-tabs">'
            + state.pathSummaries.map(p =>
                '<button class="path-pill' + (p.index === state.pathIndex ? " active" : "") + '" data-path-idx="' + p.index + '">'
                + esc("Path " + (p.index + 1) + " · " + p.status + " · " + p.steps + " steps")
                + "</button>"
              ).join("")
            + "</div>"
          : "";

        return '<header class="header">'
          + '<div class="badges-row">' + poolBadge + sevBadge + cweBadge + confBadge + statusBadge + "</div>"
          + '<div class="title-block">'
          +   '<h1 class="main-title">' + esc(state.title) + "</h1>"
          +   (state.subtitle ? '<div class="sub-title">' + esc(state.subtitle) + "</div>" : "")
          + "</div>"
          + guardsHtml
          + '<div class="actions-bar">'
          +   triageButtons
          +   '<button class="btn" id="btn-open-note">' + icon("bookmark") + esc(t("加笔记", "Add Note")) + "</button>"
          +   '<button class="btn primary" id="btn-verify-ai">' + icon("sparkle") + esc(t("AI 研判", "Verify with AI")) + "</button>"
          +   '<button class="btn" id="btn-copy-prompt" title="' + esc(t("复制 AI Prompt", "Copy AI Prompt")) + '">' + icon("copy") + esc(t("Prompt", "Prompt")) + "</button>"
          +   '<button class="btn" id="btn-copy-md" title="' + esc(t("复制链路 Markdown", "Copy Path Markdown")) + '">' + icon("copy") + "MD</button>"
          + "</div>"
          + pathTabsHtml
          + '<nav class="nav-tabs">'
          +   '<button class="nav-tab' + (activeTab === "timeline" ? " active" : "") + '" data-tab="timeline">'
          +     esc(t("污点链路", "Flow Timeline")) + '<span class="tab-count">' + state.stepCount + "</span>"
          +   "</button>"
          +   '<button class="nav-tab' + (activeTab === "ai" ? " active" : "") + '" data-tab="ai">'
          +     icon("sparkle") + esc(t("AI 研判", "AI Verification"))
          +     (state.ai.status === "streaming" ? '<span class="live-dot"></span>' : "")
          +   "</button>"
          +   '<button class="nav-tab' + (activeTab === "notes" ? " active" : "") + '" data-tab="notes">'
          +     icon("bookmark") + esc(t("审计笔记", "Notes")) + '<span class="tab-count">' + (state.notes || []).length + "</span>"
          +   "</button>"
          + "</nav>"
          + "</header>";
      }

      function renderActiveTab() {
        if (activeTab === "ai") return renderAiTab();
        if (activeTab === "notes") return renderNotesTab();
        return renderTimelineTab();
      }

      function renderTimelineTab() {
        const stepper = (state.mode === "finding" || state.mode === "trace") && state.stepCount > 0
          ? '<div class="stepper-bar">'
            + "<span>" + esc(t("第 " + (state.cursor + 1) + " / " + state.stepCount + " 步 · 点击任意卡片同步跳转左侧代码", "Step " + (state.cursor + 1) + " of " + state.stepCount + " · Click any card to jump in editor")) + "</span>"
            + '<div class="stepper-controls">'
            +   '<button class="btn sm" id="btn-prev-step">' + icon("arrowUp") + esc(t("上一步", "Prev")) + "</button>"
            +   '<button class="btn sm" id="btn-next-step">' + icon("arrowDown") + esc(t("下一步", "Next")) + "</button>"
            +   '<button class="btn sm" id="btn-clear-hl">' + esc(t("清除高亮", "Clear HL")) + "</button>"
            + "</div>"
            + "</div>"
          : "";

        const itemsHtml = (state.steps || []).map((step, idx) => {
          const rClass = roleClass(step.role);
          const indentPx = (step.depth || 0) * 18;
          const codeHtml = (step.snippet && step.snippet.length)
            ? '<div class="code-box">'
              + step.snippet.map(line =>
                  '<div class="code-line' + (line.active ? " active" : "") + '"><span class="ln">' + line.number + '</span><span class="lc">' + esc(line.text) + "</span></div>"
                ).join("")
              + "</div>"
            : "";

          const inlineInt = step.interruption
            ? renderInterruptionRow(step.interruption, "node:" + (step.nodeId || idx), indentPx + 18)
            : "";

          return '<div class="tl-item ' + rClass + '" style="margin-left:' + indentPx + 'px">'
            + '<div class="tl-rail">'
            +   '<div class="tl-node" title="' + esc(step.role) + '">' + icon(roleIcon(step.role)) + "</div>"
            +   '<div class="tl-line"></div>'
            + "</div>"
            + '<div class="step-card' + (step.active ? " active" : "") + (step.reviewed ? " reviewed" : "") + '" data-step-kind="' + esc(step.kind) + '" data-step-index="' + step.index + '" data-node-id="' + esc(step.nodeId || "") + '">'
            +   '<div class="step-head">'
            +     '<div class="step-head-left">'
            +       '<div class="step-meta-row">'
            +         '<span class="role-tag">' + esc((step.index + 1) + " · " + step.role) + "</span>"
            +         '<span class="proof-tag proof-' + esc(step.status) + '">' + esc(step.status) + "</span>"
            +         (step.functionName ? '<span class="step-fn">' + esc(step.functionName + "()") + "</span>" : "")
            +       "</div>"
            +       '<div class="step-title">' + esc(step.label) + "</div>"
            +     "</div>"
            +     '<div class="step-head-right">'
            +       (step.fileName ? '<span class="loc-chip">' + esc(step.fileName + ":" + step.line) + "</span>" : "")
            +       (!step.inheritedReview
                      ? '<button class="icon-btn' + (step.reviewed ? " on" : "") + '" data-toggle-safe="1" title="' + esc(t("标记为安全/忽略", "Toggle Safe / Ignored")) + '">' + icon("check") + "</button>"
                      : "")
            +       '<button class="icon-btn" data-note-step="1" title="' + esc(t("为此步骤添加笔记", "Add note for this step")) + '">' + icon("bookmark") + "</button>"
            +     "</div>"
            +   "</div>"
            +   codeHtml
            +   (step.reason ? '<div class="step-reason">' + esc(step.reason) + "</div>" : "")
            + "</div>"
            + "</div>"
            + inlineInt;
        }).join("");

        const tailInterruption = state.interruption
          ? renderInterruptionRow(state.interruption, "tail", 0)
          : "";

        return stepper + '<div class="timeline">' + itemsHtml + tailInterruption + "</div>";
      }

      function renderInterruptionRow(interruption, key, indentPx) {
        const isOpen = openModelKey === key;
        const formHtml = isOpen ? renderInlineModelForm(interruption) : "";
        return '<div class="tl-item role-unresolved" style="margin-left:' + indentPx + 'px">'
          + '<div class="tl-rail"><div class="tl-node">' + icon("disconnect") + "</div></div>"
          + '<div class="interrupt-card">'
          +   '<div class="interrupt-head">'
          +     '<span class="interrupt-title">' + icon("disconnect") + esc(t("链路中断", "Path Interrupted") + " · " + interruption.status) + "</span>"
          +     '<div class="stepper-controls">'
          +       (interruption.modelable
                    ? '<button class="btn sm primary" data-toggle-model="' + esc(key) + '">' + icon("wrench") + esc(isOpen ? t("收起表单", "Hide Form") : t("补充语义模型", "Model This Call")) + "</button>"
                    : "")
          +       (interruption.absolutePath
                    ? '<button class="btn sm" data-inspect-callees="' + esc(interruption.absolutePath) + '" data-line="' + interruption.line + '">' + esc(t("查候选目标", "Inspect Callees")) + "</button>"
                    : "")
          +       (interruption.absolutePath
                    ? '<button class="btn sm" data-open-loc="' + esc(interruption.absolutePath) + '" data-line="' + interruption.line + '">' + esc(interruption.fileName + ":" + interruption.line) + "</button>"
                    : "")
          +     "</div>"
          +   "</div>"
          +   '<div class="interrupt-text">' + esc(interruption.reason) + "</div>"
          +   '<div class="interrupt-next">' + esc(interruption.next) + "</div>"
          +   formHtml
          + "</div>"
          + "</div>";
      }

      function renderInlineModelForm(interruption) {
        const role = modelDraft.role;
        const catalog = role === "sink"
          ? state.catalogs.sinks
          : role === "sanitizer"
            ? state.catalogs.sanitizers
            : role === "source"
              ? state.catalogs.sources
              : [];
        const needsArgs = ["sink", "sanitizer", "propagator"].includes(role);
        const argLabels = (modelDraft.rawArguments && modelDraft.rawArguments.length)
          ? modelDraft.rawArguments
          : Array.from({ length: Math.max(2, modelDraft.extraArgs + 2) }, (_, i) => "arg" + i);
        const allArgs = [...argLabels];
        for (let i = 0; i < modelDraft.extraArgs; i++) {
          if (modelDraft.rawArguments && modelDraft.rawArguments.length) allArgs.push("arg" + (argLabels.length + i));
        }

        const previewObj = {
          language: modelDraft.language || "auto",
          function: modelDraft.functionName || "<callName>",
          ...(role !== "propagator" ? { [role === "sanitizer" ? "capability" : "kind"]: role === "sanitizer" ? [modelDraft.kind] : modelDraft.kind } : {}),
          ...(needsArgs ? { arguments: modelDraft.arguments } : { returnsTaint: true }),
        };

        return '<div class="model-form">'
          + '<div class="field">'
          +   '<label>' + esc(t("建模角色", "Semantic Role")) + "</label>"
          +   '<div class="role-seg">'
          +     ["sink", "sanitizer", "source", "propagator"].map(r =>
                  '<button type="button" class="seg-btn' + (role === r ? " active" : "") + '" data-model-role="' + r + '">' + esc(r.toUpperCase()) + "</button>"
                ).join("")
          +   "</div>"
          + "</div>"
          + '<div class="form-grid">'
          +   '<div class="field">'
          +     '<label>' + esc(t("函数 / 调用名称", "Function / Call Name")) + "</label>"
          +     '<input id="mf-fn" class="text-input" type="text" value="' + esc(modelDraft.functionName) + '" placeholder="e.g. db.query, sanitizePath"/>'
          +   "</div>"
          +   (catalog.length
                ? '<div class="field">'
                  + '<label>' + esc(role === "sanitizer" ? t("消毒能力", "Guarantee Capability") : t("类别", "Category")) + "</label>"
                  + '<select id="mf-kind" class="select-input">'
                  + catalog.map(opt => '<option value="' + esc(opt.kind) + '"' + (opt.kind === modelDraft.kind ? " selected" : "") + ">" + esc(opt.label + " (" + opt.kind + ")") + "</option>").join("")
                  + "</select></div>"
                : "")
          + "</div>"
          + (needsArgs
              ? '<div class="field">'
                + '<label>' + esc(t("点选受影响参数位置", "Select Affected Arguments")) + "</label>"
                + '<div class="arg-chips">'
                + allArgs.map((expr, idx) =>
                    '<button type="button" class="arg-chip' + (modelDraft.arguments.includes(idx) ? " selected" : "") + '" data-arg-idx="' + idx + '">'
                    + esc("[" + idx + "] " + String(expr).slice(0, 28))
                    + "</button>"
                  ).join("")
                + '<button type="button" class="arg-chip" id="btn-more-arg">+ arg</button>'
                + "</div>"
                + "</div>"
              : "")
          + '<div class="json-preview">' + esc(JSON.stringify(previewObj)) + "</div>"
          + (modelFeedback ? '<div class="form-feedback ' + (modelFeedback.ok ? "ok" : "err") + '">' + esc(modelFeedback.message) + "</div>" : "")
          + '<div class="actions-bar">'
          +   '<button type="button" class="btn primary" id="btn-save-model-perm">' + esc(t("写入 .traceguard.json 并重算", "Save to .traceguard.json & Re-trace")) + "</button>"
          +   ((role === "sink" || role === "sanitizer")
                ? '<button type="button" class="btn" id="btn-save-model-temp">' + esc(t("仅本次会话临时生效", "Apply Temporarily")) + "</button>"
                : "")
          + "</div>"
          + "</div>";
      }

      function renderAiTab() {
        const ai = state.ai || {};
        const streaming = ai.status === "streaming";
        const bodyHtml = ai.uriString
          ? '<div class="ai-body" id="ai-md-body">' + (ai.html || "")
            + (ai.statusText ? '<div class="ai-status-foot">' + (streaming ? '<span class="live-dot"></span>' : icon("check")) + "<span>" + esc(ai.statusText) + "</span></div>" : "")
            + "</div>"
          : '<div class="ai-body"><div class="empty-state" style="padding:28px 12px">'
            + icon("sparkle")
            + "<h3>" + esc(t("AI 链路研判助手", "AI Chain Verification")) + "</h3>"
            + "<p>" + esc(t("将当前链路的代码切片发送到已配置的模型，查看路径证据、防护条件和修复建议。", "Send the code for this trace to your configured model to review path evidence, safeguards and possible fixes.")) + "</p>"
            + '<div class="actions-bar" style="justify-content:center;margin-top:4px">'
            +   '<button class="btn primary" id="btn-ai-run-empty">' + icon("sparkle") + esc(t("立即研判当前链路", "Verify Current Chain")) + "</button>"
            +   '<button class="btn" id="btn-ai-copy-empty">' + icon("copy") + esc(t("仅复制 Prompt（不调用模型）", "Copy Prompt Only")) + "</button>"
            + "</div>"
            + "</div></div>";

        return '<div class="ai-toolbar">'
          + '<span class="ai-model-meta">' + esc((ai.model || "model") + (ai.endpointHost ? " @ " + ai.endpointHost : "")) + "</span>"
          + '<div class="actions-bar">'
          +   (streaming
                ? '<button class="btn danger" id="btn-ai-stop">' + icon("stop") + esc(t("停止生成", "Stop")) + "</button>"
                : '<button class="btn primary" id="btn-ai-run">' + icon("sparkle") + esc(t("重新研判", "Verify with AI")) + "</button>")
          +   (ai.markdown ? '<button class="btn" id="btn-ai-copy-report">' + icon("copy") + esc(t("复制报告", "Copy")) + "</button>" : "")
          +   (ai.uriString ? '<button class="btn" id="btn-ai-open-raw">' + icon("external") + esc(t("源码视图", "Raw .md")) + "</button>" : "")
          +   '<button class="btn" id="btn-ai-key">' + esc(t("API Key", "API Key")) + "</button>"
          + "</div>"
          + "</div>"
          + bodyHtml;
      }

      function renderNotesTab() {
        const notes = state.notes || [];
        const locSummary = noteDraft.absolutePath
          ? (noteDraft.relativePath || noteDraft.absolutePath) + ":" + noteDraft.line
          : t("未关联源码位置", "No source location");

        const composerHtml = '<div class="note-composer">'
          + '<div class="form-grid">'
          +   '<div class="field">'
          +     '<label>' + esc(t("笔记类型", "Evidence Type")) + "</label>"
          +     '<select id="note-type" class="select-input">'
          +       (state.catalogs.noteTypes || []).map(tp => '<option value="' + esc(tp) + '"' + (tp === noteDraft.type ? " selected" : "") + ">" + esc(tp) + "</option>").join("")
          +     "</select>"
          +   "</div>"
          +   '<div class="field">'
          +     '<label>' + esc(t("关联代码位置", "Anchored Location")) + "</label>"
          +     '<input class="text-input" type="text" value="' + esc(locSummary) + '" readonly/>'
          +   "</div>"
          + "</div>"
          + '<div class="field">'
          +   '<label>' + esc(t("审计判断 / 备注", "Audit Judgment / Note")) + "</label>"
          +   '<textarea id="note-text" class="textarea-input" rows="3" placeholder="' + esc(t("记录可控性、缺失上下文、利用前提或误报原因…", "Record controllability, missing context, exploit preconditions, or false-positive reason…")) + '">' + esc(noteDraft.note) + "</textarea>"
          + "</div>"
          + (noteFeedback ? '<div class="form-feedback ' + (noteFeedback.ok ? "ok" : "err") + '">' + esc(noteFeedback.message) + "</div>" : "")
          + '<div class="actions-bar"><button class="btn primary" id="btn-save-note">' + icon("bookmark") + esc(t("保存到审计笔记", "Save Note")) + "</button></div>"
          + "</div>";

        const listHtml = notes.length
          ? '<div class="note-list">' + notes.map(n =>
              '<div class="note-card">'
              + '<div class="note-card-head">'
              +   '<div class="badges-row"><span class="badge badge-blue">' + esc(n.type) + "</span>"
              +     '<button class="btn sm" data-open-note="' + esc(n.id) + '">' + esc(n.fileName + ":" + n.line) + "</button>"
              +     (n.stale ? '<span class="badge badge-amber">stale</span>' : "")
              +   "</div>"
              +   '<button class="icon-btn" data-remove-note="' + esc(n.id) + '" title="' + esc(t("删除笔记", "Delete note")) + '">' + icon("clear") + "</button>"
              + "</div>"
              + (n.note ? "<div>" + esc(n.note) + "</div>" : "")
              + (n.code ? '<div class="note-code">' + esc(n.code) + "</div>" : "")
              + "</div>"
            ).join("") + "</div>"
          : '<div class="empty-state" style="padding:20px"><p>' + esc(t("当前链路相关文件暂无审计笔记。", "No audit notes recorded for files in this trace yet.")) + "</p></div>";

        return composerHtml + listHtml;
      }

      function bindEvents() {
        for (const tab of document.querySelectorAll("[data-tab]")) {
          tab.addEventListener("click", () => {
            activeTab = tab.getAttribute("data-tab");
            render();
          });
        }
        for (const btn of document.querySelectorAll("[data-status]")) {
          btn.addEventListener("click", () => vscode.postMessage({ type: "setFindingStatus", status: btn.getAttribute("data-status") }));
        }
        for (const pill of document.querySelectorAll("[data-path-idx]")) {
          pill.addEventListener("click", () => vscode.postMessage({ type: "switchPath", pathIndex: Number(pill.getAttribute("data-path-idx")) }));
        }
        const openNoteBtn = document.getElementById("btn-open-note");
        if (openNoteBtn) openNoteBtn.addEventListener("click", () => {
          syncNoteDraftFromActiveStep(true);
          activeTab = "notes";
          render();
          const ta = document.getElementById("note-text");
          if (ta) ta.focus();
        });
        const verifyAi = document.getElementById("btn-verify-ai");
        if (verifyAi) verifyAi.addEventListener("click", () => {
          activeTab = "ai";
          render();
          vscode.postMessage({ type: "verifyAi" });
        });
        const copyPrompt = document.getElementById("btn-copy-prompt");
        if (copyPrompt) copyPrompt.addEventListener("click", () => vscode.postMessage({ type: "copyAiPrompt" }));
        const copyMd = document.getElementById("btn-copy-md");
        if (copyMd) copyMd.addEventListener("click", () => vscode.postMessage({ type: "copyMarkdown" }));

        const prevStep = document.getElementById("btn-prev-step");
        if (prevStep) prevStep.addEventListener("click", () => vscode.postMessage({ type: "prevStep" }));
        const nextStep = document.getElementById("btn-next-step");
        if (nextStep) nextStep.addEventListener("click", () => vscode.postMessage({ type: "nextStep" }));
        const clearHl = document.getElementById("btn-clear-hl");
        if (clearHl) clearHl.addEventListener("click", () => vscode.postMessage({ type: "clearHighlights" }));

        for (const card of document.querySelectorAll(".step-card")) {
          card.addEventListener("click", event => {
            const kind = card.getAttribute("data-step-kind");
            const index = Number(card.getAttribute("data-step-index"));
            const nodeId = card.getAttribute("data-node-id");
            if (event.target.closest("[data-toggle-safe]")) {
              vscode.postMessage({ type: "toggleStepReviewed", kind, index, nodeId });
              return;
            }
            if (event.target.closest("[data-note-step]")) {
              const step = (state.steps || []).find(s => (kind === "trace-step" ? s.index === index : s.nodeId === nodeId));
              if (step) {
                noteDraft.absolutePath = step.absolutePath;
                noteDraft.relativePath = step.relativePath;
                noteDraft.line = step.line;
                noteDraft.code = step.code || (step.snippet?.find(l => l.active)?.text || "");
                noteFeedback = null;
                activeTab = "notes";
                render();
              }
              return;
            }
            vscode.postMessage({ type: "selectStep", kind, index, nodeId });
          });
        }

        for (const btn of document.querySelectorAll("[data-toggle-model]")) {
          btn.addEventListener("click", () => {
            const key = btn.getAttribute("data-toggle-model");
            if (openModelKey === key) {
              openModelKey = null;
            } else {
              openModelKey = key;
              let target = state.interruption;
              if (key.startsWith("node:")) {
                const nid = key.slice(5);
                const found = (state.steps || []).find((s, i) => String(s.nodeId || i) === nid);
                if (found?.interruption) target = found.interruption;
              }
              if (target) initModelDraft(target);
            }
            render();
          });
        }
        for (const btn of document.querySelectorAll("[data-inspect-callees]")) {
          btn.addEventListener("click", () => vscode.postMessage({
            type: "inspectCallees",
            absolutePath: btn.getAttribute("data-inspect-callees"),
            line: Number(btn.getAttribute("data-line")) || 1,
          }));
        }
        for (const btn of document.querySelectorAll("[data-open-loc]")) {
          btn.addEventListener("click", () => vscode.postMessage({
            type: "openLocation",
            absolutePath: btn.getAttribute("data-open-loc"),
            line: Number(btn.getAttribute("data-line")) || 1,
          }));
        }

        // Inline Model Form Events
        for (const btn of document.querySelectorAll("[data-model-role]")) {
          btn.addEventListener("click", () => {
            const role = btn.getAttribute("data-model-role");
            modelDraft.role = role;
            if (role === "sink") modelDraft.kind = "SQL_QUERY";
            else if (role === "sanitizer") modelDraft.kind = "INPUT_VALIDATION";
            else if (role === "source") modelDraft.kind = "EXTERNAL_INPUT";
            modelFeedback = null;
            render();
          });
        }
        const mfFn = document.getElementById("mf-fn");
        if (mfFn) mfFn.addEventListener("input", () => {
          modelDraft.functionName = mfFn.value;
          const prev = document.querySelector(".json-preview");
          if (prev) {
            const role = modelDraft.role;
            const needsArgs = ["sink", "sanitizer", "propagator"].includes(role);
            prev.textContent = JSON.stringify({
              language: modelDraft.language || "auto",
              function: modelDraft.functionName || "<callName>",
              ...(role !== "propagator" ? { [role === "sanitizer" ? "capability" : "kind"]: role === "sanitizer" ? [modelDraft.kind] : modelDraft.kind } : {}),
              ...(needsArgs ? { arguments: modelDraft.arguments } : { returnsTaint: true }),
            });
          }
        });
        const mfKind = document.getElementById("mf-kind");
        if (mfKind) mfKind.addEventListener("change", () => {
          modelDraft.kind = mfKind.value;
          render();
        });
        for (const chip of document.querySelectorAll("[data-arg-idx]")) {
          chip.addEventListener("click", () => {
            const idx = Number(chip.getAttribute("data-arg-idx"));
            if (modelDraft.arguments.includes(idx)) {
              modelDraft.arguments = modelDraft.arguments.filter(v => v !== idx);
            } else {
              modelDraft.arguments = [...modelDraft.arguments, idx].sort((a, b) => a - b);
            }
            render();
          });
        }
        const moreArg = document.getElementById("btn-more-arg");
        if (moreArg) moreArg.addEventListener("click", () => {
          modelDraft.extraArgs = (modelDraft.extraArgs || 0) + 1;
          render();
        });
        const savePerm = document.getElementById("btn-save-model-perm");
        if (savePerm) savePerm.addEventListener("click", () => {
          vscode.postMessage({ type: "saveModel", payload: { ...modelDraft, temporary: false } });
        });
        const saveTemp = document.getElementById("btn-save-model-temp");
        if (saveTemp) saveTemp.addEventListener("click", () => {
          vscode.postMessage({ type: "saveModel", payload: { ...modelDraft, temporary: true } });
        });

        // AI Tab Events
        for (const id of ["btn-ai-run", "btn-ai-run-empty"]) {
          const el = document.getElementById(id);
          if (el) el.addEventListener("click", () => vscode.postMessage({ type: "verifyAi" }));
        }
        const aiStop = document.getElementById("btn-ai-stop");
        if (aiStop) aiStop.addEventListener("click", () => vscode.postMessage({ type: "stopAi", uriString: state.ai.uriString }));
        const aiCopyEmpty = document.getElementById("btn-ai-copy-empty");
        if (aiCopyEmpty) aiCopyEmpty.addEventListener("click", () => vscode.postMessage({ type: "copyAiPrompt" }));
        const aiCopyReport = document.getElementById("btn-ai-copy-report");
        if (aiCopyReport) aiCopyReport.addEventListener("click", () => vscode.postMessage({ type: "copyText", text: state.ai.markdown || "" }));
        const aiOpenRaw = document.getElementById("btn-ai-open-raw");
        if (aiOpenRaw) aiOpenRaw.addEventListener("click", () => vscode.postMessage({ type: "openRawAiReport", uriString: state.ai.uriString }));
        const aiKey = document.getElementById("btn-ai-key");
        if (aiKey) aiKey.addEventListener("click", () => vscode.postMessage({ type: "setAiApiKey" }));
        for (const copyBtn of document.querySelectorAll(".md-copy-code")) {
          copyBtn.addEventListener("click", () => vscode.postMessage({ type: "copyText", text: copyBtn.getAttribute("data-copy") || "" }));
        }

        // Notes Tab Events
        const noteType = document.getElementById("note-type");
        if (noteType) noteType.addEventListener("change", () => { noteDraft.type = noteType.value; });
        const noteText = document.getElementById("note-text");
        if (noteText) noteText.addEventListener("input", () => { noteDraft.note = noteText.value; });
        const saveNote = document.getElementById("btn-save-note");
        if (saveNote) saveNote.addEventListener("click", () => {
          vscode.postMessage({ type: "saveNote", payload: { ...noteDraft } });
        });
        for (const btn of document.querySelectorAll("[data-open-note]")) {
          btn.addEventListener("click", () => vscode.postMessage({ type: "openNote", id: btn.getAttribute("data-open-note") }));
        }
        for (const btn of document.querySelectorAll("[data-remove-note]")) {
          btn.addEventListener("click", () => vscode.postMessage({ type: "removeNote", id: btn.getAttribute("data-remove-note") }));
        }
      }

      window.addEventListener("message", event => {
        const msg = event.data;
        if (!msg || typeof msg !== "object") return;
        if (msg.type === "state" && msg.state) {
          const prevKey = state.findingId + ":" + state.title;
          state = msg.state;
          if ((state.findingId + ":" + state.title) !== prevKey) {
            openModelKey = null;
            modelFeedback = null;
          }
          render();
        } else if (msg.type === "ai" && msg.ai) {
          state.ai = msg.ai;
          if (msg.switchTab) activeTab = "ai";
          if (activeTab === "ai") render();
          else {
            const tabBtn = document.querySelector('[data-tab="ai"]');
            if (tabBtn && msg.ai.status === "streaming" && !tabBtn.querySelector(".live-dot")) {
              const dot = document.createElement("span");
              dot.className = "live-dot";
              tabBtn.appendChild(dot);
            }
          }
        } else if (msg.type === "modelSaved") {
          modelFeedback = { ok: Boolean(msg.ok), message: msg.message || "" };
          if (msg.ok) openModelKey = null;
          render();
        } else if (msg.type === "noteSaved") {
          noteFeedback = { ok: Boolean(msg.ok), message: msg.message || "" };
          if (msg.ok) noteDraft.note = "";
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
    this._startSub?.dispose();
    this._sessionSub?.dispose();
    this._aiSub?.dispose();
    this._panel?.dispose();
    this._panel = undefined;
  }
}

module.exports = { TraceInspectorPanel, buildTraceInspectorState, extractCallMetadata };
