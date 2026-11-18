"use strict";

const vscode = require("vscode");

function isChineseLocale() {
  return /^zh(?:-|_|$)/i.test(String(vscode.env?.language || ""));
}

function createDecorations() {
  return {
    source: vscode.window.createTextEditorDecorationType({
      isWholeLine: true,
      overviewRulerColor: new vscode.ThemeColor("editorInfo.foreground"),
      overviewRulerLane: vscode.OverviewRulerLane.Right,
      after: { contentText: "  ◀ input", color: new vscode.ThemeColor("editorInfo.foreground"), fontStyle: "italic" },
    }),
    sink: vscode.window.createTextEditorDecorationType({
      isWholeLine: true,
      overviewRulerColor: new vscode.ThemeColor("editorError.foreground"),
      overviewRulerLane: vscode.OverviewRulerLane.Right,
      after: { contentText: "  ◀ sink", color: new vscode.ThemeColor("editorError.foreground"), fontStyle: "italic" },
    }),
    auth: vscode.window.createTextEditorDecorationType({
      isWholeLine: true,
      overviewRulerColor: new vscode.ThemeColor("testing.iconPassed"),
      overviewRulerLane: vscode.OverviewRulerLane.Right,
      after: { contentText: "  ◀ authz", color: new vscode.ThemeColor("testing.iconPassed"), fontStyle: "italic" },
    }),
    sanitizer: vscode.window.createTextEditorDecorationType({
      isWholeLine: true,
      overviewRulerColor: new vscode.ThemeColor("charts.green"),
      overviewRulerLane: vscode.OverviewRulerLane.Right,
      after: { contentText: "  ◀ sanitized", color: new vscode.ThemeColor("charts.green"), fontStyle: "italic" },
    }),
  };
}

// Token-level highlights stay strictly on the variable/call span so they never
// split code expressions mid-line (e.g. inside function call parentheses).
function createTracePathDecorations() {
  return {
    source: vscode.window.createTextEditorDecorationType({
      backgroundColor: new vscode.ThemeColor("editor.wordHighlightBackground"),
      borderColor: new vscode.ThemeColor("editorInfo.foreground"),
      borderStyle: "solid",
      borderWidth: "0 0 2px 0",
      borderRadius: "2px",
      overviewRulerColor: new vscode.ThemeColor("editorInfo.foreground"),
      overviewRulerLane: vscode.OverviewRulerLane.Right,
    }),
    flow: vscode.window.createTextEditorDecorationType({
      backgroundColor: new vscode.ThemeColor("editor.wordHighlightStrongBackground"),
      borderColor: new vscode.ThemeColor("editorWarning.foreground"),
      borderStyle: "dotted",
      borderWidth: "0 0 2px 0",
      borderRadius: "2px",
      overviewRulerColor: new vscode.ThemeColor("editorWarning.foreground"),
      overviewRulerLane: vscode.OverviewRulerLane.Right,
    }),
    sink: vscode.window.createTextEditorDecorationType({
      backgroundColor: new vscode.ThemeColor("editor.findMatchHighlightBackground"),
      borderColor: new vscode.ThemeColor("editorError.foreground"),
      borderStyle: "solid",
      borderWidth: "0 0 2px 0",
      borderRadius: "2px",
      overviewRulerColor: new vscode.ThemeColor("editorError.foreground"),
      overviewRulerLane: vscode.OverviewRulerLane.Right,
    }),
  };
}

// End-of-line semantic badges complement token highlights cleanly without
// interrupting code readability.
function createTraceLineDecorations() {
  return {
    source: vscode.window.createTextEditorDecorationType({
      isWholeLine: true,
      after: { contentText: "  ◀ source", color: new vscode.ThemeColor("editorInfo.foreground"), fontStyle: "italic" },
    }),
    flow: vscode.window.createTextEditorDecorationType({
      isWholeLine: true,
      after: { contentText: "  ◀ flow", color: new vscode.ThemeColor("editorWarning.foreground"), fontStyle: "italic" },
    }),
    sink: vscode.window.createTextEditorDecorationType({
      isWholeLine: true,
      after: { contentText: "  ◀ sink", color: new vscode.ThemeColor("editorError.foreground"), fontStyle: "italic" },
    }),
  };
}

function traceStepRange(document, step) {
  const lineIndex = Math.max(0, Math.min(document.lineCount - 1, Number(step?.line || 1) - 1));
  const line = document.lineAt(lineIndex);
  const candidates = [
    step?.outputAccessPath,
    step?.inputAccessPath,
    ...(step?.accessPaths || []),
  ].map(value => String(value || "").trim()).filter(Boolean);
  for (const candidate of candidates) {
    const variants = [candidate, candidate.replace(/^\$/, "")];
    for (const variant of variants) {
      const index = line.text.indexOf(variant);
      if (index >= 0) return new vscode.Range(lineIndex, index, lineIndex, index + variant.length);
    }
    const leaf = candidate.match(/[A-Za-z_$][\w$]*$/)?.[0];
    if (leaf) {
      const match = new RegExp(`\\b${escapeRegExp(leaf)}\\b`).exec(line.text);
      if (match) return new vscode.Range(lineIndex, match.index, lineIndex, match.index + match[0].length);
    }
  }
  const first = line.firstNonWhitespaceCharacterIndex;
  return new vscode.Range(lineIndex, first, lineIndex, Math.max(first, line.range.end.character));
}

function queryNodeHover(node) {
  const markdown = new vscode.MarkdownString();
  markdown.supportThemeIcons = true;
  markdown.appendMarkdown(`$(debug-stackframe) **${String(node.kind || "step").toUpperCase()}** · \`${node.status || "unresolved"}\`\n\n`);
  markdown.appendText(node.label || "Analysis step");
  if (node.reason) markdown.appendText(`\n\n${node.reason}`);
  if (node.location?.code) markdown.appendCodeblock(node.location.code);
  return markdown;
}

function tracePathHover(flowPath, activeIndex) {
  const zh = isChineseLocale();
  const steps = flowPath?.steps || [];
  const source = steps.find(step => step.kind === "source") || flowPath?.source;
  const sink = [...steps].reverse().find(step => step.kind === "sink") || flowPath?.sink;
  const middle = steps.filter(step => !["source", "sink"].includes(step.kind));
  const middleLabels = middle.slice(0, 3).map(traceStepSubject);
  const labels = zh
    ? { title: "TraceGuard 污点路径", source: "入口", flow: "流向", sink: "危险点" }
    : { title: "TraceGuard taint path", source: "Source", flow: "Flow", sink: "Sink" };
  const chain = [
    `[${labels.source}: ${traceStepSubject(source)}]`,
    ...(middleLabels.length ? [`[${labels.flow}: ${middleLabels.join(" → ")}${middle.length > middleLabels.length ? " → …" : ""}]`] : []),
    `[${labels.sink}: ${traceStepSubject(sink)}]`,
  ].join(" → ");
  const active = steps[activeIndex];
  const markdown = new vscode.MarkdownString();
  markdown.supportThemeIcons = true;
  markdown.appendMarkdown(`### $(debug-stackframe) ${labels.title} · ${Math.max(1, activeIndex + 1)}/${steps.length}\n\n`);
  markdown.appendText(chain);
  if (active) {
    markdown.appendMarkdown("\n\n---\n\n");
    markdown.appendMarkdown(`**${String(active.kind || "flow").toUpperCase()}** · `);
    markdown.appendText(active.label || "Analysis step");
    if (active.code) markdown.appendCodeblock(active.code);
  }
  return markdown;
}

function traceStepSubject(step) {
  return String(step?.outputAccessPath || step?.inputAccessPath || step?.accessPaths?.[0] || step?.label || "unknown");
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = {
  createDecorations,
  createTracePathDecorations,
  createTraceLineDecorations,
  traceStepRange,
  queryNodeHover,
  tracePathHover,
  traceStepSubject,
  escapeRegExp,
};
