"use strict";

const { TreeSitterRuntime } = require("../frontends/tree-sitter-runtime");
const { normalizePath } = require("../identity");
const { markdownFence } = require("../markdown");

const FUNCTION_TYPES = new Set([
  "function_declaration", "function_expression", "generator_function", "generator_function_declaration",
  "arrow_function", "method_definition", "method_declaration", "constructor_declaration",
  "function_definition", "lambda", "lambda_expression", "anonymous_function",
  "anonymous_function_creation_expression", "local_function_statement", "anonymous_method_expression", "func_literal",
]);

async function buildSliceContext(chain, options = {}) {
  options.signal?.throwIfAborted();
  const slice = { schema: "traceguard-slice-v1", title: chain?.title || "Source → Sink", direction: chain?.kind || "source-to-sink", steps: [], edges: [], functions: [], omissions: [] };
  const isReviewed = options.isReviewed || (() => false);
  const add = (node, parent, inherited = false) => {
    const location = node.location || node;
    const step = {
      id: slice.steps.length + 1, parent, kind: node.kind || "flow", label: node.label || "Analysis step",
      status: node.status || node.analysisStatus || "unresolved", reason: node.reason || node.candidateReason || "",
      reviewStatus: inherited || isReviewed(node) ? "safe/ignored" : "unreviewed",
      absolutePath: location.absolutePath, relativePath: location.relativePath,
      line: location.line, code: location.code || node.code || "",
    };
    slice.steps.push(step);
    if (parent) slice.edges.push({ from: parent, to: step.id });
    return step;
  };
  const walk = (nodes, parent, inherited) => {
    for (const node of nodes || []) {
      const step = add(node, parent, inherited);
      walk(node.children, step.id, step.reviewStatus === "safe/ignored");
    }
  };
  if (chain?.roots) walk(chain.roots);
  else for (const node of chain?.steps || []) add(node, slice.steps.at(-1)?.id);
  if (chain?.truncated || chain?.interruption) slice.omissions.push("The analysis path is partial or interrupted.");

  if (!options.readSource) return slice;
  const runtime = new TreeSitterRuntime({ maxTrees: 1 });
  const files = new Map();
  for (const step of slice.steps) {
    if (!step.absolutePath || !step.line) continue;
    const key = normalizePath(step.absolutePath);
    if (!files.has(key)) files.set(key, []);
    files.get(key).push(step);
  }
  let totalBytes = 0;
  let fileCount = 0;
  try {
    for (const [key, steps] of files) {
      options.signal?.throwIfAborted();
      if (++fileCount > 40 || slice.functions.length >= 100 || totalBytes >= 512 * 1024) {
        slice.omissions.push(`${steps[0].relativePath || key}: slice size limit reached`);
        continue;
      }
      try {
        const source = await options.readSource(steps[0].absolutePath);
        options.signal?.throwIfAborted();
        if (Buffer.byteLength(source.text, "utf8") > 1024 * 1024) throw new Error("file exceeds the 1 MiB slice parsing limit");
        const { tree } = await runtime.parse({ absolutePath: key, language: source.language, text: source.text, options: { languageAssets: options.languageAssets } });
        const functions = [];
        const visit = node => {
          if (FUNCTION_TYPES.has(node.type)) functions.push(node);
          for (const child of node.namedChildren) visit(child);
        };
        visit(tree.rootNode);
        const extracted = new Map();
        for (const step of steps) {
          const candidates = functions.filter(node => node.startPosition.row < step.line && node.endPosition.row >= step.line - 1);
          const fn = candidates.sort((a, b) => (a.endIndex - a.startIndex) - (b.endIndex - b.startIndex))[0];
          if (!fn || fn.hasError) {
            slice.omissions.push(`${step.relativePath || key}:${step.line}: no complete enclosing function found`);
            continue;
          }
          const identity = `${fn.startIndex}:${fn.endIndex}`;
          if (!extracted.has(identity)) {
            const code = fn.text;
            const bytes = Buffer.byteLength(code, "utf8");
            if (totalBytes + bytes > 512 * 1024 || slice.functions.length >= 100) {
              slice.omissions.push(`${step.relativePath || key}:${step.line}: complete function exceeds slice budget`);
              continue;
            }
            const entry = { id: slice.functions.length + 1, absolutePath: step.absolutePath, relativePath: step.relativePath, language: source.language, startLine: fn.startPosition.row + 1, endLine: fn.endPosition.row + 1, code };
            slice.functions.push(entry);
            extracted.set(identity, entry.id);
            totalBytes += bytes;
          }
          step.functionId = extracted.get(identity);
        }
      } catch (error) {
        if (options.signal?.aborted) throw error;
        slice.omissions.push(`${steps[0].relativePath || key}: ${error.message}`);
      } finally {
        runtime.remove(key);
      }
    }
  } finally {
    for (const parser of runtime.parsers.values()) parser.delete();
  }
  return slice;
}

function formatSliceMarkdown(slice) {
  const safe = value => String(value || "").replace(/[\\`*_{}\[\]<>#|]/g, "\\$&").replace(/[\r\n]+/g, " ");
  const lines = [`### 🔍 TraceGuard ${safe(slice.title)}`, "", `Direction: ${safe(slice.direction)}`, "", "Safe / Ignored is a manual review decision, not proof of safety.", ""];
  for (const step of slice.steps) {
    lines.push(`${step.id}. **[${safe(step.kind)}]** ${safe(step.relativePath || step.absolutePath || "unknown")}:${step.line || "?"} — ${safe(step.status)}${step.reviewStatus === "safe/ignored" ? " · ✅ Safe / Ignored" : ""}`);
    if (step.parent) lines.push(`   Branch: ${step.parent} → ${step.id}`);
    if (step.reason) lines.push(`   ${safe(step.reason)}`);
    if (step.code) {
      const fence = markdownFence(step.code);
      lines.push("", `   ${fence}`, ...step.code.split(/\r?\n/).map(line => `   ${line}`), `   ${fence}`, "");
    }
  }
  if (slice.functions.length) lines.push("", "#### Enclosing functions", "");
  for (const fn of slice.functions) {
    const fence = markdownFence(fn.code);
    lines.push(`**${safe(fn.relativePath || fn.absolutePath)}:${fn.startLine}–${fn.endLine}**`, "", `${fence}${fn.language}`, fn.code, fence, "");
  }
  if (slice.omissions.length) lines.push("", "#### Missing context", "", ...slice.omissions.map(item => `- ${safe(item)}`));
  return lines.join("\n");
}

module.exports = { buildSliceContext, formatSliceMarkdown };
