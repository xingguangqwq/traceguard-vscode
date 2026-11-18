"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");

const MAX_SNIPPET_FILE_BYTES = 2 * 1024 * 1024;

function createNonce() {
  return crypto.randomBytes(16).toString("base64");
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function safeJsonForHtml(value) {
  return JSON.stringify(value ?? null)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

function isChineseLocale(language) {
  return /^zh(?:-|_|$)/i.test(String(language || ""));
}

function buildCsp(webview, nonce) {
  const source = webview?.cspSource || "self";
  return [
    "default-src 'none'",
    `img-src ${source} data:`,
    `style-src ${source} 'nonce-${nonce}'`,
    `script-src 'nonce-${nonce}'`,
  ].join("; ");
}

async function readCodeSnippet(absolutePath, lineNumber, radius = 1, readOpenDocument) {
  const targetLine = Math.max(1, Number(lineNumber) || 1);
  if (!absolutePath) return undefined;
  let text;
  if (typeof readOpenDocument === "function") {
    try { text = await readOpenDocument(absolutePath); } catch { text = undefined; }
  }
  if (typeof text !== "string") {
    try {
      const stat = await fs.stat(absolutePath);
      if (stat.size > MAX_SNIPPET_FILE_BYTES) return undefined;
      text = await fs.readFile(absolutePath, "utf8");
    } catch {
      return undefined;
    }
  }
  const allLines = text.split(/\r?\n/);
  if (!allLines.length) return undefined;
  const clampedTarget = Math.min(allLines.length, targetLine);
  const start = Math.max(1, clampedTarget - radius);
  const end = Math.min(allLines.length, clampedTarget + radius);
  const rawLines = [];
  for (let line = start; line <= end; line += 1) {
    rawLines.push({ number: line, text: allLines[line - 1] ?? "", active: line === clampedTarget });
  }
  const indents = rawLines
    .filter(item => item.text.trim().length > 0)
    .map(item => (item.text.match(/^\s*/) || [""])[0].length);
  const minIndent = indents.length ? Math.min(...indents) : 0;
  const lines = rawLines.map(item => ({
    number: item.number,
    text: item.text.slice(minIndent).slice(0, 220),
    active: item.active,
  }));
  return {
    lines,
    targetLineText: allLines[clampedTarget - 1] || "",
  };
}

// Lightweight, XSS-safe Markdown renderer for the Trace Inspector AI drawer.
function renderMarkdownToHtml(source) {
  const text = String(source || "").replace(/\r\n?/g, "\n");
  if (!text.trim()) return "";
  const lines = text.split("\n");
  const html = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];

    // Fenced code block
    const fenceMatch = line.match(/^```([A-Za-z0-9_+.-]*)\s*$/);
    if (fenceMatch) {
      const lang = fenceMatch[1] || "";
      const codeLines = [];
      index += 1;
      while (index < lines.length && !/^```\s*$/.test(lines[index])) {
        codeLines.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      const codeContent = codeLines.join("\n");
      const langBadge = lang ? `<span class="md-code-lang">${escapeHtml(lang)}</span>` : "";
      html.push(
        `<div class="md-code-wrap"><div class="md-code-head">${langBadge}<button class="icon-btn md-copy-code" data-copy="${escapeHtml(codeContent)}" title="Copy code">Copy</button></div><pre class="md-pre"><code>${escapeHtml(codeContent)}</code></pre></div>`,
      );
      continue;
    }

    // Blank line
    if (!line.trim()) {
      index += 1;
      continue;
    }

    // Horizontal rule
    if (/^\s*(?:---+|___+|\*\*\*+)\s*$/.test(line)) {
      html.push('<hr class="md-hr"/>');
      index += 1;
      continue;
    }

    // Heading
    const headingMatch = line.match(/^(#{1,4})\s+(.+)$/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      html.push(`<h${level} class="md-h${level}">${renderInlineMarkdown(headingMatch[2].trim())}</h${level}>`);
      index += 1;
      continue;
    }

    // Blockquote
    if (/^>\s?/.test(line)) {
      const quoteLines = [];
      while (index < lines.length && /^>\s?/.test(lines[index])) {
        quoteLines.push(lines[index].replace(/^>\s?/, ""));
        index += 1;
      }
      html.push(`<blockquote class="md-quote">${quoteLines.map(renderInlineMarkdown).join("<br/>")}</blockquote>`);
      continue;
    }

    // Unordered list
    if (/^\s*[-*+]\s+/.test(line)) {
      const items = [];
      while (index < lines.length && /^\s*[-*+]\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^\s*[-*+]\s+/, ""));
        index += 1;
      }
      html.push(`<ul class="md-list">${items.map(item => `<li>${renderInlineMarkdown(item)}</li>`).join("")}</ul>`);
      continue;
    }

    // Ordered list
    if (/^\s*\d+\.\s+/.test(line)) {
      const items = [];
      while (index < lines.length && /^\s*\d+\.\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^\s*\d+\.\s+/, ""));
        index += 1;
      }
      html.push(`<ol class="md-list md-olist">${items.map(item => `<li>${renderInlineMarkdown(item)}</li>`).join("")}</ol>`);
      continue;
    }

    // Paragraph
    const paragraph = [];
    while (
      index < lines.length
      && lines[index].trim()
      && !/^```/.test(lines[index])
      && !/^#{1,4}\s+/.test(lines[index])
      && !/^>\s?/.test(lines[index])
      && !/^\s*[-*+]\s+/.test(lines[index])
      && !/^\s*\d+\.\s+/.test(lines[index])
      && !/^\s*(?:---+|___+|\*\*\*+)\s*$/.test(lines[index])
    ) {
      paragraph.push(lines[index]);
      index += 1;
    }
    html.push(`<p class="md-p">${paragraph.map(renderInlineMarkdown).join("<br/>")}</p>`);
  }

  return html.join("\n");
}

function renderInlineMarkdown(raw) {
  const escaped = escapeHtml(raw);
  const codeSegments = [];
  const withPlaceholders = escaped.replace(/`([^`]+)`/g, (_, content) => {
    const token = `\u0000CODE${codeSegments.length}\u0000`;
    codeSegments.push(`<code class="md-inline-code">${content}</code>`);
    return token;
  });
  const formatted = withPlaceholders
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/__([^_]+)__/g, "<strong>$1</strong>")
    .replace(/(^|[\s(])\*([^*]+)\*(?=[\s).,;:!?]|$)/g, "$1<em>$2</em>");
  return formatted.replace(/\u0000CODE(\d+)\u0000/g, (_, idx) => codeSegments[Number(idx)] || "");
}

// Crisp monochrome 16x16 inline SVG icons (zero external font dependencies).
const SVG_ICONS = {
  shield: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.35" stroke-linejoin="round"><path d="M8 1.5 2.75 3.6v3.8c0 3.3 2.15 6.1 5.25 7.1 3.1-1 5.25-3.8 5.25-7.1V3.6L8 1.5Z"/><path d="M5.7 6.2h2.7a.95.95 0 0 1 .95.95v.25a.95.95 0 0 1-.95.95h-.8a.95.95 0 0 0-.95.95v.5h3.7" stroke-linecap="round"/><circle cx="5.6" cy="6.2" r=".85" fill="currentColor" stroke="none"/><circle cx="10.4" cy="9.8" r=".85" fill="currentColor" stroke="none"/></svg>',
  refresh: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M13.2 8a5.2 5.2 0 1 1-1.35-3.5"/><path d="M13.2 2.4v2.6h-2.6"/></svg>',
  search: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"><circle cx="7.2" cy="7.2" r="4.5"/><path d="m10.7 10.7 3 3"/></svg>',
  clear: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M4.5 4.5 11.5 11.5M11.5 4.5 4.5 11.5"/></svg>',
  play: '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M4.5 3.1v9.8a.5.5 0 0 0 .77.42l7.6-4.9a.5.5 0 0 0 0-.84l-7.6-4.9a.5.5 0 0 0-.77.42Z"/></svg>',
  settings: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="8" r="2.2"/><path d="M8 2v1.4M8 12.6V14M2 8h1.4M12.6 8H14M3.75 3.75l1 1M11.25 11.25l1 1M12.25 3.75l-1 1M4.75 11.25l-1 1"/></svg>',
  globe: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3"><circle cx="8" cy="8" r="5.8"/><ellipse cx="8" cy="8" rx="2.7" ry="5.8"/><path d="M2.5 8h11"/></svg>',
  source: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.45" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 8h9.5"/><path d="M8.5 4.5 12 8l-3.5 3.5"/></svg>',
  sink: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.35"><circle cx="8" cy="8" r="5.5"/><circle cx="8" cy="8" r="2.6"/><circle cx="8" cy="8" r=".8" fill="currentColor" stroke="none"/></svg>',
  call: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3.5 4.5h4.8v4.8"/><path d="M8.3 4.5 3.5 9.3"/><path d="M8.2 11.5h4.5"/><path d="m10.7 9.5 2 2-2 2"/></svg>',
  guard: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M8 1.8 3 3.8v3.6c0 3.1 2 5.7 5 6.8 3-1.1 5-3.7 5-6.8V3.8L8 1.8Z"/><path d="m5.8 8.1 1.5 1.5 3-3.2"/></svg>',
  disconnect: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"><path d="M2.5 8h3.3M10.2 8h3.3"/><path d="M6.4 5.5 9.6 10.5M9.6 5.5 6.4 10.5"/></svg>',
  sparkle: '<svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 1.5 9.4 5.8 13.7 7.2 9.4 8.6 8 12.9 6.6 8.6 2.3 7.2 6.6 5.8 8 1.5Z"/><path d="M12.5 10.3 13.1 12 14.8 12.6 13.1 13.2 12.5 14.9 11.9 13.2 10.2 12.6 11.9 12 12.5 10.3Z"/></svg>',
  check: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="m3.2 8.4 3 3 6.6-6.8"/></svg>',
  slash: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"><circle cx="8" cy="8" r="5.5"/><path d="M4.3 11.7 11.7 4.3"/></svg>',
  bookmark: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.35" stroke-linejoin="round"><path d="M4 2.5h8v11l-4-2.8-4 2.8v-11Z"/></svg>',
  copy: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.35" stroke-linejoin="round"><rect x="5.2" y="5.2" width="7.8" height="8.3" rx="1.2"/><path d="M3.2 10.8V3.7A1.2 1.2 0 0 1 4.4 2.5h6.1"/></svg>',
  wrench: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" stroke-linejoin="round"><path d="M10.4 2.4a3.2 3.2 0 0 0-3.9 4.2l-3.6 3.6a1.4 1.4 0 0 0 2 2l3.6-3.6a3.2 3.2 0 0 0 4.2-3.9L11 6.4 9.6 5l1.7-1.7a3 3 0 0 0-.9-.9Z"/></svg>',
  chevron: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 4.2 4 3.8-4 3.8"/></svg>',
  stop: '<svg viewBox="0 0 16 16" fill="currentColor"><rect x="3.5" y="3.5" width="9" height="9" rx="1.5"/></svg>',
  external: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" stroke-linejoin="round"><path d="M9.5 2.5h4v4"/><path d="M7.5 8.5 13.5 2.5"/><path d="M12.5 9v3.3a1.2 1.2 0 0 1-1.2 1.2H3.7a1.2 1.2 0 0 1-1.2-1.2V4.7a1.2 1.2 0 0 1 1.2-1.2H7"/></svg>',
  arrowUp: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 12.5V3.5M4.5 7 8 3.5 11.5 7"/></svg>',
  arrowDown: '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3.5v9M4.5 9 8 12.5 11.5 9"/></svg>',
};

module.exports = {
  SVG_ICONS,
  buildCsp,
  createNonce,
  escapeHtml,
  isChineseLocale,
  readCodeSnippet,
  renderMarkdownToHtml,
  safeJsonForHtml,
};
