"use strict";

function normalizeText(text) { return String(text || "").replace(/\r\n?/g, "\n"); }

function createEvidenceAnchor(text, line, endLine = line) {
  return contextAnchor(normalizeText(text).split("\n"), line, endLine);
}

function contextAnchor(lines, line, endLine) {
  return {
    version: 1,
    before: lines.slice(Math.max(0, line - 3), line - 1).join("\n").slice(-1000),
    after: lines.slice(endLine, endLine + 2).join("\n").slice(0, 1000),
  };
}

function sanitizeEvidenceAnchor(anchor) {
  if (anchor?.version !== 1 || typeof anchor.before !== "string" || typeof anchor.after !== "string") return undefined;
  return { version: 1, before: anchor.before.slice(-1000), after: anchor.after.slice(0, 1000) };
}

function resolveEvidenceLocation(note, source) {
  const text = normalizeText(source);
  const code = normalizeText(note.code).trim();
  if (!code) return { status: "stale" };
  const lines = text.split("\n");
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") starts.push(i + 1);
  const span = code.split("\n").length - 1;
  const matches = [];
  for (let offset = text.indexOf(code); offset !== -1; offset = text.indexOf(code, offset + 1)) {
    if (matches.length >= 500) return { status: "stale" };
    let low = 0, high = starts.length;
    while (low < high) {
      const middle = (low + high) >>> 1;
      if (starts[middle] <= offset) low = middle + 1;
      else high = middle;
    }
    matches.push({ line: low, endLine: low + span });
  }
  let candidates = matches;
  const anchor = sanitizeEvidenceAnchor(note.anchor);
  if (candidates.length > 1 && anchor) candidates = candidates.filter(match => {
    const context = contextAnchor(lines, match.line, match.endLine);
    return context.before === anchor.before && context.after === anchor.after;
  });
  if (candidates.length !== 1) return { status: "stale" };
  const match = candidates[0];
  return { status: match.line === note.line ? "current" : "relocated", ...match };
}

module.exports = { createEvidenceAnchor, sanitizeEvidenceAnchor, resolveEvidenceLocation };
