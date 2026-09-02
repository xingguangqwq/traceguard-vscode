"use strict";

const MAX_SOURCE_LINE_LENGTH = 20_000;
const DEFAULT_MAX_SOURCE_BYTES = 256 * 1024;
const MAX_IR_FUNCTIONS_PER_FILE = 5_000;
const MAX_IR_OPERATIONS_PER_FILE = 100_000;
const MAX_IR_CODE_CHARACTERS_PER_FILE = 8_000_000;

function inspectSourcePath() {
  return accepted();
}

function inspectSourceFile(file = {}, options = {}) {
  if (typeof file.text !== "string") return accepted();
  const maxSourceBytes = Math.max(1, Number(options.maxSourceBytes) || DEFAULT_MAX_SOURCE_BYTES);
  const sourceBytes = Buffer.byteLength(file.text, "utf8");
  if (sourceBytes > maxSourceBytes) {
    return rejected(
      file,
      `Source exceeds the configured ${Math.round(maxSourceBytes / 1024)} KiB per-file parsing budget; it was not sent to the AST frontend.`,
      "source-size-budget",
      { size: sourceBytes, limit: maxSourceBytes },
    );
  }
  const longestLine = firstLineOverLimit(file.text, MAX_SOURCE_LINE_LENGTH);
  if (!longestLine) return accepted();
  return rejected(
    file,
    `Source contains a line longer than ${MAX_SOURCE_LINE_LENGTH.toLocaleString("en-US")} characters; it was skipped to prevent unbounded AST/IR expansion.`,
    "oversized-line",
    { line: longestLine.line, lineLength: longestLine.length, limit: MAX_SOURCE_LINE_LENGTH },
  );
}

function inspectAnalysisComplexity(analysis = {}) {
  const functions = analysis.ir?.functions || [];
  let operations = 0;
  let codeCharacters = 0;
  for (const fn of functions) {
    operations += (fn.operations || []).length;
    for (const operation of fn.operations || []) {
      codeCharacters += String(operation.location?.code || "").length;
      if (operations > MAX_IR_OPERATIONS_PER_FILE || codeCharacters > MAX_IR_CODE_CHARACTERS_PER_FILE) break;
    }
    if (operations > MAX_IR_OPERATIONS_PER_FILE || codeCharacters > MAX_IR_CODE_CHARACTERS_PER_FILE) break;
  }
  const metadata = {
    functions: functions.length,
    operations,
    codeCharacters,
    limits: {
      functions: MAX_IR_FUNCTIONS_PER_FILE,
      operations: MAX_IR_OPERATIONS_PER_FILE,
      codeCharacters: MAX_IR_CODE_CHARACTERS_PER_FILE,
    },
  };
  if (functions.length <= MAX_IR_FUNCTIONS_PER_FILE &&
    operations <= MAX_IR_OPERATIONS_PER_FILE &&
    codeCharacters <= MAX_IR_CODE_CHARACTERS_PER_FILE) return accepted();
  return rejected(
    { absolutePath: analysis.absolutePath, relativePath: analysis.relativePath },
    "Parsed source exceeded the per-file IR complexity budget; the file requires explicit review or a narrower project scope.",
    "ir-complexity-budget",
    metadata,
  );
}

function firstLineOverLimit(text, limit) {
  let line = 1;
  let length = 0;
  for (let index = 0; index < text.length; index += 1) {
    const character = text.charCodeAt(index);
    if (character === 10 || character === 13) {
      if (length > limit) return { line, length };
      if (character === 13 && text.charCodeAt(index + 1) === 10) index += 1;
      line += 1;
      length = 0;
      continue;
    }
    length += 1;
    if (length > limit) return { line, length };
  }
  return length > limit ? { line, length } : undefined;
}

function accepted() {
  return { accepted: true };
}

function rejected(file, reason, code, metadata = {}) {
  return {
    accepted: false,
    detail: {
      absolutePath: String(file.absolutePath || file.fsPath || ""),
      relativePath: String(file.relativePath || file.absolutePath || file.fsPath || ""),
      reason,
      code,
      ...metadata,
    },
  };
}

module.exports = {
  DEFAULT_MAX_SOURCE_BYTES,
  MAX_IR_CODE_CHARACTERS_PER_FILE,
  MAX_IR_FUNCTIONS_PER_FILE,
  MAX_IR_OPERATIONS_PER_FILE,
  MAX_SOURCE_LINE_LENGTH,
  inspectAnalysisComplexity,
  inspectSourceFile,
  inspectSourcePath,
};
