"use strict";

const vscode = require("vscode");
const { normalizeAccessPath } = require("../ir/access-path");

function selectedAccessPath(editor) {
  const selected = editor.document.getText(editor.selection).trim();
  const accessPath = /^\$?[A-Za-z_][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*|\[(?:\d+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\])*$/;
  if (accessPath.test(selected)) return normalizeAccessPath(selected, { dynamic: false });
  const range = editor.document.getWordRangeAtPosition(
    editor.selection.active,
    /\$?[A-Za-z_][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*|\[(?:\d+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')\])*/,
  );
  return range ? normalizeAccessPath(editor.document.getText(range), { dynamic: false }) : "";
}

async function openLocation(absolutePath, line, endLine, existingDocument) {
  const document = existingDocument || await vscode.workspace.openTextDocument(vscode.Uri.file(absolutePath));
  const editor = await vscode.window.showTextDocument(document, { preview: true, preserveFocus: false });
  const start = new vscode.Position(Math.min(document.lineCount - 1, Math.max(0, line - 1)), 0);
  const end = new vscode.Position(Math.min(document.lineCount - 1, Math.max(line - 1, (endLine || line) - 1)), 0);
  editor.selection = new vscode.Selection(start, start);
  editor.revealRange(new vscode.Range(start, end), vscode.TextEditorRevealType.InCenterIfOutsideViewport);
  return editor;
}

module.exports = { selectedAccessPath, openLocation };
