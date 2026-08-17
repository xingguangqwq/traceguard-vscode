"use strict";

const vscode = require("vscode");
const { AuditController } = require("./src/audit-controller");

class TraceGuardExtension {
  constructor(context) {
    this.output = vscode.window.createOutputChannel("TraceGuard Audit", { log: true });
    this.audit = new AuditController(context, this.output);
    context.subscriptions.push(this.output);
  }

  dispose() {
    this.audit?.dispose();
  }
}

function activate(context) {
  const extension = new TraceGuardExtension(context);
  context.subscriptions.push(extension);
  extension.audit.initialize().catch(error => {
    extension.output.error(`Initial code index failed: ${firstLine(error?.message || error)}`);
  });
  return extension;
}

function deactivate() {}

function firstLine(value) {
  return String(value || "Unknown error").split(/\r?\n/)[0].slice(0, 280);
}

module.exports = { activate, deactivate, TraceGuardExtension, firstLine };
