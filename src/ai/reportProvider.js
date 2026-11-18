"use strict";

const vscode = require("vscode");
const { aiStrings } = require("./locale");

class AiReportProvider {
  constructor() {
    this.reports = new Map();
    this.latestByChain = new WeakMap();
    this.serial = 0;
    this.changed = new vscode.EventEmitter();
    this.onDidChange = this.changed.event;
  }
  create(onClose, language = "en", { chain, model, endpointHost } = {}) {
    const strings = aiStrings(language);
    if (this.reports.size >= 20) {
      const open = new Set((vscode.workspace?.textDocuments || []).map(doc => doc.uri.toString()));
      const unused = Array.from(this.reports.values()).find(entry => entry.outcome !== "streaming" && !open.has(entry.uri.toString()));
      if (!unused) throw new Error(strings.reportLimit);
      this.close(unused.uri);
    }
    const uri = vscode.Uri.parse(`traceguard-ai:/report-${++this.serial}.md`);
    this.reports.set(uri.toString(), {
      uri, header: `${strings.reportTitle}\n\n${strings.reportNotice}\n\n`, text: "",
      status: strings.preparing, outcome: "streaming", model, endpointHost, onClose,
    });
    if (chain) this.latestByChain.set(chain, uri.toString());
    return uri;
  }
  provideTextDocumentContent(uri) {
    const entry = this.reports.get(uri.toString());
    return entry ? `${entry.header}${entry.text}\n\n---\n${entry.status}\n` : aiStrings(vscode.env?.language).closed;
  }
  append(uri, text) {
    const entry = this.reports.get(uri.toString());
    if (!entry) return;
    entry.text += text;
    if (!entry.timer) entry.timer = setTimeout(() => { entry.timer = undefined; this.changed.fire(uri); }, 100);
  }
  finish(uri, status, outcome = "complete") {
    const entry = this.reports.get(uri.toString());
    if (!entry) return;
    clearTimeout(entry.timer);
    entry.timer = undefined;
    entry.status = status;
    entry.outcome = outcome;
    this.changed.fire(uri);
  }
  close(uri) {
    const entry = this.reports.get(uri.toString());
    if (!entry) return;
    clearTimeout(entry.timer);
    entry.onClose?.();
    this.reports.delete(uri.toString());
    this.changed.fire(uri);
  }
  dispose() {
    this.changed.dispose();
    for (const entry of [...this.reports.values()]) this.close(entry.uri);
  }
}

module.exports = { AiReportProvider };
