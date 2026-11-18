"use strict";

const vscode = require("vscode");
const { stableHash } = require("../identity");
const { buildAiPrompt } = require("./promptBuilder");
const { completionUrl, streamCompletion } = require("./llmClient");
const { AiReportProvider } = require("./reportProvider");
const { aiStrings } = require("./locale");

class AiController {
  constructor(context, audit) {
    this.context = context;
    this.audit = audit;
    this.provider = new AiReportProvider();
    this.requests = new Map();
    this._started = new vscode.EventEmitter();
    this.onDidStartReport = this._started.event;
    context.subscriptions.push(this,
      this._started,
      vscode.workspace.registerTextDocumentContentProvider("traceguard-ai", this.provider),
      vscode.workspace.onDidCloseTextDocument(document => { if (document.uri.scheme === "traceguard-ai") this.provider.close(document.uri); }),
      vscode.commands.registerCommand("traceguard.copyAiPrompt", item => this.copyPrompt(item)),
      vscode.commands.registerCommand("traceguard.verifyChainWithAi", item => this.verify(item)),
      vscode.commands.registerCommand("traceguard.setAiApiKey", () => this.setKey()),
      vscode.commands.registerCommand("traceguard.clearAiApiKey", () => this.clearKey()),
    );
  }

  settings() {
    const config = vscode.workspace.getConfiguration("traceguard");
    const baseUrl = config.get("ai.baseUrl", "http://localhost:11434/v1");
    const endpoint = completionUrl(baseUrl);
    return { baseUrl, endpoint, model: config.get("ai.model", "qwen2.5-coder:14b"), apiKey: config.get("ai.apiKey", ""), secretName: `traceguard.ai.key.${stableHash(endpoint)}` };
  }

  async setKey() {
    try {
      const strings = aiStrings(vscode.env.language);
      const settings = this.settings();
      const key = await vscode.window.showInputBox({ title: `${strings.keyTitle} ${new URL(settings.endpoint).host}`, password: true, ignoreFocusOut: true, prompt: strings.keyPrompt });
      if (!key?.trim()) return;
      await this.context.secrets.store(settings.secretName, key.trim());
      vscode.window.setStatusBarMessage(strings.keySaved, 3000);
    } catch (error) { void vscode.window.showErrorMessage(error.message); }
  }

  async clearKey() {
    try {
      await this.context.secrets.delete(this.settings().secretName);
      vscode.window.setStatusBarMessage(aiStrings(vscode.env.language).keyRemoved, 4000);
    } catch (error) { void vscode.window.showErrorMessage(error.message); }
  }

  chain(item) { return item?.result || item?.flowPath || this.audit.queryProvider.current || this.audit.queryProvider.currentTrace; }

  async copyPrompt(item) {
    try {
      const slice = await this.audit.buildCurrentSlice(this.chain(item));
      const prompt = buildAiPrompt(slice, vscode.env.language);
      await vscode.env.clipboard.writeText(prompt.text);
      void vscode.window.showInformationMessage(aiStrings(vscode.env.language).promptCopied);
    } catch (error) { void vscode.window.showErrorMessage(error.message); }
  }

  async verify(item, options = {}) {
    const language = vscode.env.language;
    const strings = aiStrings(language);
    const chain = this.chain(item);
    if (!chain) { void vscode.window.showInformationMessage(strings.traceRequired); return; }
    if (this.requests.size >= 3) { void vscode.window.showInformationMessage(strings.requestsFull); return; }
    const abort = new AbortController();
    let uri;
    try {
      const settings = this.settings();
      const endpointHost = new URL(settings.endpoint).host;
      uri = this.provider.create(() => abort.abort(), language, { chain, model: settings.model, endpointHost });
      this.requests.set(uri.toString(), abort);
      this._started.fire(uri);
      const apiKey = await this.context.secrets.get(settings.secretName) || settings.apiKey;
      abort.signal.throwIfAborted();
      await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: `TraceGuard AI · ${endpointHost}`, cancellable: true }, async (_progress, token) => {
        const cancel = token.onCancellationRequested(() => abort.abort());
        if (token.isCancellationRequested) abort.abort();
        try {
          if (options.openDocument !== false) {
            const document = await vscode.workspace.openTextDocument(uri);
            const editor = await vscode.window.showTextDocument(document, { viewColumn: this.reportColumn || vscode.ViewColumn.Beside, preview: true });
            this.reportColumn = editor.viewColumn;
          }
          const slice = await this.audit.buildCurrentSlice(chain, abort.signal);
          abort.signal.throwIfAborted();
          const prompt = buildAiPrompt(slice, language);
          this.provider.finish(uri, strings.generating, "streaming");
          await streamCompletion({
            ...settings,
            apiKey,
            messages: prompt.messages,
            signal: abort.signal,
            onText: text => this.provider.append(uri, text),
          });
          this.provider.finish(uri, strings.complete);
        } finally { cancel.dispose(); }
      });
    } catch (error) {
      const status = abort.signal.aborted ? strings.cancelled : `${strings.failed} ${error.message}`;
      if (uri) this.provider.finish(uri, status, abort.signal.aborted ? "cancelled" : "error");
      if (!abort.signal.aborted) void vscode.window.showErrorMessage(status);
    } finally { if (uri) this.requests.delete(uri.toString()); }
    return uri;
  }

  cancelReport(uriString) {
    this.requests.get(uriString)?.abort();
  }

  dispose() {
    for (const request of this.requests.values()) request.abort();
    this.requests.clear();
    this.provider.dispose();
  }
}

module.exports = { AiController };
