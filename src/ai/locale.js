"use strict";
// @ts-check

const english = {
  keyTitle: "API key for",
  keyPrompt: "Stored in VS Code SecretStorage for this endpoint. Leave blank to cancel.",
  keySaved: "$(key) TraceGuard API key saved securely",
  keyRemoved: "$(key) Stored key removed. A configured ai.apiKey, if present, still applies.",
  promptCopied: "Trace prompt copied. Paste it into your preferred AI assistant or local model.",
  traceRequired: "Run a trace before verifying a chain with AI.",
  requestsFull: "Three AI requests are running. Cancel or finish one before starting another.",
  reportLimit: "Close an existing AI report before opening another (20 report limit).",
  reportTitle: "# TraceGuard AI Review",
  reportNotice: "> AI suggestions require human review and never automatically mark a trace Safe.",
  preparing: "Preparing trace context…",
  generating: "Generating… Cancel from the progress notification.",
  complete: "Review complete. Check the evidence before marking Safe / Ignored.",
  cancelled: "Cancelled. The output above is incomplete.",
  failed: "Review failed. The output above is incomplete.",
  closed: "Report closed.",
};

/** @type {Record<keyof typeof english, string>} */
const chinese = {
  keyTitle: "API 密钥：",
  keyPrompt: "密钥按端点保存在 VS Code SecretStorage 中。留空取消。",
  keySaved: "$(key) TraceGuard API 密钥已安全保存",
  keyRemoved: "$(key) 已移除存储的密钥。如仍配置 ai.apiKey，该配置依然生效。",
  promptCopied: "已复制追踪切片 Prompt，可粘贴至 AI 助手或本地模型。",
  traceRequired: "请先运行追踪，再使用 AI 研判链路。",
  requestsFull: "已有三个 AI 请求正在运行。请先取消或完成其中一个。",
  reportLimit: "最多保留 20 份 AI 报告，请关闭一份后再创建。",
  reportTitle: "# TraceGuard AI 研判",
  reportNotice: "> AI 建议需人工复核，不会自动标记 Safe。",
  preparing: "正在准备切片…",
  generating: "正在生成… 可在进度通知中取消。",
  complete: "研判完成。请人工核对证据，再决定是否标记 Safe / Ignored。",
  cancelled: "已取消，以上仅为未完成的输出。",
  failed: "研判失败，以上仅为未完成的输出。",
  closed: "报告已关闭。",
};

/** @param {string} [language] @returns {'zh' | 'en'} */
function aiLanguage(language = "en") { return /^zh(?:-|_|$)/i.test(language) ? "zh" : "en"; }

/** @param {string} [language] */
function aiStrings(language) { return aiLanguage(language) === "zh" ? chinese : english; }

module.exports = { aiLanguage, aiStrings };
