"use strict";

function completionUrl(baseUrl) {
  let url;
  try { url = new URL(String(baseUrl).trim()); } catch { throw new Error("AI Base URL must be an absolute HTTP(S) URL."); }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error("AI Base URL must use HTTP(S), without credentials, query parameters or fragments.");
  }
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/chat/completions`;
  return url.toString();
}

async function streamCompletion({ baseUrl, apiKey, model, messages, signal, onText, timeoutMs = 120_000, fetchImpl = globalThis.fetch }) {
  const url = completionUrl(baseUrl);
  if (!String(model || "").trim()) throw new Error("Set traceguard.ai.model before verifying a chain.");
  if (typeof fetchImpl !== "function") throw new Error("Native fetch is unavailable in this Extension Host. Use Copy AI Prompt or update VS Code.");
  const abort = new AbortController();
  let timedOut = false;
  const cancel = () => abort.abort();
  if (signal?.aborted) cancel();
  signal?.addEventListener("abort", cancel, { once: true });
  const timer = setTimeout(() => { timedOut = true; cancel(); }, timeoutMs);
  let reader;
  let received = 0;
  let done = false;
  let finished = false;
  let buffer = "";
  const emit = text => {
    if (typeof text !== "string" || !text) return;
    received += Buffer.byteLength(text, "utf8");
    if (received > 2 * 1024 * 1024) throw new Error("AI response exceeded the 2 MiB output limit.");
    onText(text);
  };
  const event = block => {
    const data = block.split(/\r?\n/).filter(line => line.startsWith("data:")).map(line => line.slice(5).replace(/^ /, "")).join("\n");
    if (!data.trim()) return;
    if (data.trim() === "[DONE]") { done = true; return; }
    let value;
    try { value = JSON.parse(data); } catch { throw new Error("AI endpoint returned malformed SSE JSON."); }
    if (value.error) throw new Error("AI endpoint reported a streaming error. Check the provider logs.");
    const choice = value.choices?.find(item => item.index === 0) || value.choices?.[0];
    if (!choice) return; // Some providers send a final usage-only event.
    if (choice.delta?.refusal) throw new Error("The model declined this request. Use Copy AI Prompt to review the input.");
    emit(choice.delta?.content);
    if (choice.finish_reason && choice.finish_reason !== "stop") throw new Error(`AI response is incomplete (${String(choice.finish_reason).replace(/[^a-z_]/gi, "").slice(0, 40)}).`);
    if (choice.finish_reason === "stop") finished = true;
  };
  try {
    const response = await fetchImpl(url, {
      method: "POST", signal: abort.signal, redirect: "error",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream", ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}) },
      body: JSON.stringify({ model: String(model).trim(), messages, stream: true }),
    });
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`AI endpoint returned HTTP ${response.status}. ${response.status === 401 || response.status === 403 ? "Check the API key and access permissions." : response.status === 429 ? "Provider rate limit or quota exceeded; retry later." : "Check the Base URL, model and provider logs."}`);
    }
    if (!response.headers.get("content-type")?.includes("text/event-stream") || !response.body) {
      await response.body?.cancel();
      throw new Error("AI endpoint must return a text/event-stream response for stream=true.");
    }
    reader = response.body.getReader();
    const decoder = new TextDecoder();
    while (!done) {
      const chunk = await reader.read();
      buffer += chunk.done ? decoder.decode() : decoder.decode(chunk.value, { stream: true });
      if (buffer.length > 2 * 1024 * 1024) throw new Error("AI SSE event exceeded the buffer limit.");
      let separator;
      while (!done && (separator = /\r?\n\r?\n/.exec(buffer))) {
        event(buffer.slice(0, separator.index));
        buffer = buffer.slice(separator.index + separator[0].length);
      }
      if (chunk.done) { if (buffer.trim() && !done) event(buffer); break; }
    }
    if (!done && !finished) throw new Error("AI stream ended unexpectedly; partial output is not a completed verdict.");
    if (!received) throw new Error("AI endpoint returned no text content.");
  } catch (error) {
    if (timedOut) throw new Error(`AI request timed out after ${Math.ceil(timeoutMs / 1000)} seconds; partial output was retained.`);
    if (signal?.aborted) { const cancelled = new Error("AI verification cancelled."); cancelled.name = "AbortError"; throw cancelled; }
    // Fetch transport errors may contain URLs or credentials; keep the UI message local and predictable.
    if (error instanceof TypeError) throw new Error("Could not connect to the AI endpoint. Check its URL, TLS certificate and network access.");
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", cancel);
    if (reader) { await reader.cancel().catch(() => {}); reader.releaseLock(); }
    abort.abort();
  }
}

module.exports = { completionUrl, streamCompletion };
