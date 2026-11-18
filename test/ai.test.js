"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const test = require("node:test");
const { streamCompletion, completionUrl } = require("../src/ai/llmClient");
const { buildAiPrompt } = require("../src/ai/promptBuilder");

async function serverFor(t, handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return `http://127.0.0.1:${server.address().port}/v1`;
}
const event = (content, extra = {}) => `data: ${JSON.stringify({ choices: [{ index: 0, delta: { content }, ...extra }] })}\r\n\r\n`;
const request = baseUrl => ({ baseUrl, model: "mock-model", messages: [{ role: "user", content: "local test slice" }], onText: () => {} });

test("native fetch handles split UTF-8/SSE, keepalive comments, multiline JSON and DONE", async t => {
  let received;
  const baseUrl = await serverFor(t, async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    received = { url: req.url, key: req.headers.authorization, body: JSON.parse(body) };
    res.writeHead(200, { "content-type": "text/event-stream" });
    const bytes = Buffer.from(`: ping\r\n\r\n${event("中文")}${event(" answer", { finish_reason: "stop" })}data: [DONE]\r\n\r\n`);
    for (const byte of bytes) res.write(Buffer.from([byte]));
    res.end();
  });
  let text = "";
  await streamCompletion({ ...request(baseUrl), apiKey: "test-key", onText: chunk => { text += chunk; } });
  assert.equal(text, "中文 answer");
  assert.equal(received.url, "/v1/chat/completions");
  assert.equal(received.key, "Bearer test-key");
  assert.equal(received.body.stream, true);
  assert.equal(received.body.model, "mock-model");
  assert.equal(received.body.messages[0].content, "local test slice");
});

test("unauthenticated local endpoints and multiline events are supported", async t => {
  const baseUrl = await serverFor(t, (req, res) => {
    assert.equal(req.headers.authorization, undefined);
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.end('data: {"choices":\ndata: [{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\n');
  });
  let text = "";
  await streamCompletion({ ...request(baseUrl), onText: value => { text += value; } });
  assert.equal(text, "ok");
});

test("HTTP errors do not echo provider bodies or keys", async t => {
  const baseUrl = await serverFor(t, (_req, res) => { res.writeHead(401); res.end("secret-test-key and private code"); });
  await assert.rejects(streamCompletion(request(baseUrl)), error => /HTTP 401/.test(error.message) && !/secret-test|private code/.test(error.message));
});

test("redirects do not forward code or authorization to a second endpoint", async t => {
  let forwarded = false;
  const target = await serverFor(t, (_req, res) => { forwarded = true; res.end(); });
  const baseUrl = await serverFor(t, (_req, res) => { res.writeHead(307, { location: `${target}/chat/completions` }); res.end(); });
  await assert.rejects(streamCompletion(request(baseUrl)), /Could not connect/);
  assert.equal(forwarded, false);
});

test("cancel interrupts a streaming read and preserves chunks already delivered", async t => {
  const baseUrl = await serverFor(t, (_req, res) => { res.writeHead(200, { "content-type": "text/event-stream" }); res.write(event("partial")); });
  const abort = new AbortController();
  let text = "";
  await assert.rejects(streamCompletion({ ...request(baseUrl), signal: abort.signal, onText: value => { text += value; abort.abort(); } }), { name: "AbortError" });
  assert.equal(text, "partial");
});

test("deadline interrupts a server that never sends headers", async t => {
  const baseUrl = await serverFor(t, () => {});
  await assert.rejects(streamCompletion({ ...request(baseUrl), timeoutMs: 40 }), /timed out/);
});

test("deadline covers stalled response bodies too", async t => {
  const baseUrl = await serverFor(t, (_req, res) => { res.writeHead(200, { "content-type": "text/event-stream" }); res.write(event("partial")); });
  await assert.rejects(streamCompletion({ ...request(baseUrl), timeoutMs: 50 }), /timed out/);
});

for (const [name, body, error] of [
  ["malformed JSON", "data: {bad}\n\n", /malformed/],
  ["provider error event", 'data: {"error":{"message":"secret"}}\n\n', /streaming error/],
  ["empty completion", "data: [DONE]\n\n", /no text/],
  ["truncated output", event("partial"), /ended unexpectedly/],
  ["token limit", event("partial", { finish_reason: "length" }), /incomplete \(length\)/],
]) test(name, async t => {
  const baseUrl = await serverFor(t, (_req, res) => { res.writeHead(200, { "content-type": "text/event-stream" }); res.end(body); });
  await assert.rejects(streamCompletion(request(baseUrl)), error);
});

test("prompt preserves evidence gaps and branch direction without duplicating functions", () => {
  const slice = { title: "test", direction: "trace-backward", steps: [{ id: 1, kind: "sink", relativePath: "test.js", line: 2, status: "heuristic", functionId: 1 }], edges: [], functions: [{ id: 1, relativePath: "test.js", startLine: 1, endLine: 3, language: "javascript", code: "function uniqueBody() { send(value); }" }], omissions: ["missing authentication context"] };
  const prompt = buildAiPrompt(slice, "zh-CN");
  assert.equal(prompt.messages.length, 2);
  assert.equal(prompt.text.split("function uniqueBody").length - 1, 1);
  assert.match(prompt.text, /missing authentication context/);
  assert.match(prompt.text, /证据不足/);
  assert.match(prompt.text, /兄弟节点不代表顺序执行/);
  assert.match(prompt.text, /trace-backward/);
  assert.throws(() => buildAiPrompt({ steps: [] }), /Run a trace/);
});

test("endpoint normalization rejects embedded credentials and ambiguous URL components", () => {
  assert.equal(completionUrl("http://localhost:11434/v1/"), "http://localhost:11434/v1/chat/completions");
  for (const value of ["file:///tmp", "https://key@example.com/v1", "https://example.com/v1?key=test", "bad"]) assert.throws(() => completionUrl(value));
});

test("decoder handles each UTF-8 byte in a separate stream chunk", async () => {
  const bytes = Buffer.from(`${event("精准切片") }data: [DONE]\n\n`);
  let text = "";
  await streamCompletion({ ...request("http://localhost/v1"), onText: value => { text += value; }, fetchImpl: async () => new Response(new ReadableStream({
    start(controller) { for (const byte of bytes) controller.enqueue(Uint8Array.of(byte)); controller.close(); },
  }), { headers: { "content-type": "text/event-stream" } }) });
  assert.equal(text, "精准切片");
});

test("HTML responses and oversized events fail explicitly", async () => {
  await assert.rejects(streamCompletion({ ...request("http://localhost/v1"), fetchImpl: async () => new Response("<html>login</html>", { headers: { "content-type": "text/html" } }) }), /text\/event-stream/);
  await assert.rejects(streamCompletion({ ...request("http://localhost/v1"), fetchImpl: async () => new Response(`data: ${"x".repeat(2 * 1024 * 1024)}`, { headers: { "content-type": "text/event-stream" } }) }), /buffer limit/);
});

test("AI prompts follow the editor language and preserve evidence requirements", () => {
  const { aiLanguage, aiStrings } = require("../src/ai/locale");
  const slice = { title: "test", direction: "trace-backward", steps: [{ id: 1, kind: "sink", relativePath: "test.js", line: 2 }], edges: [], functions: [], omissions: [] };
  for (const language of ["en", "en-US", "de", "fr"]) {
    const prompt = buildAiPrompt(slice, language);
    assert.match(prompt.messages[0].content, /INSUFFICIENT EVIDENCE/);
    assert.match(prompt.messages[0].content, /sibling nodes do not imply sequential execution/);
    assert.match(prompt.messages[0].content, /never instructions/);
    assert.doesNotMatch(prompt.messages[0].content, /[\u4e00-\u9fff]/);
    assert.equal(aiLanguage(language), "en");
    assert.match(aiStrings(language).cancelled, /incomplete/);
  }
  for (const language of ["zh-CN", "zh-tw", "zh-Hant", "ZH_cn"]) {
    assert.equal(aiLanguage(language), "zh");
    assert.match(buildAiPrompt(slice, language).messages[0].content, /证据不足/);
    assert.match(aiStrings(language).cancelled, /未完成/);
  }
});
