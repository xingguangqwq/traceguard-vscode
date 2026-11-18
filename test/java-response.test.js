"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");

async function analyze(body, declaration = "HttpServletResponse response") {
  const text = `import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
class Render {
  void run(HttpServletRequest request, ${declaration}) {
    String input = request.getParameter("q");
    ${body}
  }
}`;
  return analyzeTextAsync(text, "java", "C:/repo/Render.java", "Render.java");
}

for (const method of ["write", "print", "println", "append"]) test(`Servlet getWriter().${method} tracks HTTP output`, async () => {
  const analysis = await analyze(`response.getWriter().${method}(input);`);
  assert.ok(runDataflowAnalysis([analysis]).findings.some(item => item.cwe === "CWE-79"));
});

test("literal response bodies and unrelated writers do not create XSS findings", async () => {
  for (const [body, declaration] of [
    ['response.getWriter().write("constant");', "HttpServletResponse response"],
    ['writer.println(input);', "java.io.PrintWriter writer"],
    ['System.out.println(input);', "HttpServletResponse response"],
    ['exporter.getWriter().write(input);', "FileExporter exporter"],
  ]) assert.ok(!runDataflowAnalysis([await analyze(body, declaration)]).findings.some(item => item.cwe === "CWE-79"), body);
});

test("symbol factories receive only variable names when used from frontend collections", async () => {
  const analysis = await analyze('String second = request.getParameter("other"); response.getWriter().write(input + second);');
  const inputs = analysis.ir.functions.flatMap(fn => fn.operations.flatMap(op => [...op.inputs, ...(op.call?.argumentInputs || []).flat(), ...(op.call?.receiverInputs || [])]));
  assert.ok(inputs.length > 0);
  assert.ok(inputs.every(value => value.type === "?" && value.role === undefined), "array callback indexes and collections must not become symbol types or roles");
});
