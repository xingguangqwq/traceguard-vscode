"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");

test("Java calls follow the explicitly imported type beyond the old six-candidate limit", async () => {
  const analyses = [];
  for (let index = 1; index <= 7; index += 1) {
    const dangerous = index === 7 ? "Runtime.getRuntime().exec(value);" : "System.out.println(value);";
    analyses.push(await javaAnalysis(`package p${index}; public class ToolService { public void run(String value) { ${dangerous} } }`, `p${index}/ToolService.java`));
  }
  analyses.push(await javaAnalysis(`
package app;
import p7.ToolService;
class Controller {
  void handle(HttpServletRequest request, ToolService service) {
    String command = request.getParameter("command");
    service.run(command);
  }
}`, "app/Controller.java"));

  const result = runDataflowAnalysis(analyses);
  const finding = result.findings.find(item => item.ruleId === "potential-command-injection");
  assert.ok(finding);
  assert.ok(finding.path.steps.some(step => step.relativePath === "p7/ToolService.java"));
  assert.ok(!finding.path.steps.some(step => /^p[1-6]\//.test(step.relativePath)));
});

test("Java calls do not cross into a same-named type from an unimported package", async () => {
  const analyses = await Promise.all([
    javaAnalysis(`package safe; public class ToolService { public void run(String value) { System.out.println(value); } }`, "safe/ToolService.java"),
    javaAnalysis(`package dangerous; public class ToolService { public void run(String value) { Runtime.getRuntime().exec(value); } }`, "dangerous/ToolService.java"),
    javaAnalysis(`
package app;
import safe.ToolService;
class Controller {
  void handle(HttpServletRequest request, ToolService service) {
    service.run(request.getParameter("command"));
  }
}`, "app/Controller.java"),
  ]);

  assert.equal(runDataflowAnalysis(analyses).findings.some(item => item.ruleId === "potential-command-injection"), false);
});

test("Java resolves a service in the caller package without an import", async () => {
  const analyses = [];
  for (let index = 1; index <= 6; index += 1) {
    analyses.push(await javaAnalysis(`package other${index}; public class ToolService { public void run(String value) { System.out.println(value); } }`, `other${index}/ToolService.java`));
  }
  analyses.push(await javaAnalysis(`package app; public class ToolService { public void run(String value) { Runtime.getRuntime().exec(value); } }`, "app/ToolService.java"));
  analyses.push(await javaAnalysis(`
package app;
class Controller {
  void handle(HttpServletRequest request, ToolService service) {
    service.run(request.getParameter("command"));
  }
}`, "app/Controller.java"));

  const finding = runDataflowAnalysis(analyses).findings.find(item => item.ruleId === "potential-command-injection");
  assert.ok(finding);
  assert.ok(finding.path.steps.some(step => step.relativePath === "app/ToolService.java"));
});

test("Java wildcard imports resolve the matching package before candidate limits", async () => {
  const analyses = [];
  for (let index = 1; index <= 6; index += 1) {
    analyses.push(await javaAnalysis(`package p${index}; public class ToolService { public void run(String value) { System.out.println(value); } }`, `p${index}/ToolService.java`));
  }
  analyses.push(await javaAnalysis(`package p7; public class ToolService { public void run(String value) { Runtime.getRuntime().exec(value); } }`, "p7/ToolService.java"));
  analyses.push(await javaAnalysis(`
package app;
import p7.*;
class Controller {
  void handle(HttpServletRequest request, ToolService service) {
    service.run(request.getParameter("command"));
  }
}`, "app/Controller.java"));

  const finding = runDataflowAnalysis(analyses).findings.find(item => item.ruleId === "potential-command-injection");
  assert.ok(finding);
  assert.ok(finding.path.steps.some(step => step.relativePath === "p7/ToolService.java"));
});

test("Java interface inheritance resolves implementations transitively", async () => {
  const analyses = await Promise.all([
    javaAnalysis("package contracts; public interface Parent { void run(String value); }", "contracts/Parent.java"),
    javaAnalysis("package contracts; public interface Child extends Parent {}", "contracts/Child.java"),
    javaAnalysis(`
package impl;
import contracts.Child;
public class ToolServiceImpl implements Child {
  public void run(String value) { Runtime.getRuntime().exec(value); }
}`, "impl/ToolServiceImpl.java"),
    javaAnalysis(`
package app;
import contracts.Parent;
class Controller {
  void handle(HttpServletRequest request, Parent service) {
    service.run(request.getParameter("command"));
  }
}`, "app/Controller.java"),
  ]);

  const finding = runDataflowAnalysis(analyses).findings.find(item => item.ruleId === "potential-command-injection");
  assert.ok(finding);
  assert.ok(finding.path.steps.some(step => step.relativePath === "impl/ToolServiceImpl.java"));
});

test("Java resolves this.field receiver types instead of losing the member identity", async () => {
  const analyses = await Promise.all([
    javaAnalysis(`package safe; public class Runner { public void run(String value) { System.out.println(value); } }`, "safe/Runner.java"),
    javaAnalysis(`package dangerous; public class Runner { public void run(String value) { Runtime.getRuntime().exec(value); } }`, "dangerous/Runner.java"),
    javaAnalysis(`
package app;
import dangerous.Runner;
class Controller {
  private final Runner runner;
  Controller(Runner runner) { this.runner = runner; }
  void handle(HttpServletRequest request) {
    String command = request.getParameter("command");
    this.runner.run(command);
  }
}`, "app/Controller.java"),
  ]);

  const finding = runDataflowAnalysis(analyses).findings.find(item => item.ruleId === "potential-command-injection");
  assert.ok(finding);
  assert.ok(finding.path.steps.some(step => step.relativePath === "dangerous/Runner.java"));
  assert.ok(!finding.path.steps.some(step => step.relativePath === "safe/Runner.java"));
});

test("Servlet annotations retain their static route and doGet method", async () => {
  const analysis = await javaAnalysis(`
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
@WebServlet("/tool")
class ToolServlet extends HttpServlet {
  protected void doGet(HttpServletRequest request, HttpServletResponse response) {}
}`, "ToolServlet.java");
  const entry = analysis.ir.entryPoints.find(item => item.framework === "servlet");

  assert.equal(entry?.method, "GET");
  assert.equal(entry?.route, "/tool");
});

function javaAnalysis(source, relativePath) {
  return analyzeTextAsync(source, "java", `C:\\repo\\${relativePath.replaceAll("/", "\\")}`, relativePath);
}
