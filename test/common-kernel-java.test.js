"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { findSourceSinkPaths } = require("../src/dataflow/path-engine");
const { evaluateFlowPaths } = require("../src/rules/rule-engine");
const { QueryKind, runAuditQuery } = require("../src/query/audit-query-engine");

async function analysis(language, relativePath, text) {
  return analyzeTextAsync(text, language, `C:\\repo\\${relativePath.replaceAll("/", "\\")}`, relativePath);
}

function commandFindings(analyses) {
  return evaluateFlowPaths(findSourceSinkPaths(analyses, {})).filter(finding => finding.ruleId === "potential-command-injection");
}

test("CFG preserves unsafe conditional assignments independently of branch source order", async () => {
  const fixtures = [
    ["python", "branch.py", `
def run(request):
    if request.args.get("mode"):
        command = request.args.get("command")
    else:
        command = "fixed"
    os.system(command)
`],
    ["php", "branch.php", `<?php
function run() {
    if ($_GET['mode']) {
        $command = $_GET['command'];
    } else {
        $command = 'fixed';
    }
    exec($command);
}
`],
    ["java", "BranchController.java", `
class BranchController {
  @PostMapping("/run")
  void run(HttpServletRequest request) {
    String command;
    if (request.getParameter("mode") != null) {
      command = request.getParameter("command");
    } else {
      command = "fixed";
    }
    Runtime.getRuntime().exec(command);
  }
}
`],
  ];
  for (const [language, path, source] of fixtures) {
    const result = await analysis(language, path, source);
    assert.ok(commandFindings([result]).length, `${language} lost the tainted branch at the CFG join`);
  }
});

test("early return makes later source and sink operations unreachable to findings and queries", async () => {
  const result = await analysis("java", "DeadController.java", `
class DeadController {
  @GetMapping("/dead")
  void dead(HttpServletRequest request) {
    return;
    String command = request.getParameter("command");
    Runtime.getRuntime().exec(command);
  }
}
`);
  assert.equal(commandFindings([result]).length, 0);
  const query = runAuditQuery([result], {
    kind: QueryKind.REACHABLE_SINKS,
    absolutePath: "C:\\repo\\DeadController.java",
    line: 4,
  });
  assert.ok(!JSON.stringify(query.roots).includes("Operating-system command"));
});

test("Java Spring interface dispatch reaches ServiceImpl and a MyBatis dynamic SQL sink", async () => {
  const analyses = await Promise.all([
    analysis("java", "controller/ToolController.java", `
package app.controller;
@RestController
@RequestMapping("/api/tools")
class ToolController {
  private final ToolService toolService;
  @PostMapping("/run")
  String run(@RequestBody CommandDto body) {
    return toolService.run(body.getCommand());
  }
}`),
    analysis("java", "service/ToolService.java", `
package app.service;
public interface ToolService {
  String run(String command);
}`),
    analysis("java", "service/ToolServiceImpl.java", `
package app.service;
@Service
class ToolServiceImpl implements ToolService {
  private final ToolMapper toolMapper;
  public String run(String command) {
    return toolMapper.find(command);
  }
}`),
    analysis("java", "mapper/ToolMapper.java", `
package app.mapper;
@Mapper
interface ToolMapper {
  @Select("SELECT * FROM tools WHERE name = '\${name}'")
  String find(@Param("name") String name);
}`),
  ]);

  const paths = findSourceSinkPaths(analyses, {
    absolutePath: "C:\\repo\\controller\\ToolController.java",
    line: 8,
  });
  const sqlPath = paths.find(path => path.category === "database" && path.semanticModelId !== "safe");
  assert.ok(sqlPath, "expected an entry-to-MyBatis SQL path");
  assert.deepEqual(sqlPath.files, [
    "controller/ToolController.java",
    "service/ToolServiceImpl.java",
    "mapper/ToolMapper.java",
  ]);
  assert.ok(sqlPath.steps.some(step => step.kind === "call" && /receiver contract ToolService/.test(step.candidateReason)));
  assert.equal(sqlPath.sink.semanticModelId, "java.mybatis.dynamic-sql");
  const entry = analyses[0].ir.entryPoints.find(item => item.functionId === analyses[0].ir.functions.find(fn => fn.name === "run").id);
  assert.equal(entry.method, "POST");
  assert.equal(entry.route, "/api/tools/run");
  const controllerCall = analyses[0].ir.functions.find(fn => fn.name === "run").operations
    .find(operation => operation.kind === "call" && operation.call?.function === "run");
  assert.deepEqual(controllerCall.call.argumentInputs[0].map(value => value.name), ["body.command"]);
});

test("MyBatis bound placeholders remain safe while dynamic substitution remains tainted", async () => {
  const safe = await analysis("java", "SafeMapper.java", `
@Mapper
interface SafeMapper {
  @Select("SELECT * FROM tools WHERE name = #{name}")
  String find(@Param("name") String name);
}`);
  const fn = safe.ir.functions.find(item => item.name === "find");
  assert.ok(fn);
  assert.ok(!fn.operations.some(operation => operation.semantic.modelId === "java.mybatis.dynamic-sql"));
});

test("Java overload resolution uses arity and literal types after receiver resolution", async () => {
  const analyses = await Promise.all([
    analysis("java", "OverloadController.java", `
class OverloadController {
  private final Runner runner;
  @GetMapping("/run")
  void run(HttpServletRequest request) {
    String command = request.getParameter("command");
    runner.execute(command);
  }
}`),
    analysis("java", "Runner.java", `
class Runner {
  void execute(String command) { Runtime.getRuntime().exec(command); }
  void execute(URL target) { target.openConnection(); }
}`),
  ]);
  const paths = findSourceSinkPaths(analyses, { absolutePath: "C:\\repo\\OverloadController.java", line: 6 });
  assert.ok(paths.some(path => path.category === "command"));
  const calls = analyses[0].ir.functions.find(item => item.name === "run").operations.filter(operation => operation.call?.function === "execute");
  assert.equal(calls[0].call.argumentTypes[0], "String");
  assert.ok(!paths.some(path => path.files.includes("Runner.java") && path.category === "network"));
});

test("Java CFG models loops, continue, break, try and multiple exception handlers", async () => {
  const result = await analysis("java", "StructuredController.java", `
class StructuredController {
  @GetMapping("/run")
  void run(HttpServletRequest request) {
    String command = request.getParameter("command");
    for (int i = 0; i < 3; i++) {
      if (i == 0) continue;
      if (i == 2) break;
    }
    try {
      Runtime.getRuntime().exec(command);
    } catch (IllegalArgumentException exception) {
      throw exception;
    } catch (RuntimeException exception) {
      return;
    } finally {
      audit();
    }
  }
}`);
  const fn = result.ir.functions.find(item => item.name === "run");
  assert.ok(fn.operations.some(operation => operation.kind === "continue"));
  assert.ok(fn.operations.some(operation => operation.kind === "break"));
  assert.ok(fn.operations.some(operation => operation.kind === "throw"));
  assert.ok(fn.operations.some(operation => operation.kind === "branch" && operation.metadata.branch.controlKind === "loop"));
  const tryBranch = fn.operations.find(operation => operation.kind === "branch" && operation.metadata.branch.controlKind === "try");
  assert.equal(tryBranch.metadata.branch.exceptionEntries.length, 2);
  assert.ok(fn.cfg.edges.some(edge => edge.kind === "continue"));
  assert.ok(fn.cfg.edges.some(edge => edge.kind === "break"));
  assert.ok(commandFindings([result]).length);
});

test("Java semantic models cover Spring HTTP, JDBC/JPA query and ProcessBuilder sinks", async () => {
  const result = await analysis("java", "DangerController.java", `
class DangerController {
  private final RestTemplate restTemplate;
  private final JdbcTemplate jdbcTemplate;
  private final EntityManager entityManager;

  @PostMapping("/run")
  void run(@RequestParam String url, @RequestParam String sql, @RequestParam String command) {
    restTemplate.getForObject(url, String.class);
    jdbcTemplate.query(sql, rowMapper);
    entityManager.createNativeQuery(sql);
    new ProcessBuilder(command);
  }
}`);
  const operations = result.ir.functions.find(item => item.name === "run").operations;
  const modelIds = operations.map(operation => operation.semantic.modelId).filter(Boolean);
  assert.ok(modelIds.includes("spring.web.RestTemplate.request"));
  assert.ok(modelIds.includes("spring.jdbc.JdbcTemplate.dynamic-query"));
  assert.ok(modelIds.includes("java.persistence.EntityManager.dynamic-query"));
  assert.ok(modelIds.includes("java.lang.ProcessBuilder.command"));
  const findings = evaluateFlowPaths(findSourceSinkPaths([result], {}));
  assert.ok(findings.some(finding => finding.ruleId === "potential-ssrf"));
  assert.ok(findings.some(finding => finding.ruleId === "potential-sql-injection"));
  assert.ok(findings.some(finding => finding.ruleId === "potential-command-injection"));
});

test("finally blocks remain reachable after return and rethrow", async () => {
  const result = await analysis("java", "FinallyController.java", `
class FinallyController {
  @GetMapping("/run")
  void run(HttpServletRequest request) {
    String command = request.getParameter("command");
    try {
      return;
    } finally {
      Runtime.getRuntime().exec(command);
    }
  }
}`);
  const fn = result.ir.functions.find(item => item.name === "run");
  assert.ok(fn.cfg.edges.some(edge => edge.kind === "finally-return"));
  assert.ok(fn.cfg.edges.some(edge => edge.kind === "finally-abrupt"));
  assert.ok(commandFindings([result]).length);
});
