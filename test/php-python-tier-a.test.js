"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { WorkspaceAnalysisEngine } = require("../src/analysis/workspace-engine");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");

async function analyze(language, fileName, source) {
  const analysis = await analyzeTextAsync(source, language, `/workspace/${fileName}`, fileName);
  return { analysis, dataflow: runDataflowAnalysis([analysis]) };
}

test("PHP does not treat arbitrary exec and query methods as built-in sinks", async () => {
  const runner = await analyze("php", "runner.php", `<?php
class SafeRunner { public function exec($value) { return $value; } }
$runner = new SafeRunner();
$runner->exec($_GET["x"]);
`);
  const request = await analyze("php", "request.php", `<?php
use Illuminate\\Http\\Request;
function index(Request $request) { return $request->query("sort"); }
`);

  assert.equal(runner.dataflow.findings.length, 0);
  assert.equal(request.dataflow.findings.some(item => item.ruleId === "potential-sql-injection"), false);
  assert.ok(request.analysis.ir.functions.flatMap(fn => fn.operations)
    .some(operation => operation.semantic.modelId === "php.framework.request-input"));
});

test("Laravel request input reaches a verified database sink", async () => {
  const { analysis, dataflow } = await analyze("php", "SearchController.php", `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
use Illuminate\\Support\\Facades\\DB;
class SearchController {
  public function search(Request $request) {
    $sort = $request->input("sort");
    return DB::select("SELECT * FROM users ORDER BY " . $sort);
  }
}
`);

  assert.ok(dataflow.findings.some(item => item.ruleId === "potential-sql-injection"));
  const models = analysis.ir.functions.flatMap(fn => fn.operations).map(operation => operation.semantic.modelId);
  assert.ok(models.includes("php.framework.request-input"));
  assert.ok(models.includes("php.laravel.dynamic-query"));
});

test("Symfony attributes create an entry and request input reaches command execution", async () => {
  const { analysis, dataflow } = await analyze("php", "ToolController.php", `<?php
namespace App\\Controller;
use Symfony\\Component\\HttpFoundation\\Request;
use Symfony\\Component\\Routing\\Annotation\\Route;
class ToolController {
  #[Route("/tool", methods: ["GET"])]
  public function run(Request $request) {
    $cmd = $request->query->get("cmd");
    return system($cmd);
  }
}
`);

  assert.ok(analysis.ir.entryPoints.some(entry => entry.route === "/tool" && entry.method === "GET"));
  assert.ok(dataflow.findings.some(item => item.ruleId === "potential-command-injection"));
});

test("PHP use declarations select the matching namespace instead of a same-named class", async () => {
  const analyses = await Promise.all([
    analyzeTextAsync(`<?php namespace App\\Safe; class Runner { public function run($value) { return $value; } }`, "php", "/workspace/src/Safe/Runner.php", "src/Safe/Runner.php"),
    analyzeTextAsync(`<?php namespace App\\Evil; class Runner { public function run($value) { system($value); } }`, "php", "/workspace/src/Evil/Runner.php", "src/Evil/Runner.php"),
    analyzeTextAsync(`<?php
namespace App\\Http;
use App\\Safe\\Runner;
class Controller {
  public function handle(Runner $runner) { return $runner->run($_GET["cmd"]); }
}`, "php", "/workspace/src/Http/Controller.php", "src/Http/Controller.php"),
  ]);

  assert.equal(runDataflowAnalysis(analyses).findings.some(item => item.ruleId === "potential-command-injection"), false);
});

test("PHP group-use aliases and promoted properties preserve the receiver class", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const result = await engine.initializeWorkspace([
    {
      language: "php", absolutePath: "/workspace/src/Safe/Runner.php", relativePath: "src/Safe/Runner.php", version: "1",
      text: `<?php namespace App\\Safe; class Runner { public function run($value) { return $value; } }`,
    },
    {
      language: "php", absolutePath: "/workspace/src/Evil/Runner.php", relativePath: "src/Evil/Runner.php", version: "1",
      text: `<?php namespace App\\Evil; class Runner { public function run($value) { system($value); } }`,
    },
    {
      language: "php", absolutePath: "/workspace/src/Http/SafeController.php", relativePath: "src/Http/SafeController.php", version: "1",
      text: `<?php
namespace App\\Http;
use App\\Safe\\{Runner, Logger};
class SafeController {
  public function __construct(private Runner $runner) {}
  public function handle() { $this->runner->run($_GET["cmd"]); }
}`,
    },
    {
      language: "php", absolutePath: "/workspace/src/Http/EvilController.php", relativePath: "src/Http/EvilController.php", version: "1",
      text: `<?php
namespace App\\Http;
use App\\Evil\\Runner;
class EvilController {
  public function __construct(private Runner $runner) {}
  public function handle() { $this->runner->run($_GET["cmd"]); }
}`,
    },
  ]);

  const findings = result.findingDelta.upsert.filter(item => item.ruleId === "potential-command-injection");
  assert.equal(findings.length, 1);
  assert.match(findings[0].absolutePath, /Evil[\\/]Runner\.php$/);
  assert.ok(findings[0].path.steps.some(step => /EvilController\.php$/.test(step.relativePath)));
});

test("Laravel route arrays bind across files to their controller method", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const result = await engine.initializeWorkspace([
    {
      language: "php", absolutePath: "/workspace/routes/web.php", relativePath: "routes/web.php", version: "1",
      text: `<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Http\\Controllers\\ToolController;
Route::post("/run", [ToolController::class, "run"]);`,
    },
    {
      language: "php", absolutePath: "/workspace/app/Http/Controllers/ToolController.php", relativePath: "app/Http/Controllers/ToolController.php", version: "1",
      text: `<?php
namespace App\\Http\\Controllers;
use Illuminate\\Http\\Request;
class ToolController {
  public function run(Request $request) { system($request->input("cmd")); }
}`,
    },
  ]);

  const controller = result.analyses.find(item => /ToolController\.php$/.test(item.relativePath));
  const method = controller.ir.functions.find(fn => fn.name === "run");
  assert.ok(method.entryPoints.some(entry => entry.route === "/run" && entry.framework === "php-route"));
  assert.ok(result.findingDelta.upsert.some(item => item.ruleId === "potential-command-injection"));
});

test("FastAPI dependency parameters are not seeded as HTTP input", async () => {
  const { analysis, dataflow } = await analyze("python", "routes.py", `
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
router = APIRouter()

@router.get("/health")
def health(db: Session = Depends(get_db)):
    return db.execute("SELECT 1")
`);

  const entry = analysis.ir.entryPoints.find(item => item.route === "/health");
  assert.equal(entry?.parameterRoles?.[0], "database");
  assert.equal(dataflow.findings.some(item => item.ruleId === "potential-sql-injection"), false);
});

test("Python local shadowing rejects a standard-library lookalike", async () => {
  const shadowed = await analyze("python", "shadowed.py", `
import os
class SafeRunner:
    def system(self, value):
        return value
def run(user_input):
    os = SafeRunner()
    return os.system(user_input)
`);
  const standardLibrary = await analyze("python", "command.py", `
import os
def run(request):
    return os.system(request.args.get("cmd"))
`);

  assert.equal(shadowed.dataflow.findings.some(item => item.ruleId === "potential-command-injection"), false);
  assert.ok(standardLibrary.dataflow.findings.some(item => item.ruleId === "potential-command-injection"));
});

test("Python custom Session and raw methods are not database sinks by simple type name", async () => {
  const customSession = await analyze("python", "custom_session.py", `
class Session:
    def execute(self, value):
        return value
@app.get("/run")
def run(request):
    session = Session()
    return session.execute(request.args.get("value"))
`);
  const customRaw = await analyze("python", "custom_raw.py", `
class ReportStore:
    def raw(self, value):
        return value
@app.get("/report")
def report(request):
    store = ReportStore()
    return store.raw(request.args.get("value"))
`);

  assert.equal(customSession.dataflow.findings.some(item => item.ruleId === "potential-sql-injection"), false);
  assert.equal(customRaw.dataflow.findings.some(item => item.ruleId === "potential-sql-injection"), false);
});

test("Python verified Django raw queries remain SQL sinks", async () => {
  const { dataflow } = await analyze("python", "django_raw.py", `
from django.db.models import QuerySet
@app.get("/report")
def report(request, rows: QuerySet):
    return rows.raw(request.args.get("sql"))
`);

  assert.ok(dataflow.findings.some(item => item.ruleId === "potential-sql-injection"));
});

test("Python database factory return types reach sqlite3 cursors and SQLAlchemy sessions", async () => {
  const sqlite = await analyze("python", "sqlite_route.py", `
import sqlite3
def run(request):
    sql = request.args.get("sql")
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    return cursor.execute(sql)
`);
  const sqlalchemy = await analyze("python", "sqlalchemy_route.py", `
from sqlalchemy.orm import sessionmaker
SessionLocal = sessionmaker()
def run(request):
    db = SessionLocal()
    return db.execute(request.args.get("sql"))
`);

  for (const sample of [sqlite, sqlalchemy]) {
    const finding = sample.dataflow.findings.find(item => item.ruleId === "potential-sql-injection");
    assert.ok(finding);
    assert.equal(finding.path.sink.semanticModelId, "python.dbapi.dynamic-query");
    assert.notEqual(finding.confidence, "low");
  }
});

test("Python unknown database factories downgrade execute calls to review instead of disappearing", async () => {
  const { dataflow } = await analyze("python", "unknown_factory.py", `
def run(request):
    db = SessionLocal()
    return db.execute(request.args.get("sql"))
`);
  const finding = dataflow.findings.find(item => item.ruleId === "potential-sql-injection");

  assert.equal(finding?.confidence, "low");
  assert.equal(finding?.path.sink.semanticVerification, "candidate");
});

test("Python subprocess argv distinguishes a constant executable from shell commands", async () => {
  const safe = await analyze("python", "safe_subprocess.py", `
import subprocess
@app.get("/ping")
def ping(request):
    host = request.args.get("host")
    return subprocess.run(["ping", "-c", "1", host], shell=False)
`);
  const shell = await analyze("python", "shell_subprocess.py", `
import subprocess
@app.get("/ping")
def ping(request):
    host = request.args.get("host")
    return subprocess.run("ping -c 1 " + host, shell=True)
`);

  assert.equal(safe.dataflow.findings.some(item => item.ruleId === "potential-command-injection"), false);
  assert.ok(shell.dataflow.findings.some(item => item.ruleId === "potential-command-injection"));
});

test("Python self.field keeps the imported class identity across same-named modules", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const result = await engine.initializeWorkspace([
    {
      language: "python", absolutePath: "/workspace/safe.py", relativePath: "safe.py", version: "1",
      text: `class Runner:\n    def run(self, value):\n        return value`,
    },
    {
      language: "python", absolutePath: "/workspace/dangerous.py", relativePath: "dangerous.py", version: "1",
      text: `import os\nclass Runner:\n    def run(self, value):\n        return os.system(value)`,
    },
    {
      language: "python", absolutePath: "/workspace/controller.py", relativePath: "controller.py", version: "1",
      text: `from dangerous import Runner
class Controller:
    def __init__(self, runner: Runner):
        self.runner = runner
    def handle(self, request):
        return self.runner.run(request.args.get("cmd"))`,
    },
  ]);

  const finding = result.findingDelta.upsert.find(item => item.ruleId === "potential-command-injection");
  assert.ok(finding);
  assert.ok(finding.path.steps.some(step => step.relativePath === "dangerous.py"));
  assert.ok(!finding.path.steps.some(step => step.relativePath === "safe.py"));
});

test("Django path declarations bind their route to a handler in another module", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const result = await engine.initializeWorkspace([
    {
      language: "python", absolutePath: "/workspace/app/urls.py", relativePath: "app/urls.py", version: "1",
      text: `from django.urls import path
from app import views
urlpatterns = [path("run/", views.run)]`,
    },
    {
      language: "python", absolutePath: "/workspace/app/views.py", relativePath: "app/views.py", version: "1",
      text: `import os
def run(request):
    return os.system(request.GET.get("cmd"))`,
    },
  ]);

  const views = result.analyses.find(item => item.relativePath === "app/views.py");
  const handler = views.ir.functions.find(fn => fn.name === "run");
  assert.ok(handler.entryPoints.some(entry => entry.route === "run/" && entry.framework === "django"));
  assert.ok(result.findingDelta.upsert.some(item => item.ruleId === "potential-command-injection"));
});

test("FastAPI Pydantic field flows through a service to httpx", async () => {
  const engine = new WorkspaceAnalysisEngine();
  const result = await engine.initializeWorkspace([
    {
      language: "python",
      absolutePath: "/workspace/routes.py",
      relativePath: "routes.py",
      version: "1",
      text: `
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from service import DownloadService
router = APIRouter()
class FetchBody(BaseModel):
    url: str
@router.post("/fetch")
async def fetch(body: FetchBody, service: DownloadService = Depends()):
    return await service.download(body.url)
`,
    },
    {
      language: "python",
      absolutePath: "/workspace/service.py",
      relativePath: "service.py",
      version: "1",
      text: `
import httpx
class DownloadService:
    async def download(self, url: str):
        async with httpx.AsyncClient() as client:
            return await client.get(url)
`,
    },
  ]);

  const finding = result.findingDelta.upsert.find(item => item.ruleId === "potential-ssrf");
  assert.ok(finding);
  assert.ok(finding.paths.some(flow => flow.steps.some(step => step.inputAccessPath === "body.url" || step.outputAccessPath === "body.url")));
  assert.ok(finding.paths.some(flow => new Set(flow.touchedFunctionIds).size >= 2));
});
