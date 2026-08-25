"use strict";

const path = require("node:path");
const { performance } = require("node:perf_hooks");
const { DataflowWorkerClient } = require("../src/dataflow/worker-client");

const benchmarkRoot = path.join(path.parse(process.cwd()).root, "traceguard-benchmark");

const requested = Number(process.argv.find(argument => argument.startsWith("--files="))?.split("=")[1] || 200);
const fileCount = Math.min(8000, Math.max(1, Number.isFinite(requested) ? Math.floor(requested) : 200));
const requestedRssLimit = Number(process.argv.find(argument => argument.startsWith("--max-rss-mib="))?.split("=")[1]);
const maxRssMiB = Number.isFinite(requestedRssLimit) && requestedRssLimit > 0 ? requestedRssLimit : null;
const fixture = process.argv.find(argument => argument.startsWith("--fixture="))?.split("=")[1] || "independent-js-routes";
const requestedIncrementalLimit = Number(process.argv.find(argument => argument.startsWith("--max-incremental-ms="))?.split("=")[1]);
const disableIncrementalGate = process.argv.includes("--no-incremental-gate");
const requestedRuns = Number(process.argv.find(argument => argument.startsWith("--runs="))?.split("=")[1] || 5);
const incrementalRuns = Math.min(20, Math.max(1, Number.isFinite(requestedRuns) ? Math.floor(requestedRuns) : 5));
const maxIncrementalMs = disableIncrementalGate
  ? null
  : Number.isFinite(requestedIncrementalLimit) && requestedIncrementalLimit > 0
  ? requestedIncrementalLimit
  : fileCount >= 200 ? 500 : null;

async function main() {
  const client = new DataflowWorkerClient({ timeoutMs: 120_000 });
  const benchmark = buildFixture(fixture, fileCount);
  const files = benchmark.files;
  const heapBefore = process.memoryUsage().heapUsed;
  const startedAt = performance.now();
  const initial = await client.initializeWorkspace(files, { maxDepth: 6, maxPaths: Math.max(400, fileCount * 2) });
  const initializedAt = performance.now();
  const unrelatedStartedAt = performance.now();
  const unrelated = await client.updateFile(benchmark.unrelated || benchmark.changed);
  const unrelatedSaveMs = performance.now() - unrelatedStartedAt;
  const incrementalTimes = [];
  let mainThreadDispatchMs = 0;
  let incremental;
  for (let run = 0; run < incrementalRuns; run += 1) {
    const changed = benchmark.changeForRun ? benchmark.changeForRun(run) : { ...benchmark.changed, version: `semantic-${run}`, text: `${benchmark.changed.text}\nexport const benchmarkMarker${run} = ${run};\n` };
    const dispatchStartedAt = performance.now();
    const pending = client.updateFile(changed);
    mainThreadDispatchMs = Math.max(mainThreadDispatchMs, performance.now() - dispatchStartedAt);
    incremental = await pending;
    incrementalTimes.push(performance.now() - dispatchStartedAt);
  }
  const memory = process.memoryUsage();
  await client.dispose();

  const result = {
    fixture: benchmark.name,
    files: files.length,
    functions: initial.analyses.reduce((total, analysis) => total + analysis.ir.functions.length, 0),
    findings: initial.findingDelta.upsert.length,
    initializeMs: round(initializedAt - startedAt),
    unrelatedSaveMs: round(unrelatedSaveMs),
    unrelatedInvalidatedFiles: unrelated.metadata.incrementallyInvalidatedFiles,
    mainThreadDispatchMs: round(mainThreadDispatchMs),
    incrementalMs: round(percentile(incrementalTimes, 0.95)),
    incrementalP95Ms: round(percentile(incrementalTimes, 0.95)),
    incrementalSamplesMs: incrementalTimes.map(round),
    invalidatedFiles: incremental.metadata.incrementallyInvalidatedFiles,
    invalidatedFunctions: incremental.metadata.incrementallyInvalidatedFunctions,
    heapDeltaMiB: round(Math.max(0, memory.heapUsed - heapBefore) / 1024 / 1024),
    rssMiB: round(memory.rss / 1024 / 1024),
    workerPeakRssMiB: round((incremental.metadata.workerPeakRssBytes || initial.metadata.workerPeakRssBytes || 0) / 1024 / 1024),
    workerHeapUsedMiB: round((incremental.metadata.workerHeapUsedBytes || 0) / 1024 / 1024),
    dataflowMs: incremental.metadata.dataflowMs,
    findingPathDiffMs: incremental.metadata.findingPathDiffMs,
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.mainThreadDispatchMs >= 50) throw new Error(`Main-thread dispatch gate failed: ${result.mainThreadDispatchMs} ms (target <50 ms).`);
  const maximumUnrelatedInvalidatedFiles = benchmark.maximumUnrelatedInvalidatedFiles || 0;
  if (result.unrelatedSaveMs >= 500 || result.unrelatedInvalidatedFiles > maximumUnrelatedInvalidatedFiles) {
    throw new Error(`Unrelated-save gate failed: ${result.unrelatedSaveMs} ms, ${result.unrelatedInvalidatedFiles} invalidated files (maximum ${maximumUnrelatedInvalidatedFiles}).`);
  }
  if (maxIncrementalMs !== null && result.incrementalMs >= maxIncrementalMs) {
    throw new Error(`Incremental analysis gate failed: ${result.incrementalMs} ms (target <${maxIncrementalMs} ms).`);
  }
  if (benchmark.minimumInvalidatedFiles && result.invalidatedFiles < benchmark.minimumInvalidatedFiles) {
    throw new Error(`Dependency invalidation gate failed: ${result.invalidatedFiles} files (expected at least ${benchmark.minimumInvalidatedFiles}).`);
  }
  if (maxRssMiB !== null && result.rssMiB > maxRssMiB) {
    throw new Error(`Worker RSS gate failed: ${result.rssMiB} MiB (target <=${maxRssMiB} MiB).`);
  }
}

function buildFixture(name, count) {
  if (name === "java-backend") return javaBackendFixture(Math.max(4, count));
  if (name === "php-backend") return phpBackendFixture(Math.max(3, count));
  if (name === "python-backend") return pythonBackendFixture(Math.max(2, count));
  if (name === "typescript-dependents") {
    const provider = {
      absolutePath: path.join(benchmarkRoot, "provider.ts"),
      relativePath: "provider.ts",
      language: "typescript",
      version: "string",
      text: "export function consume(callback: (value: string) => void) { callback('safe'); }",
    };
    const consumers = Array.from({ length: Math.max(1, count - 1) }, (_, index) => ({
      absolutePath: path.join(benchmarkRoot, `consumer-${index}.ts`),
      relativePath: `consumer-${index}.ts`,
      language: "typescript",
      version: "1",
      text: `import { consume } from "./provider"; consume(value => String(value));`,
    }));
    return {
      name: "persistent-worker-typescript-dependent-fanout",
      files: [provider, ...consumers],
      unrelated: {
        ...consumers[0],
        version: "comment",
        text: `${consumers[0].text}\n// unrelated saved edit\n`,
      },
      changed: {
        ...provider,
        version: "number",
        text: "export function consume(callback: (value: number) => void) { callback(1); }",
      },
      maximumUnrelatedInvalidatedFiles: 1,
      minimumInvalidatedFiles: count,
    };
  }
  const files = Array.from({ length: count }, (_, index) => ({
    absolutePath: path.join(benchmarkRoot, `route-${index}.js`),
    relativePath: `route-${index}.js`,
    language: "javascript",
    version: "1",
    text: `export function route${index}(req, res) {\n  const target = req.query.url;\n  fetch(target);\n  res.send("ok");\n}\n`,
  }));
  const selected = files[Math.floor(count / 2)];
  return {
    name: "persistent-worker-independent-js-routes",
    files,
    changed: { ...selected, version: "2", text: `${selected.text}\n// unrelated saved edit\n` },
    changeForRun: run => ({ ...selected, version: `semantic-${run}`, text: `${selected.text}\nexport const benchmarkMarker${run} = ${run};\n` }),
    minimumInvalidatedFiles: 1,
  };
}

function javaBackendFixture(count) {
  const files = [];
  const groups = Math.ceil(count / 4);
  for (let index = 0; index < groups; index += 1) {
    files.push(javaFile(index, "Controller", `package app${index}; import service${index}.Service${index}; class Controller${index} { void handle(HttpServletRequest request, Service${index} service) { service.run${index}(request.getParameter("sql")); } }`));
    files.push(javaFile(index, "Service", `package service${index}; public interface Service${index} { void run${index}(String value); }`));
    files.push(javaFile(index, "ServiceImpl", `package service${index}; import mapper${index}.Mapper${index}; public class ServiceImpl${index} implements Service${index} { Mapper${index} mapper; public void run${index}(String value) { mapper.query${index}(value); } }`));
    files.push(javaFile(index, "Mapper", `package mapper${index}; import java.sql.Statement; public class Mapper${index} { Statement statement; public void query${index}(String value) { statement.executeQuery(value); } }`));
  }
  const selected = files.find(file => /ServiceImpl/.test(file.relativePath));
  return backendFixture("java-controller-interface-impl-mapper", files.slice(0, Math.max(4, count)), selected);
}

function phpBackendFixture(count) {
  const files = [];
  const groups = Math.ceil(count / 3);
  for (let index = 0; index < groups; index += 1) {
    files.push(phpFile(`routes/route-${index}.php`, `<?php
use Illuminate\\Support\\Facades\\Route;
use App\\Controller\\Controller${index};
Route::post("/run-${index}", [Controller${index}::class, "handle${index}"]);`));
    files.push(phpFile(`src/Controller/Controller${index}.php`, `<?php
namespace App\\Controller;
use App\\Service\\Service${index};
class Controller${index} {
  public function __construct(private Service${index} $service) {}
  public function handle${index}() { $this->service->run${index}($_POST["cmd"]); }
}`));
    files.push(phpFile(`src/Service/Service${index}.php`, `<?php
namespace App\\Service;
class Service${index} {
  public function run${index}($value) { system($value); }
}`));
  }
  const selected = files.find(file => /Service/.test(file.relativePath));
  return backendFixture("php-route-controller-service", files.slice(0, Math.max(3, count)), selected);
}

function pythonBackendFixture(count) {
  const files = [];
  const groups = Math.ceil(count / 2);
  for (let index = 0; index < groups; index += 1) {
    files.push(pythonFile(`routes_${index}.py`, `from fastapi import APIRouter\nfrom service_${index} import Service${index}\nrouter = APIRouter()\n@router.get("/fetch-${index}")\ndef fetch${index}(request, service: Service${index}):\n    return service.fetch${index}(request.args.get("url"))`));
    files.push(pythonFile(`service_${index}.py`, `import httpx\nclass Service${index}:\n    def fetch${index}(self, url):\n        return httpx.get(url)`));
  }
  const selected = files.find(file => /service_/.test(file.relativePath));
  return backendFixture("python-fastapi-service-httpx", files.slice(0, Math.max(2, count)), selected);
}

function backendFixture(name, files, selected) {
  const comment = selected.language === "python" ? "# unrelated saved edit" : "// unrelated saved edit";
  return {
    name,
    files,
    changed: { ...selected, version: "2", text: `${selected.text}\n${comment}\n` },
    changeForRun: run => semanticBackendChange(selected, run),
    minimumInvalidatedFiles: 1,
  };
}

function semanticBackendChange(file, run) {
  if (file.language === "python") {
    return { ...file, version: `semantic-${run}`, text: `${file.text}\n    def traceguard_marker_${run}(self):\n        return ${run}\n` };
  }
  const marker = file.language === "php"
    ? `\n  public function traceguardMarker${run}() { return ${run}; }\n}`
    : `\n  void traceguardMarker${run}() { int marker = ${run}; }\n}`;
  return { ...file, version: `semantic-${run}`, text: file.text.replace(/}\s*$/, marker) };
}

function javaFile(index, kind, text) {
  const directory = kind === "Controller" ? `app${index}` : kind === "Mapper" ? `mapper${index}` : `service${index}`;
  const className = `${kind}${index}`;
  return sourceFile(path.join(directory, `${className}.java`), "java", text);
}

function phpFile(relativePath, text) { return sourceFile(relativePath, "php", text); }
function pythonFile(relativePath, text) { return sourceFile(relativePath, "python", text); }
function sourceFile(relativePath, language, text) {
  return { absolutePath: path.join(benchmarkRoot, relativePath), relativePath: relativePath.replaceAll("\\", "/"), language, version: "1", text };
}

function percentile(values, ratio) {
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(sorted.length * ratio) - 1)] || 0;
}

function round(value) { return Math.round(value * 100) / 100; }

main().catch(error => {
  process.stderr.write(`${error?.stack || error}\n`);
  process.exitCode = 1;
});
