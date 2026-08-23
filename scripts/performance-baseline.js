"use strict";

const path = require("node:path");
const { performance } = require("node:perf_hooks");
const { DataflowWorkerClient } = require("../src/dataflow/worker-client");

const benchmarkRoot = path.join(path.parse(process.cwd()).root, "traceguard-benchmark");

const requested = Number(process.argv.find(argument => argument.startsWith("--files="))?.split("=")[1] || 200);
const fileCount = Math.min(5000, Math.max(1, Number.isFinite(requested) ? Math.floor(requested) : 200));
const requestedRssLimit = Number(process.argv.find(argument => argument.startsWith("--max-rss-mib="))?.split("=")[1]);
const maxRssMiB = Number.isFinite(requestedRssLimit) && requestedRssLimit > 0 ? requestedRssLimit : null;
const fixture = process.argv.find(argument => argument.startsWith("--fixture="))?.split("=")[1] || "independent-js-routes";
const requestedIncrementalLimit = Number(process.argv.find(argument => argument.startsWith("--max-incremental-ms="))?.split("=")[1]);
const maxIncrementalMs = Number.isFinite(requestedIncrementalLimit) && requestedIncrementalLimit > 0
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
  const changed = benchmark.changed;
  const dispatchStartedAt = performance.now();
  const pending = client.updateFile(changed);
  const dispatchedAt = performance.now();
  const incremental = await pending;
  const finishedAt = performance.now();
  const memory = process.memoryUsage();
  await client.dispose();

  const result = {
    fixture: benchmark.name,
    files: fileCount,
    functions: initial.analyses.reduce((total, analysis) => total + analysis.ir.functions.length, 0),
    findings: initial.findingDelta.upsert.length,
    initializeMs: round(initializedAt - startedAt),
    mainThreadDispatchMs: round(dispatchedAt - dispatchStartedAt),
    incrementalMs: round(finishedAt - dispatchStartedAt),
    invalidatedFiles: incremental.metadata.incrementallyInvalidatedFiles,
    invalidatedFunctions: incremental.metadata.incrementallyInvalidatedFunctions,
    heapDeltaMiB: round(Math.max(0, memory.heapUsed - heapBefore) / 1024 / 1024),
    rssMiB: round(memory.rss / 1024 / 1024),
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (result.mainThreadDispatchMs >= 50) throw new Error(`Main-thread dispatch gate failed: ${result.mainThreadDispatchMs} ms (target <50 ms).`);
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
      changed: {
        ...provider,
        version: "number",
        text: "export function consume(callback: (value: number) => void) { callback(1); }",
      },
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
    minimumInvalidatedFiles: 1,
  };
}

function round(value) { return Math.round(value * 100) / 100; }

main().catch(error => {
  process.stderr.write(`${error?.stack || error}\n`);
  process.exitCode = 1;
});
