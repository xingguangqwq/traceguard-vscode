"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const yauzl = require("yauzl");

const repositoryRoot = path.resolve(__dirname, "..");
const requestedExtensionRoot = process.argv[2] ? path.resolve(process.argv[2]) : undefined;
let extensionRoot = requestedExtensionRoot;
const assetPackRoot = path.resolve(process.argv[3] || path.join(__dirname, "..", "dist-assets"));
const samples = [
  { label: "javascript", language: "javascript", extension: ".js", text: "export function run(req) { const cmd = req.body.cmd; exec(cmd); }" },
  { label: "typescript", language: "typescript", extension: ".ts", text: "export function run(req: { body: { cmd: string } }): void { exec(req.body.cmd); }" },
  { label: "tsx", language: "typescript", extension: ".tsx", text: "export const View = ({ value }: { value: string }) => <section>{value}</section>;" },
  { label: "java", language: "java", extension: ".java", text: "class Demo { void run(String value) { Runtime.getRuntime().exec(value); } }" },
  { label: "python", language: "python", extension: ".py", text: "def run(value):\n    eval(value)\n" },
  { label: "php", language: "php", extension: ".php", text: "<?php function run($value) { system($value); }" },
  { label: "csharp", language: "csharp", extension: ".cs", text: "class Demo { void Run(string value) { System.Diagnostics.Process.Start(value); } }" },
  { label: "go", language: "go", extension: ".go", text: "package demo\nfunc run(value string) { exec.Command(value) }\n" },
];

async function main() {
  const packageWorkspace = requestedExtensionRoot ? undefined : fs.mkdtempSync(path.join(os.tmpdir(), "traceguard-vsix-verify-"));
  extensionRoot = requestedExtensionRoot || await unpackCurrentVsix(packageWorkspace);
  assert.ok(fs.existsSync(path.join(extensionRoot, "package.json")), `No extension package at ${extensionRoot}`);
  if (!requestedExtensionRoot) verifyRuntimeSourceParity(extensionRoot);
  assert.deepEqual(
    fs.readdirSync(extensionRoot, { withFileTypes: true }).filter(entry => entry.isFile()).map(entry => entry.name).sort(),
    ["LICENSE.txt", "THIRD_PARTY_NOTICES.md", "changelog.md", "extension.js", "package.json", "readme.md"],
    "VSIX root contains an undeclared workspace or probe file",
  );
  for (const relativePath of [
    "THIRD_PARTY_NOTICES.md",
    "resources/traceguard.schema.json",
    "resources/language-assets.json",
    "src/config/project-config.js",
    "node_modules/web-tree-sitter/LICENSE",
    "node_modules/tree-sitter-javascript/LICENSE",
    "node_modules/tree-sitter-typescript/LICENSE",
    "node_modules/tree-sitter-java/LICENSE",
    "node_modules/tree-sitter-python/LICENSE",
    "node_modules/tree-sitter-php/LICENSE",
    "node_modules/tree-sitter-c-sharp/LICENSE",
    "node_modules/tree-sitter-go/LICENSE",
    "node_modules/typescript/LICENSE.txt",
    "node_modules/typescript/ThirdPartyNoticeText.txt",
  ]) assert.ok(fs.existsSync(path.join(extensionRoot, relativePath)), `Packaged extension is missing ${relativePath}`);
  for (const relativePath of [
    "node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm",
    "node_modules/tree-sitter-typescript/tree-sitter-typescript.wasm",
    "node_modules/typescript/lib/lib.esnext.full.d.ts",
  ]) assert.equal(fs.existsSync(path.join(extensionRoot, relativePath)), false, `Core VSIX still contains deferred asset ${relativePath}`);
  assert.equal(fs.existsSync(path.join(extensionRoot, "debug.log")), false, "Core VSIX contains a workspace debug log");
  for (const relativePath of [
    "node_modules/tree-sitter-java/tree-sitter-java.wasm",
    "node_modules/tree-sitter-python/tree-sitter-python.wasm",
    "node_modules/tree-sitter-php/tree-sitter-php.wasm",
  ]) assert.equal(fs.existsSync(path.join(extensionRoot, relativePath)), true, `Offline core grammar is missing ${relativePath}`);

  const cacheRoot = fs.mkdtempSync(path.join(os.tmpdir(), "traceguard-package-assets-"));
  const deferredLanguageAssetOptions = { assetCacheRoot: cacheRoot, assetPackRoot, allowBundledAssets: false };
  const offlineCoreAssetOptions = { assetCacheRoot: cacheRoot, allowBundledAssets: true, allowAssetDownloads: false };
  const results = [];
  try {
    const { analyzeTextAsync } = require(path.join(extensionRoot, "src", "audit-analyzer.js"));
    for (const sample of samples) {
      const absolutePath = path.join(extensionRoot, `.traceguard-runtime-${sample.label}${sample.extension}`);
      const coreOffline = ["java", "python", "php"].includes(sample.language);
      const analysis = await analyzeTextAsync(sample.text, sample.language, absolutePath, path.basename(absolutePath), {
        languageAssets: coreOffline ? offlineCoreAssetOptions : deferredLanguageAssetOptions,
      });
      assert.equal(analysis.frontend?.mode, "ast", `${sample.label} did not load its deferred AST frontend`);
      assert.ok(analysis.functions.length > 0, `${sample.label} produced no function IR`);
      assert.equal(analysis.frontend.treeHasErrors, false, `${sample.label} grammar recovered from a valid smoke sample`);
      results.push(`${sample.label}:${analysis.frontend.id}`);
    }
    const { DataflowWorkerClient } = require(path.join(extensionRoot, "src", "dataflow", "worker-client.js"));
    const worker = new DataflowWorkerClient({
      workerPath: path.join(extensionRoot, "src", "dataflow", "worker.js"),
      indexTimeoutMs: 300_000,
    });
    const backendFiles = [
      packagedFile("CommandController.java", "java", "class CommandController { void run(HttpServletRequest request) { Runtime.getRuntime().exec(request.getParameter(\"cmd\")); } }"),
      packagedFile("command.php", "php", "<?php function run() { system($_GET[\"cmd\"]); }"),
      packagedFile("command.py", "python", "import os\ndef run(request):\n    os.system(request.args.get(\"cmd\"))\n"),
    ];
    try {
      const initialized = await worker.initializeWorkspace(backendFiles, { maxDepth: 6, maxPaths: 80, languageAssets: offlineCoreAssetOptions });
      const findings = initialized.findingDelta.upsert;
      assert.ok(findings.some(finding => finding.relativePath === "CommandController.java"));
      assert.ok(findings.some(finding => finding.relativePath === "command.php"));
      assert.ok(findings.some(finding => finding.relativePath === "command.py"));
      const query = await worker.queryPaths({ absolutePath: backendFiles[0].absolutePath });
      assert.ok(Array.isArray(query.paths));
      assert.ok(query.metadata.workerRssBytes > 0);
      results.push("worker:java/php/python");
    } finally {
      await worker.dispose();
    }
  } finally {
    fs.rmSync(cacheRoot, { recursive: true, force: true });
    if (packageWorkspace) fs.rmSync(packageWorkspace, { recursive: true, force: true });
  }
  process.stdout.write(`Verified offline core and deferred packaged AST runtimes: ${results.join(", ")}\n`);
}

async function unpackCurrentVsix(targetRoot) {
  const manifest = JSON.parse(fs.readFileSync(path.join(repositoryRoot, "package.json"), "utf8"));
  const vsixPath = path.join(repositoryRoot, `traceguard-vscode-${manifest.version}.vsix`);
  assert.ok(fs.existsSync(vsixPath), `No packaged VSIX at ${vsixPath}; run npm run package first`);
  await extractZip(vsixPath, targetRoot);
  return path.join(targetRoot, "extension");
}

function verifyRuntimeSourceParity(packagedRoot) {
  const sourceFiles = ["extension.js", "package.json", ...relativeFiles(path.join(repositoryRoot, "src"), ".js").map(file => `src/${file}`)];
  const packagedFiles = relativeFiles(path.join(packagedRoot, "src"), ".js").map(file => `src/${file}`);
  assert.deepEqual(packagedFiles, sourceFiles.filter(file => file.startsWith("src/")), "VSIX runtime source set differs from the workspace");
  for (const relativePath of sourceFiles) {
    const workspaceBytes = fs.readFileSync(path.join(repositoryRoot, ...relativePath.split("/")));
    const packagedBytes = fs.readFileSync(path.join(packagedRoot, ...relativePath.split("/")));
    assert.ok(workspaceBytes.equals(packagedBytes), `VSIX runtime file is stale: ${relativePath}`);
  }
}

function relativeFiles(root, extension) {
  if (!fs.existsSync(root)) return [];
  const files = [];
  const pending = [root];
  while (pending.length) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolutePath = path.join(directory, entry.name);
      if (entry.isDirectory()) pending.push(absolutePath);
      else if (!extension || entry.name.endsWith(extension)) files.push(path.relative(root, absolutePath).replaceAll("\\", "/"));
    }
  }
  return files.sort();
}

function extractZip(zipPath, targetRoot) {
  return new Promise((resolve, reject) => {
    yauzl.open(zipPath, { lazyEntries: true }, (openError, zip) => {
      if (openError) { reject(openError); return; }
      let settled = false;
      const fail = error => {
        if (settled) return;
        settled = true;
        zip.close();
        reject(error);
      };
      zip.on("error", fail);
      zip.on("end", () => {
        if (settled) return;
        settled = true;
        resolve();
      });
      zip.on("entry", entry => {
        let relativePath;
        try {
          relativePath = safeZipPath(entry.fileName);
        } catch (error) {
          fail(error);
          return;
        }
        const destination = path.join(targetRoot, ...relativePath.split("/"));
        if (/\/$/.test(entry.fileName)) {
          fs.mkdirSync(destination, { recursive: true });
          zip.readEntry();
          return;
        }
        fs.mkdirSync(path.dirname(destination), { recursive: true });
        zip.openReadStream(entry, (streamError, stream) => {
          if (streamError) { fail(streamError); return; }
          const output = fs.createWriteStream(destination, { flags: "wx" });
          stream.on("error", fail);
          output.on("error", fail);
          output.on("close", () => { if (!settled) zip.readEntry(); });
          stream.pipe(output);
        });
      });
      zip.readEntry();
    });
  });
}

function safeZipPath(value) {
  const normalized = path.posix.normalize(String(value || "").replaceAll("\\", "/"));
  if (!normalized || normalized === "." || normalized.startsWith("../") || path.posix.isAbsolute(normalized) || /^[A-Za-z]:/.test(normalized)) {
    throw new Error(`Unsafe VSIX entry path: ${value}`);
  }
  return normalized;
}

function packagedFile(relativePath, language, text) {
  return {
    absolutePath: path.join(extensionRoot, ".traceguard-package-smoke", relativePath),
    relativePath,
    language,
    version: "package-smoke-1",
    text,
  };
}

main().catch(error => {
  process.stderr.write(`Packaged runtime verification failed: ${error?.stack || error}\n`);
  process.exitCode = 1;
});
