"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const extensionRoot = path.resolve(process.argv[2] || path.join(__dirname, ".."));
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
  assert.ok(fs.existsSync(path.join(extensionRoot, "package.json")), `No extension package at ${extensionRoot}`);
  for (const relativePath of [
    "THIRD_PARTY_NOTICES.md",
    "resources/traceguard.schema.json",
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
    "node_modules/typescript/lib/lib.esnext.full.d.ts",
  ]) assert.ok(fs.existsSync(path.join(extensionRoot, relativePath)), `Packaged extension is missing ${relativePath}`);
  const { analyzeTextAsync } = require(path.join(extensionRoot, "src", "audit-analyzer.js"));
  const results = [];
  for (const sample of samples) {
    const absolutePath = path.join(extensionRoot, `.traceguard-runtime-${sample.label}${sample.extension}`);
    const analysis = await analyzeTextAsync(sample.text, sample.language, absolutePath, path.basename(absolutePath));
    assert.equal(analysis.frontend?.mode, "ast", `${sample.label} did not load its packaged AST frontend`);
    assert.ok(analysis.functions.length > 0, `${sample.label} produced no function IR`);
    assert.equal(analysis.frontend.treeHasErrors, false, `${sample.label} grammar recovered from a valid smoke sample`);
    results.push(`${sample.label}:${analysis.frontend.id}`);
  }
  process.stdout.write(`Verified packaged AST runtimes: ${results.join(", ")}\n`);
}

main().catch(error => {
  process.stderr.write(`Packaged runtime verification failed: ${error?.stack || error}\n`);
  process.exitCode = 1;
});
