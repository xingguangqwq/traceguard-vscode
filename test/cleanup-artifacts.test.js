"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");
const { cleanupPlan, removeArtifact } = require("../scripts/cleanup-artifacts");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "traceguard-cleanup-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test("cleanup is limited to old generated artifacts and preserves recent packages", t => {
  const root = fixture(t);
  for (const name of ["source.js", "bench-owasp.js", "old.log", "traceguard-vscode-1.0.0.vsix", "traceguard-vscode-1.1.0.vsix", "traceguard-vscode-1.2.0.vsix"]) fs.writeFileSync(path.join(root, name), "content");
  fs.mkdirSync(path.join(root, ".target-labs"));
  fs.mkdirSync(path.join(root, ".tmp-vsix-old"));
  const old = new Date(Date.now() - 48 * 3600000);
  for (const name of ["old.log", "traceguard-vscode-1.0.0.vsix", ".tmp-vsix-old"]) fs.utimesSync(path.join(root, name), old, old);
  const plan = cleanupPlan(root).map(file => path.basename(file));
  assert.deepEqual(plan, [".tmp-vsix-old", "old.log", "traceguard-vscode-1.0.0.vsix"]);
  assert.equal(fs.existsSync(path.join(root, "old.log")), true, "planning does not delete");
  removeArtifact(root, path.join(root, ".tmp-vsix-old"));
  assert.equal(fs.existsSync(path.join(root, ".tmp-vsix-old")), false);
  assert.throws(() => removeArtifact(root, path.join(root, "source.js")), /Refusing/);
  assert.throws(() => removeArtifact(root, path.join(root, "..", "outside.log")), /Refusing/);
});

test("cleanup refuses a nested directory link without touching its target", t => {
  const root = fixture(t);
  const artifact = path.join(root, ".tmp-vsix-linked");
  const source = path.join(root, "source");
  fs.mkdirSync(artifact); fs.mkdirSync(source);
  fs.writeFileSync(path.join(source, "keep.js"), "keep");
  try { fs.symlinkSync(source, path.join(artifact, "linked"), process.platform === "win32" ? "junction" : "dir"); }
  catch (error) { if (["EPERM", "EACCES"].includes(error.code)) { t.skip("Directory links are unavailable"); return; } throw error; }
  assert.throws(() => removeArtifact(root, artifact), /link/);
  assert.equal(fs.readFileSync(path.join(source, "keep.js"), "utf8"), "keep");
});
