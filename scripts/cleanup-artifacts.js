"use strict";

const fs = require("node:fs");
const path = require("node:path");

function cleanupPlan(directory, { keepVsix = 2, minAgeHours = 24, now = Date.now() } = {}) {
  const root = fs.realpathSync(directory);
  const entries = fs.readdirSync(root, { withFileTypes: true });
  const packages = entries.filter(entry => entry.isFile() && /^traceguard-vscode-[\w.-]+\.vsix$/.test(entry.name))
    .sort((a, b) => fs.statSync(path.join(root, b.name)).mtimeMs - fs.statSync(path.join(root, a.name)).mtimeMs);
  const preserved = new Set(packages.slice(0, keepVsix).map(entry => entry.name));
  return entries.filter(entry => !entry.isSymbolicLink() && !preserved.has(entry.name) &&
    (entry.isDirectory() && /^\.tmp-vsix(?:-|$)/.test(entry.name) ||
      entry.isFile() && (/\.log$/.test(entry.name) || /^traceguard-vscode-[\w.-]+\.vsix$/.test(entry.name))))
    .map(entry => path.join(root, entry.name))
    .filter(target => now - fs.lstatSync(target).mtimeMs >= minAgeHours * 3600000)
    .sort();
}

function removeArtifact(directory, target) {
  const root = fs.realpathSync(directory);
  const requested = path.resolve(target);
  const absolute = path.join(fs.realpathSync(path.dirname(requested)), path.basename(requested));
  const name = path.basename(absolute);
  if (path.dirname(absolute) !== root) {
    throw new Error(`Refusing cleanup outside generated root artifacts: ${absolute}`);
  }
  const stat = fs.lstatSync(absolute);
  if (!(stat.isDirectory() && /^\.tmp-vsix(?:-|$)/.test(name) ||
    stat.isFile() && (/\.log$/.test(name) || /^traceguard-vscode-[\w.-]+\.vsix$/.test(name)))) {
    throw new Error(`Refusing cleanup of an unrecognized artifact: ${absolute}`);
  }
  const validate = current => {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) throw new Error(`Refusing cleanup through a link: ${current}`);
    const resolved = fs.realpathSync(current);
    if (resolved !== absolute && !resolved.startsWith(absolute + path.sep)) throw new Error(`Cleanup path escaped its artifact: ${resolved}`);
    if (stat.isDirectory()) for (const entry of fs.readdirSync(current)) validate(path.join(current, entry));
  };
  validate(absolute);
  fs.rmSync(absolute, { recursive: fs.lstatSync(absolute).isDirectory() });
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.some(arg => arg !== "--apply")) throw new Error("Usage: npm run clean:artifacts [-- --apply]");
  const root = path.resolve(__dirname, "..");
  const targets = cleanupPlan(root);
  process.stdout.write(`${args.includes("--apply") ? "Removing" : "Dry run:"} ${targets.length} generated artifacts older than 24 hours; keeping the two newest VSIX packages.\n`);
  for (const target of targets) {
    process.stdout.write(`${target}\n`);
    if (args.includes("--apply")) removeArtifact(root, target);
  }
}

module.exports = { cleanupPlan, removeArtifact };
