"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const config = JSON.parse(fs.readFileSync(path.join(root, "tsconfig.check.json"), "utf8"));
const checked = config.include.filter(file => file.endsWith(".js"));
for (const file of checked) {
  if (!/^\s*\/\/\s*@ts-check\s*$/m.test(fs.readFileSync(path.join(root, file), "utf8"))) {
    throw new Error(`Required static checking was removed from ${file}`);
  }
}
const result = spawnSync(process.execPath, [require.resolve("typescript/bin/tsc"), "-p", path.join(root, "tsconfig.check.json"), "--pretty", "false"], { stdio: "inherit", cwd: root });
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status || 1);
process.stdout.write(`Strict type checking passed for ${checked.length} production modules and IR contract assertions.\n`);
