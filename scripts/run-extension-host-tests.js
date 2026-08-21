"use strict";

const path = require("node:path");
const { runTests } = require("@vscode/test-electron");

async function main() {
  const extensionDevelopmentPath = path.resolve(__dirname, "..");
  await runTests({
    version: process.env.VSCODE_TEST_VERSION || "1.90.0",
    extensionDevelopmentPath,
    extensionTestsPath: path.join(extensionDevelopmentPath, "test", "extension-host-smoke.js"),
    launchArgs: [extensionDevelopmentPath, "--disable-extensions", "--disable-workspace-trust"],
  });
}

main().catch(error => {
  process.stderr.write(`Extension Host smoke test failed: ${error?.stack || error}\n`);
  process.exitCode = 1;
});
