"use strict";

const path = require("node:path");
const fs = require("node:fs");
const { runTests } = require("@vscode/test-electron");

async function main() {
  const extensionDevelopmentPath = path.resolve(__dirname, "..");
  const localWindowsCode = process.platform === "win32" && process.env.LOCALAPPDATA
    ? path.join(process.env.LOCALAPPDATA, "Programs", "Microsoft VS Code", "Code.exe")
    : undefined;
  const vscodeExecutablePath = process.env.VSCODE_EXECUTABLE_PATH ||
    (localWindowsCode && fs.existsSync(localWindowsCode) ? localWindowsCode : undefined);
  await runTests({
    version: process.env.VSCODE_TEST_VERSION || "1.90.0",
    ...(vscodeExecutablePath ? { vscodeExecutablePath } : {}),
    extensionDevelopmentPath,
    extensionTestsPath: path.join(extensionDevelopmentPath, "test", "extension-host-smoke.js"),
    launchArgs: [extensionDevelopmentPath, "--disable-extensions", "--disable-workspace-trust"],
  });
}

main().catch(error => {
  process.stderr.write(`Extension Host smoke test failed: ${error?.stack || error}\n`);
  process.exitCode = 1;
});
