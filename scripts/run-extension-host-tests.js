"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { runTests } = require("@vscode/test-electron");

async function main() {
  const extensionDevelopmentPath = path.resolve(__dirname, "..");
  // A user's installed VS Code may be an incompatible Insiders or newly
  // released Electron build. Use the pinned test version by default so local,
  // CI and release runs execute the same Extension Host. An explicit path is
  // still supported for controlled environments.
  const executableArgument = process.argv.find(argument => argument.startsWith("--vscode-executable="));
  const vscodeExecutablePath = process.env.VSCODE_EXECUTABLE_PATH || executableArgument?.slice("--vscode-executable=".length);
  // Some agent shells set this variable so Electron binaries behave like the
  // Node executable. Passing it to Code.exe bypasses the Extension Host module
  // loader and makes a valid `require("vscode")` fail. Keep the parent value,
  // but never leak it into the VS Code child process.
  const electronRunAsNode = process.env.ELECTRON_RUN_AS_NODE;
  const userDataPath = fs.mkdtempSync(path.join(os.tmpdir(), "traceguard-vscode-test-"));
  delete process.env.ELECTRON_RUN_AS_NODE;
  try {
    await runTests({
      version: process.env.VSCODE_TEST_VERSION || "1.90.0",
      ...(vscodeExecutablePath ? { vscodeExecutablePath } : {}),
      extensionDevelopmentPath,
      extensionTestsPath: path.join(extensionDevelopmentPath, "test", "extension-host-smoke.js"),
      launchArgs: [
        `--user-data-dir=${userDataPath}`,
        "--disable-extensions",
        "--disable-workspace-trust",
        extensionDevelopmentPath,
      ],
    });
  } finally {
    if (electronRunAsNode === undefined) delete process.env.ELECTRON_RUN_AS_NODE;
    else process.env.ELECTRON_RUN_AS_NODE = electronRunAsNode;
    fs.rmSync(userDataPath, { recursive: true, force: true, maxRetries: 3 });
  }
}

main().catch(error => {
  process.stderr.write(`Extension Host smoke test failed: ${error?.stack || error}\n`);
  process.exitCode = 1;
});
