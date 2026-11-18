const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const files = [path.join(root, "extension.js"), ...javascriptFiles(path.join(root, "src"))];

for (const file of files) {
  const result = spawnSync(process.execPath, ["--check", file], { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status || 1);
}
process.stdout.write(`Checked ${files.length} JavaScript files.\n`);
const types = spawnSync(process.execPath, [path.join(__dirname, "typecheck.js")], { stdio: "inherit" });
if (types.error) throw types.error;
if (types.status !== 0) process.exit(types.status || 1);

function javascriptFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true })
    .flatMap(entry => entry.isDirectory()
      ? javascriptFiles(path.join(directory, entry.name))
      : entry.isFile() && entry.name.endsWith(".js") ? [path.join(directory, entry.name)] : [])
    .sort();
}
