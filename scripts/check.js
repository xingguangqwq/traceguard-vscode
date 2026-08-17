const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");
const files = [
  path.join(root, "extension.js"),
  ...["src"].flatMap(folder => fs.readdirSync(path.join(root, folder))
    .filter(name => name.endsWith(".js"))
    .map(name => path.join(root, folder, name))),
];

for (const file of files) {
  const result = spawnSync(process.execPath, ["--check", file], { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status || 1);
}
process.stdout.write(`Checked ${files.length} JavaScript files.\n`);
