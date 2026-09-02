"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const zlib = require("node:zlib");
const { promisify } = require("node:util");

const gzip = promisify(zlib.gzip);
const root = path.resolve(__dirname, "..");
const outputRoot = path.join(root, "dist-assets");

const assets = {
  "javascript-typescript": {
    files: {
      "grammars/tree-sitter-javascript.wasm": "node_modules/tree-sitter-javascript/tree-sitter-javascript.wasm",
      "grammars/tree-sitter-typescript.wasm": "node_modules/tree-sitter-typescript/tree-sitter-typescript.wasm",
      "grammars/tree-sitter-tsx.wasm": "node_modules/tree-sitter-typescript/tree-sitter-tsx.wasm",
      "typescript/traceguard-minimal-lib.d.ts": "assets-src/typescript/traceguard-minimal-lib.d.ts",
    },
    grammars: {
      javascript: "grammars/tree-sitter-javascript.wasm",
      typescript: "grammars/tree-sitter-typescript.wasm",
      tsx: "grammars/tree-sitter-tsx.wasm",
    },
    typeLibrary: "typescript/traceguard-minimal-lib.d.ts",
  },
  csharp: grammarAsset("csharp", "node_modules/tree-sitter-c-sharp/tree-sitter-c_sharp.wasm"),
  go: grammarAsset("go", "node_modules/tree-sitter-go/tree-sitter-go.wasm"),
};

async function main() {
  const extension = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8"));
  const repository = String(extension.repository?.url || "").replace(/\.git$/, "");
  const manifest = {
    schema: "traceguard-language-assets",
    version: 1,
    release: extension.version,
    baseUrl: `${repository}/releases/download/v${extension.version}`,
    assets: {},
  };
  await fs.mkdir(outputRoot, { recursive: true });
  for (const fileName of await fs.readdir(outputRoot)) {
    if (/^traceguard-assets-[a-z-]+-v[0-9.]+\.json\.gz$/.test(fileName)) await fs.unlink(path.join(outputRoot, fileName));
  }
  for (const [assetId, specification] of Object.entries(assets)) {
    const files = [];
    for (const [target, source] of Object.entries(specification.files)) {
      const content = await fs.readFile(path.join(root, source));
      files.push({ path: target, sha256: sha256(content), data: content.toString("base64") });
    }
    const pack = Buffer.from(JSON.stringify({ schema: "traceguard-language-asset-pack", version: 1, assetId, files }));
    const compressed = await gzip(pack, { level: 9, mtime: 0 });
    const fileName = `traceguard-assets-${assetId}-v${extension.version}.json.gz`;
    await fs.writeFile(path.join(outputRoot, fileName), compressed);
    manifest.assets[assetId] = {
      fileName,
      sha256: sha256(compressed),
      bytes: compressed.byteLength,
      files: Object.fromEntries(files.map(file => [file.path, file.sha256])),
      grammars: specification.grammars,
      typeLibrary: specification.typeLibrary,
    };
  }
  await fs.writeFile(path.join(root, "resources/language-assets.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write(`Built ${Object.keys(manifest.assets).length} TraceGuard language asset packs for ${extension.version}.\n`);
}

function grammarAsset(language, source) {
  const target = `grammars/${path.basename(source)}`;
  return { files: { [target]: source }, grammars: { [language]: target } };
}

function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }

main().catch(error => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
