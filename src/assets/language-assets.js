"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const zlib = require("node:zlib");
const { promisify } = require("node:util");

const gunzip = promisify(zlib.gunzip);
const MAX_PACK_BYTES = 24 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 64 * 1024 * 1024;
const ASSET_BY_LANGUAGE = Object.freeze({
  javascript: "javascript-typescript",
  typescript: "javascript-typescript",
  tsx: "javascript-typescript",
  java: "java",
  python: "python",
  php: "php",
  csharp: "csharp",
  go: "go",
});

const BUNDLED_GRAMMARS = Object.freeze({
  java: ["tree-sitter-java/tree-sitter-java.wasm"],
  python: ["tree-sitter-python/tree-sitter-python.wasm"],
  php: ["tree-sitter-php/tree-sitter-php.wasm"],
  csharp: ["tree-sitter-c-sharp/tree-sitter-c_sharp.wasm"],
  go: ["tree-sitter-go/tree-sitter-go.wasm"],
  javascript: ["tree-sitter-javascript/tree-sitter-javascript.wasm"],
  typescript: ["tree-sitter-typescript/tree-sitter-typescript.wasm"],
  tsx: ["tree-sitter-typescript/tree-sitter-tsx.wasm"],
});

class LanguageAssetManager {
  constructor(options = {}) {
    this.manifestPath = options.manifestPath || path.resolve(__dirname, "../../resources/language-assets.json");
    this.inflight = new Map();
    this.ready = new Map();
    this.failures = new Map();
    this.failureBackoffMs = Math.max(1000, Number(options.failureBackoffMs) || 30_000);
  }

  ensure(language, options = {}) {
    const assetId = ASSET_BY_LANGUAGE[language];
    if (!assetId) return Promise.reject(new Error(`No language asset is configured for ${language}.`));
    const cacheKey = `${assetId}:${options.assetCacheRoot || "bundled"}:${options.assetBaseUrl || "default"}:${options.assetPackRoot || ""}`;
    const recentFailure = this.failures.get(cacheKey);
    if (recentFailure && Date.now() - recentFailure.at < this.failureBackoffMs) return Promise.reject(recentFailure.error);
    if (this.ready.has(cacheKey)) return Promise.resolve(this.ready.get(cacheKey));
    if (this.inflight.has(cacheKey)) return this.inflight.get(cacheKey);
    const pending = this._ensure(assetId, options).then(asset => {
      this.ready.set(cacheKey, asset);
      this.failures.delete(cacheKey);
      return asset;
    }).catch(error => {
      this.failures.set(cacheKey, { at: Date.now(), error });
      throw error;
    }).finally(() => this.inflight.delete(cacheKey));
    this.inflight.set(cacheKey, pending);
    return pending;
  }

  async _ensure(assetId, options) {
    const manifest = await readManifest(options.assetManifestPath || this.manifestPath);
    const entry = manifest?.assets?.[assetId];
    const cached = entry && options.assetCacheRoot
      ? await cachedAsset(options.assetCacheRoot, manifest.version, assetId, entry)
      : undefined;
    if (cached) return cached;
    const bundled = options.allowBundledAssets === false ? undefined : bundledAsset(assetId);
    if (bundled) return bundled;
    if (!entry) throw new Error(`TraceGuard language asset manifest has no ${assetId} entry.`);
    if (options.allowAssetDownloads === false) throw new Error(`TraceGuard language asset ${assetId} is not installed and downloads are disabled.`);
    if (!options.assetCacheRoot) throw new Error(`TraceGuard cannot install ${assetId}: no global asset cache is configured.`);
    const bytes = options.assetPackRoot
      ? await fsp.readFile(path.join(options.assetPackRoot, entry.fileName))
      : await downloadAsset(assetUrl(manifest, entry, options.assetBaseUrl), options.assetDownloadTimeoutMs);
    if (bytes.byteLength > MAX_PACK_BYTES) throw new Error(`TraceGuard asset ${assetId} exceeds the ${MAX_PACK_BYTES} byte compressed limit.`);
    if (sha256(bytes) !== entry.sha256) throw new Error(`TraceGuard rejected ${assetId}: compressed SHA-256 mismatch.`);
    return installPack(bytes, options.assetCacheRoot, manifest.version, assetId, entry);
  }
}

async function readManifest(manifestPath) {
  try {
    const value = JSON.parse(await fsp.readFile(manifestPath, "utf8"));
    if (value.schema !== "traceguard-language-assets" || value.version !== 1) throw new Error("unsupported schema");
    return value;
  } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw new Error(`TraceGuard could not read its language asset manifest: ${error.message}`);
  }
}

function bundledAsset(assetId) {
  const grammars = {};
  for (const [language, candidates] of Object.entries(BUNDLED_GRAMMARS)) {
    if (ASSET_BY_LANGUAGE[language] !== assetId) continue;
    const resolved = resolveFirst(candidates);
    if (!resolved) return undefined;
    grammars[language] = resolved;
  }
  let typeLibraryPath;
  if (assetId === "javascript-typescript") {
    const candidate = path.resolve(__dirname, "../../assets-src/typescript/traceguard-minimal-lib.d.ts");
    if (!fs.existsSync(candidate)) return undefined;
    typeLibraryPath = candidate;
  }
  return { assetId, source: "bundled-development", grammars, typeLibraryPath };
}

async function cachedAsset(cacheRoot, version, assetId, entry) {
  const root = path.join(cacheRoot, String(version), assetId);
  try {
    const marker = JSON.parse(await fsp.readFile(path.join(root, ".installed.json"), "utf8"));
    if (marker.packSha256 !== entry.sha256) return undefined;
    return await materializedAsset(root, assetId, entry, "cache", true);
  } catch {
    return undefined;
  }
}

async function installPack(bytes, cacheRoot, version, assetId, entry) {
  const unpacked = await gunzip(bytes);
  if (unpacked.byteLength > MAX_UNPACKED_BYTES) throw new Error(`TraceGuard asset ${assetId} exceeds the unpacked size limit.`);
  const pack = JSON.parse(unpacked.toString("utf8"));
  if (pack.schema !== "traceguard-language-asset-pack" || pack.version !== 1 || pack.assetId !== assetId) {
    throw new Error(`TraceGuard rejected ${assetId}: invalid asset pack identity.`);
  }
  const target = path.join(cacheRoot, String(version), assetId);
  const temporary = path.join(cacheRoot, String(version), `.tmp-${assetId}-${process.pid}-${crypto.randomBytes(6).toString("hex")}`);
  await fsp.mkdir(temporary, { recursive: true });
  try {
    let total = 0;
    const installedFiles = new Set();
    for (const file of pack.files || []) {
      const relativePath = safeRelativePath(file.path);
      const expectedSha256 = entry.files?.[relativePath];
      if (entry.files && !expectedSha256) throw new Error(`TraceGuard rejected ${assetId}: unexpected file ${relativePath}.`);
      const content = Buffer.from(file.data, "base64");
      total += content.byteLength;
      if (total > MAX_UNPACKED_BYTES) throw new Error(`TraceGuard asset ${assetId} expands beyond its size budget.`);
      if (sha256(content) !== file.sha256) throw new Error(`TraceGuard rejected ${assetId}/${relativePath}: file SHA-256 mismatch.`);
      if (expectedSha256 && file.sha256 !== expectedSha256) throw new Error(`TraceGuard rejected ${assetId}/${relativePath}: manifest SHA-256 mismatch.`);
      const destination = path.join(temporary, ...relativePath.split("/"));
      await fsp.mkdir(path.dirname(destination), { recursive: true });
      await fsp.writeFile(destination, content);
      installedFiles.add(relativePath);
    }
    for (const relativePath of Object.keys(entry.files || {})) {
      if (!installedFiles.has(relativePath)) throw new Error(`TraceGuard rejected ${assetId}: missing declared file ${relativePath}.`);
    }
    await fsp.writeFile(path.join(temporary, ".installed.json"), JSON.stringify({ packSha256: entry.sha256, installedAt: new Date().toISOString() }));
    await fsp.mkdir(path.dirname(target), { recursive: true });
    await fsp.rm(target, { recursive: true, force: true });
    await fsp.rename(temporary, target);
  } catch (error) {
    await fsp.rm(temporary, { recursive: true, force: true });
    throw error;
  }
  return materializedAsset(target, assetId, entry, "download", false);
}

async function materializedAsset(root, assetId, entry, source, verifyIntegrity) {
  if (verifyIntegrity) {
    for (const [relativePath, expected] of Object.entries(entry.files || {})) {
      const resolved = path.join(root, ...safeRelativePath(relativePath).split("/"));
      const content = await fsp.readFile(resolved);
      if (sha256(content) !== expected) throw new Error(`TraceGuard cached asset ${assetId}/${relativePath} failed integrity verification.`);
    }
  }
  const grammars = {};
  for (const [language, relativePath] of Object.entries(entry.grammars || {})) {
    const resolved = path.join(root, ...safeRelativePath(relativePath).split("/"));
    if (!fs.existsSync(resolved)) throw new Error(`TraceGuard cached asset ${assetId} is missing ${relativePath}.`);
    grammars[language] = resolved;
  }
  const typeLibraryPath = entry.typeLibrary
    ? path.join(root, ...safeRelativePath(entry.typeLibrary).split("/"))
    : undefined;
  if (typeLibraryPath && !fs.existsSync(typeLibraryPath)) throw new Error(`TraceGuard cached asset ${assetId} is missing ${entry.typeLibrary}.`);
  return { assetId, source, root, grammars, typeLibraryPath };
}

async function downloadAsset(url, timeoutMs = 30_000) {
  if (!/^https:\/\//i.test(url)) throw new Error(`TraceGuard language assets require HTTPS: ${url}`);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(1000, Number(timeoutMs) || 30_000));
  try {
    const response = await fetch(url, { signal: controller.signal, redirect: "follow" });
    if (!response.ok) throw new Error(`HTTP ${response.status} ${response.statusText}`);
    const declared = Number(response.headers.get("content-length") || 0);
    if (declared > MAX_PACK_BYTES) throw new Error(`asset response exceeds ${MAX_PACK_BYTES} bytes`);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.byteLength > MAX_PACK_BYTES) throw new Error(`asset response exceeds ${MAX_PACK_BYTES} bytes`);
    return bytes;
  } catch (error) {
    throw new Error(`TraceGuard could not download ${url}: ${error.message}`);
  } finally {
    clearTimeout(timer);
  }
}

function assetUrl(manifest, entry, overrideBaseUrl) {
  const base = String(overrideBaseUrl || manifest.baseUrl || "").replace(/\/+$/, "");
  if (!base) throw new Error(`TraceGuard asset ${entry.fileName} has no download base URL.`);
  return `${base}/${encodeURIComponent(entry.fileName)}`;
}

function safeRelativePath(value) {
  const normalized = path.posix.normalize(String(value || "").replaceAll("\\", "/"));
  if (!normalized || normalized === "." || normalized.startsWith("../") || path.posix.isAbsolute(normalized)) {
    throw new Error(`Unsafe language asset path: ${value}`);
  }
  return normalized;
}

function resolveFirst(candidates) {
  for (const candidate of candidates) {
    try { return require.resolve(candidate); } catch {}
  }
  return undefined;
}

function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }

const languageAssets = new LanguageAssetManager();

module.exports = {
  ASSET_BY_LANGUAGE,
  LanguageAssetManager,
  languageAssets,
  safeRelativePath,
  sha256,
};
