"use strict";

const path = require("node:path");
const { normalizePath, stableHash } = require("../identity");

const COMPOSER_FILENAME = "composer.json";
const MAX_COMPOSER_BYTES = 1024 * 1024;

function parseComposerConfigurationText(text, workspaceRoot, source = path.join(workspaceRoot, COMPOSER_FILENAME)) {
  let value;
  try {
    value = JSON.parse(String(text || ""));
  } catch (error) {
    return invalid(source, `Invalid composer.json: ${String(error.message || error)}`);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return invalid(source, "composer.json root must be an object.");
  const mappings = [
    ...compilePsr4(value.autoload?.["psr-4"], workspaceRoot, false),
    ...compilePsr4(value["autoload-dev"]?.["psr-4"], workspaceRoot, true),
  ].sort((left, right) => right.prefix.length - left.prefix.length || Number(left.dev) - Number(right.dev));
  const identity = finalizeProjectIdentity({ workspaceRoot, source, mappings });
  return { valid: true, identity, issues: [] };
}

function emptyProjectIdentity(workspaceRoot) {
  return finalizeProjectIdentity({ workspaceRoot, source: path.join(workspaceRoot, COMPOSER_FILENAME), mappings: [] });
}

function compilePsr4(value, workspaceRoot, dev) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  const mappings = [];
  for (const [rawPrefix, rawDirectories] of Object.entries(value)) {
    const prefix = String(rawPrefix || "").replace(/^\\+/, "");
    const directories = (Array.isArray(rawDirectories) ? rawDirectories : [rawDirectories])
      .filter(directory => typeof directory === "string" && directory.trim())
      .map(directory => path.resolve(workspaceRoot, directory));
    if (!directories.length) continue;
    mappings.push({ prefix, directories, dev });
  }
  return mappings;
}

function composerPathsForType(identity, typeName) {
  const type = String(typeName || "").replace(/^\\+/, "");
  const mapping = (identity?.mappings || []).find(item => !item.prefix || type.toLowerCase().startsWith(item.prefix.toLowerCase()));
  if (!mapping) return [];
  const suffix = type.slice(mapping.prefix.length).replaceAll("\\", path.sep);
  return mapping.directories.map(directory => normalizePath(path.join(directory, `${suffix}.php`)));
}

function projectIdentityForAbsolutePath(options = {}, absolutePath) {
  const target = normalizePath(absolutePath);
  return (options.projectIdentitiesByRoot || [])
    .map(item => ({ ...item, normalizedRoot: normalizePath(item.root) }))
    .filter(item => target === item.normalizedRoot || target.startsWith(`${item.normalizedRoot}/`))
    .sort((left, right) => right.normalizedRoot.length - left.normalizedRoot.length)[0]?.identity;
}

function projectIdentityFingerprint(values = []) {
  return JSON.stringify(values.map(item => [normalizePath(item.root), item.identity?.fingerprint]).sort((left, right) => left[0].localeCompare(right[0])));
}

function finalizeProjectIdentity(identity) {
  const mappings = (identity.mappings || []).map(item => ({
    prefix: item.prefix,
    directories: item.directories.map(directory => path.resolve(directory)),
    dev: Boolean(item.dev),
  }));
  return { ...identity, mappings, fingerprint: stableHash(JSON.stringify(mappings)) };
}

function invalid(source, message) {
  return { valid: false, identity: undefined, issues: [{ source, path: "$.autoload.psr-4", message, severity: "error", line: 1, column: 1 }] };
}

module.exports = {
  COMPOSER_FILENAME,
  MAX_COMPOSER_BYTES,
  composerPathsForType,
  emptyProjectIdentity,
  parseComposerConfigurationText,
  projectIdentityFingerprint,
  projectIdentityForAbsolutePath,
};
