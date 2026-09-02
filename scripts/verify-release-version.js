"use strict";

const fs = require("node:fs");
const path = require("node:path");

function verifyReleaseVersion(tag, manifest, lockfile) {
  const value = String(tag || "").trim();
  if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(value)) throw new Error(`Release tag is not a supported semantic version: ${value || "<missing>"}`);
  const tagVersion = value.slice(1);
  if (String(manifest?.version || "") !== tagVersion) {
    throw new Error(`Release tag ${value} does not match package.json ${manifest?.version || "<missing>"}.`);
  }
  const lockVersions = [lockfile?.version, lockfile?.packages?.[""]?.version].filter(Boolean);
  if (lockVersions.some(version => String(version) !== tagVersion)) {
    throw new Error(`Release tag ${value} does not match package-lock.json ${[...new Set(lockVersions)].join(" / ")}.`);
  }
  return tagVersion;
}

function main() {
  const tag = process.argv[2] || process.env.GITHUB_REF_NAME;
  const root = path.resolve(__dirname, "..");
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const lockfile = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
  const version = verifyReleaseVersion(tag, manifest, lockfile);
  process.stdout.write(`Release version verified: v${version}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message || error}\n`);
    process.exitCode = 1;
  }
}

module.exports = { verifyReleaseVersion };
