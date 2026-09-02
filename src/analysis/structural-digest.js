"use strict";

const crypto = require("node:crypto");

function structuralDigest(value, length = 64) {
  const hash = crypto.createHash("sha256");
  appendValue(hash, value, new Set());
  return hash.digest("hex").slice(0, Math.max(1, Math.min(64, Number(length) || 64)));
}

function appendValue(hash, value, ancestors) {
  if (value === null) {
    hash.update("null;");
    return;
  }
  const type = typeof value;
  if (type !== "object") {
    const text = String(value);
    hash.update(`${type}:${text.length}:`);
    hash.update(text);
    hash.update(";");
    return;
  }
  if (ancestors.has(value)) {
    hash.update("cycle;");
    return;
  }
  ancestors.add(value);
  if (Array.isArray(value)) {
    hash.update(`array:${value.length}:[`);
    for (const item of value) appendValue(hash, item, ancestors);
    hash.update("];");
  } else {
    const keys = Object.keys(value).sort();
    hash.update(`object:${keys.length}:{`);
    for (const key of keys) {
      hash.update(`key:${key.length}:${key};`);
      appendValue(hash, value[key], ancestors);
    }
    hash.update("};");
  }
  ancestors.delete(value);
}

module.exports = { structuralDigest };
