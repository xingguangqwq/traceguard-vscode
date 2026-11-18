"use strict";
// @ts-check

const { normalizeAccessPath } = require("../ir/access-path");
/** @typedef {Pick<import("../ir/contracts").GuardBinding, "inputs" | "protectedOutputs" | "output" | "valueVersions">} VersionBinding */

/** @param {Map<string, number>} versions @param {string | undefined} value */
function advanceValueVersion(versions, value) {
  const key = normalizeAccessPath(value);
  if (!key) return;
  versions.set(key, (versions.get(key) || 0) + 1);
}

/** @param {VersionBinding} binding @param {Map<string, number>} versions @returns {Record<string, number>} */
function captureGuardVersions(binding, versions) {
  return Object.fromEntries([...(binding.inputs || []), ...(binding.protectedOutputs || []), binding.output]
    .map(value => normalizeAccessPath(value))
    .filter(Boolean)
    .map(value => [value, versions.get(value) || 0]));
}

/** @param {VersionBinding} binding @param {string} value @param {Map<string, number>} versions @returns {boolean} */
function guardVersionChanged(binding, value, versions) {
  const key = normalizeAccessPath(value);
  if (!key || !binding.valueVersions || binding.valueVersions[key] === undefined) return false;
  return binding.valueVersions[key] !== (versions.get(key) || 0);
}

module.exports = { advanceValueVersion, captureGuardVersions, guardVersionChanged };
