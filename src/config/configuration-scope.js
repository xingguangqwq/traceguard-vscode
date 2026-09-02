"use strict";

const { normalizePath } = require("../identity");

function configurationForAbsolutePath(options = {}, absolutePath) {
  if (!(options.projectConfigurationsByRoot || []).length) return options.projectConfiguration;
  const target = normalizePath(absolutePath);
  const scoped = (options.projectConfigurationsByRoot || [])
    .map(item => ({ ...item, normalizedRoot: normalizePath(item.root) }))
    .filter(item => target === item.normalizedRoot || target.startsWith(`${item.normalizedRoot}/`))
    .sort((left, right) => right.normalizedRoot.length - left.normalizedRoot.length)[0];
  return scoped?.configuration || options.projectConfiguration;
}

function scopedConfigurationFingerprint(values = []) {
  return JSON.stringify(values.map(item => [
    normalizePath(item.root),
    item.configuration?.fingerprint,
  ]).sort((left, right) => left[0].localeCompare(right[0])));
}

function workspaceRootForAbsolutePath(options = {}, absolutePath) {
  const target = normalizePath(absolutePath);
  return (options.projectConfigurationsByRoot || [])
    .map(item => normalizePath(item.root))
    .filter(root => target === root || target.startsWith(`${root}/`))
    .sort((left, right) => right.length - left.length)[0];
}

function analysisSettingsForAbsolutePath(options = {}, absolutePath) {
  const target = normalizePath(absolutePath);
  const scoped = (options.analysisSettingsByRoot || [])
    .map(item => ({ ...item, normalizedRoot: normalizePath(item.root) }))
    .filter(item => target === item.normalizedRoot || target.startsWith(`${item.normalizedRoot}/`))
    .sort((left, right) => right.normalizedRoot.length - left.normalizedRoot.length)[0];
  return scoped?.settings || {
    maxDepth: options.maxDepth,
    maxHigherOrderDepth: options.maxHigherOrderDepth,
    maxAsyncDepth: options.maxAsyncDepth,
    maxTraceSteps: options.maxTraceSteps,
    maxAnalysisMs: options.maxAnalysisMs,
    maxPaths: options.maxPaths,
    maxSourceBytes: options.maxSourceBytes,
  };
}

module.exports = { analysisSettingsForAbsolutePath, configurationForAbsolutePath, scopedConfigurationFingerprint, workspaceRootForAbsolutePath };
