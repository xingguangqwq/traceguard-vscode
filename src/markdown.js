"use strict";

function markdownFence(value) {
  const runs = String(value || "").match(/`+/g) || [];
  const longest = runs.reduce((maximum, run) => Math.max(maximum, run.length), 0);
  return "`".repeat(Math.max(3, longest + 1));
}

module.exports = { markdownFence };
