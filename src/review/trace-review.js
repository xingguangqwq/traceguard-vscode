"use strict";

const { stableHash } = require("../identity");

// Decisions are scoped to the exact evidence tree. A changed result must be reviewed again.
class TraceReviewState {
  constructor(keys = []) {
    this.keys = new Set(Array.isArray(keys) ? keys.filter(key => typeof key === "string").slice(-1000) : []);
  }

  setChain(chain) {
    this.scope = stableHash(JSON.stringify(chain?.roots
      ? { kind: chain.kind, subject: chain.subject, roots: chain.roots }
      : { steps: chain?.steps || [] }));
  }

  key(node) { return `${this.scope}:${stableHash(JSON.stringify(node))}`; }
  has(node) { return this.keys.has(this.key(node)); }
  toggle(node) {
    const key = this.key(node);
    if (this.keys.has(key)) this.keys.delete(key);
    else this.keys.add(key);
    while (this.keys.size > 1000) this.keys.delete(this.keys.values().next().value);
    return [...this.keys];
  }
}

module.exports = { TraceReviewState };
