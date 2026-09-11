"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { dependencyFingerprints } = require("../src/review/fingerprint");
const { reconcileReviewStatuses } = require("../src/review/status-store");

test("dependency fingerprints propagate through recursive calls without changing unrelated roots", () => {
  const records = [
    { key: "entry", digest: "a", dependencies: ["service"] },
    { key: "service", digest: "b", dependencies: ["mapper"] },
    { key: "mapper", digest: "c", dependencies: ["service"] },
    { key: "other-root", digest: "d", dependencies: [] },
  ];
  const before = dependencyFingerprints(records);
  const reordered = dependencyFingerprints([...records].reverse());
  assert.deepEqual([...before].sort(), [...reordered].sort());
  records[2].digest = "changed guard";
  const after = dependencyFingerprints(records);
  for (const key of ["entry", "service", "mapper"]) assert.notEqual(before.get(key), after.get(key));
  assert.equal(before.get("other-root"), after.get("other-root"));
  records.pop();
  records.splice(2, 1);
  assert.notEqual(after.get("entry"), dependencyFingerprints(records).get("entry"));
});

test("long dependency chains do not overflow the JS stack", () => {
  const records = Array.from({ length: 12000 }, (_, index) => ({ key: String(index), digest: "x", dependencies: index ? [String(index - 1)] : [] }));
  assert.equal(dependencyFingerprints(records).size, records.length);
});

test("changed and legacy decisions retain their original conclusion until explicitly reviewed", () => {
  const statuses = { a: { status: "reviewed", reviewFingerprint: "old", updatedAt: "original" }, b: { status: "blocked" } };
  const records = [{ id: "a", reviewFingerprint: "new" }, { id: "b", reviewFingerprint: "new" }];
  const result = reconcileReviewStatuses(statuses, records, { complete: false });
  assert.equal(result.statuses.a.status, "reviewed");
  assert.equal(result.statuses.a.updatedAt, "original");
  assert.equal(result.statuses.a.reviewFingerprint, "old");
  assert.equal(result.statuses.a.needsReview, true);
  assert.match(result.statuses.b.changeReason, /older decision/);
  assert.equal(reconcileReviewStatuses(result.statuses, records).changed, false);
  assert.equal(reconcileReviewStatuses({ a: { status: "reviewed", reviewFingerprint: "new" } }, records).changed, false);
});
