"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { reconcileReviewStatuses } = require("../src/review/status-store");

test("review statuses migrate to stable IDs and orphan cleanup waits for a complete index", () => {
  const now = new Date("2026-08-21T00:00:00.000Z");
  const item = { id: "stable", legacyIds: ["legacy"] };
  const initial = {
    legacy: { status: "reviewed", updatedAt: "2026-08-01T00:00:00.000Z" },
    missing: { status: "blocked", updatedAt: "2026-01-01T00:00:00.000Z" },
  };

  const partial = reconcileReviewStatuses(initial, [item], { complete: false, now });
  assert.equal(partial.statuses.stable.status, "reviewed");
  assert.equal(partial.statuses.legacy, undefined);
  assert.equal(partial.statuses.missing.orphanedAt, undefined);

  const complete = reconcileReviewStatuses(partial.statuses, [item], { complete: true, now });
  assert.equal(complete.statuses.missing.orphanedAt, now.toISOString());

  const expired = reconcileReviewStatuses(complete.statuses, [item], {
    complete: true,
    now: new Date("2026-09-21T00:00:00.000Z"),
  });
  assert.equal(expired.statuses.missing, undefined);
  assert.equal(expired.removed, 1);
});
