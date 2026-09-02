"use strict";

const DEFAULT_ORPHAN_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

function reconcileReviewStatuses(statuses, items, options = {}) {
  return reconcilePersistedStatuses(statuses, items, options);
}

function reconcileFindingStatuses(statuses, findings, options = {}) {
  return reconcilePersistedStatuses(statuses, findings, options);
}

function reconcilePersistedStatuses(statuses, records, options = {}) {
  const now = options.now instanceof Date ? options.now : new Date(options.now || Date.now());
  const nowIso = now.toISOString();
  const retentionMs = options.retentionMs ?? DEFAULT_ORPHAN_RETENTION_MS;
  const complete = Boolean(options.complete);
  const next = Object.fromEntries(Object.entries(statuses || {}).map(([id, record]) => [id, { ...record }]));
  const activeIds = new Set(records.map(item => item.id));
  let migrated = 0;
  let removed = 0;
  let changed = false;

  for (const item of records) {
    const legacyIds = item.legacyIds || [];
    const legacyId = legacyIds.find(id => next[id]);
    if (!next[item.id] && legacyId) {
      next[item.id] = { ...next[legacyId] };
      migrated += 1;
      changed = true;
    }
    for (const id of legacyIds) {
      if (!next[id]) continue;
      delete next[id];
      changed = true;
    }
    if (next[item.id]?.orphanedAt) {
      const { orphanedAt: _orphanedAt, ...activeRecord } = next[item.id];
      next[item.id] = activeRecord;
      changed = true;
    }
  }

  if (complete) {
    for (const [id, record] of Object.entries(next)) {
      if (activeIds.has(id)) continue;
      if (!record.orphanedAt) {
        next[id] = { ...record, orphanedAt: nowIso };
        changed = true;
        continue;
      }
      const orphanedAt = Date.parse(record.orphanedAt);
      if (Number.isFinite(orphanedAt) && now.getTime() - orphanedAt >= retentionMs) {
        delete next[id];
        removed += 1;
        changed = true;
      }
    }
  }

  return { statuses: next, migrated, removed, changed };
}

module.exports = { DEFAULT_ORPHAN_RETENTION_MS, reconcileFindingStatuses, reconcilePersistedStatuses, reconcileReviewStatuses };
