"use strict";

const path = require("node:path");
const { normalizePath } = require("../identity");
const { languageForPath } = require("../language-support");

const EXCLUDED_DIRECTORIES = new Set([".git", ".svn", "node_modules", "vendor", "target", "build", "dist", "coverage", ".gradle", ".mvn", ".venv", "venv", "__pycache__", "bin", "obj", "storage", "cache", "tmp", "temp"]);
const EXCLUDE_GLOB = `**/{${[...EXCLUDED_DIRECTORIES].join(",")}}/**`;

function isDefaultExcluded(relativePath) {
  return String(relativePath).replaceAll("\\", "/").split("/").slice(0, -1).some(part => EXCLUDED_DIRECTORIES.has(part));
}

function isProjectMetadata(uri) {
  return [".traceguard.json", "composer.json"].includes(path.basename(uri.fsPath));
}

function isRelevantDiskChange(workspace, session, uri, kind) {
  const folder = workspace.getWorkspaceFolder(uri);
  if (!workspace.isTrusted || !folder) return false;
  if (isDefaultExcluded(path.relative(folder.uri.fsPath, uri.fsPath))) return false;
  if (isProjectMetadata(uri)) return true;
  if (languageForPath(uri.fsPath)) return !session._isExcludedUri(uri);
  const prefix = `${normalizePath(uri.fsPath)}/`;
  return kind === "delete" && session.analyses.some(item => normalizePath(item.absolutePath).startsWith(prefix));
}

async function synchronizeWorkspaceChanges(workspace, session, batch) {
  if (!workspace.isTrusted) return;
  if (session.indexPromise) await session.indexPromise;
  if (!workspace.isTrusted || session.disposed) return;
  const metadata = batch.changes.some(change => isProjectMetadata(change.uri));
  if (metadata || batch.rescan) {
    await session.reloadProjectConfiguration({ rebuild: false, silent: true });
    await session.reloadProjectIdentities({ silent: true });
  }
  const additions = batch.changes.filter(change => languageForPath(change.uri.fsPath) &&
    change.kind !== "delete" && !session.analysisForUri(change.uri)).length;
  const limit = workspace.getConfiguration("traceguard").get("maxWorkspaceFiles", 1000);
  if (batch.rescan || metadata || batch.changes.length > 32 || session.analyses.length + additions > limit) {
    await session.indexWorkspace();
    if (session.indexStage.phase !== "ready") throw new Error("Filesystem synchronization did not complete; refresh the review index.");
    return;
  }
  for (const { uri } of batch.changes) {
    if (session.disposed || !workspace.isTrusted) return;
    if (!workspace.getWorkspaceFolder(uri)) continue;
    const key = normalizePath(uri.fsPath);
    // Unsaved editor text wins even if a git checkout replaced/deleted the disk file.
    const dirty = (workspace.textDocuments || []).find(document => document.isDirty && normalizePath(document.uri.fsPath) === key);
    if (dirty && languageForPath(uri.fsPath)) {
      await session.reindexDocument(dirty, { throwOnError: true });
      continue;
    }
    try { await workspace.fs.stat(uri); }
    catch (error) {
      if (!["ENOENT", "FileNotFound"].includes(error?.code) && !/not.?found/i.test(error?.name || "")) throw error;
      const removed = session.analyses.filter(item => normalizePath(item.absolutePath) === key || normalizePath(item.absolutePath).startsWith(`${key}/`));
      await session.removeFiles(removed.map(item => ({ fsPath: item.absolutePath })));
      continue;
    }
    if (languageForPath(uri.fsPath)) await session.reindexFile(uri, { throwOnError: true });
  }
}

module.exports = { EXCLUDE_GLOB, isDefaultExcluded, isRelevantDiskChange, synchronizeWorkspaceChanges };
