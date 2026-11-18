"use strict";

const { markdownFence } = require("../markdown");

function buildReport(audit) {
  const lines = [
    "# TraceGuard Code Audit Report", "",
    `Generated: ${new Date().toISOString()}`, "",
    "## Manual review coverage", "",
    `- Manual review coverage: **${audit.statusCounts.reviewed} / ${audit.items.length}** targets`,
    `- Indexed: ${audit.files} files, ${audit.functions} functions, ${audit.lines} lines${audit.indexIncomplete ? ` (**partial index**${audit.indexScope === "current-files" ? "; workspace-wide indexing has not run" : ""}${audit.indexSkippedFiles ? `; ${audit.indexSkippedFiles} files skipped` : ""})` : ""}`,
    `- Attack surface: ${audit.entries.length} entry points`,
    `- Data-flow review items: ${audit.findings.length}${audit.findingPathsTruncated ? ` (prioritized subset of at least ${audit.findingPathCandidates} candidate paths)` : ""}`,
    `- Evidence records: ${audit.evidence.length}`, "",
    "## Parser and index coverage", "",
    ...Object.entries(audit.languageCapabilities || {}).map(([language, capability]) =>
      `- ${language}: ${capability.astFiles}/${capability.files} files parsed with AST${capability.degradedFiles ? `; ${capability.degradedFiles} degraded` : ""}`,
    ),
    ...(audit.indexSkippedDetails?.length ? ["", "Skipped files:", ...audit.indexSkippedDetails.map(item => `- \`${item.relativePath}\` — ${item.reason}`)] : []), "",
    "## Attack surface", "",
    ...audit.entries.map(entry => `- \`${entry.title}\` — ${entry.relativePath}:${entry.line}`), "",
    "## Verified flows and review hypotheses", "",
    ...audit.findings.flatMap(finding => [
      `### ${finding.title} (${finding.cwe})`, "",
      `- Severity/confidence: **${finding.severity.toUpperCase()} / ${finding.confidence}**`,
      `- Status: **${finding.status || "open"}**`,
      `- Sink: \`${finding.relativePath}:${finding.line}\``,
      `- Observed guards: ${(finding.observedGuards || []).join(", ") || "none"}`,
      `- Missing guards: ${(finding.missingGuards || []).join(", ") || "none"}`,
      `- Confidence reason: ${finding.explanation?.confidenceReason || "Direct local flow or resolved calls"}`, "",
      "Source → Sink path:",
      ...(finding.path?.steps || []).map((step, index) => `${index + 1}. **${step.kind}** · ${step.label} — \`${step.relativePath}:${step.line}\``),
      "",
    ]),
    "## Review targets", "",
  ];
  for (const item of audit.items) {
    lines.push(`### ${item.priority} · ${item.title}`, "", `- Location: \`${item.relativePath}:${item.line}\``, `- Status: **${item.status}**`, `- Review reasons: ${item.reasons.join("; ")}`, "", "Checklist:", ...item.checklist.map(check => `- [${check.state === "observed" ? "x" : " "}] ${check.label} — ${check.evidence}`), "");
  }
  lines.push("## Evidence notebook", "");
  for (const evidence of audit.evidence) {
    const fence = markdownFence(evidence.code);
    lines.push(`### ${evidence.type} · ${evidence.relativePath}:${evidence.line}`, "", evidence.note || "No note", "", fence, evidence.code, fence, "");
  }
  lines.push("---", "TraceGuard audit signals are reviewer aids, not proof that code is secure or vulnerable.", "");
  return lines.join("\n");
}

module.exports = { buildReport };
