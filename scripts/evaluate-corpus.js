"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
const { WorkspaceAnalysisEngine } = require("../src/analysis/workspace-engine");
const { languageForPath } = require("../src/language-support");
const { parseComposerConfigurationText } = require("../src/config/project-identity");

const corpusRoot = path.resolve(process.argv.find(argument => argument.startsWith("--corpus="))?.split("=")[1] || "eval-corpus");
const baselinePath = process.argv.find(argument => argument.startsWith("--baseline="))?.split("=")[1];

async function main() {
  const manifest = JSON.parse(await fs.readFile(path.join(corpusRoot, "manifest.json"), "utf8"));
  if (manifest.schema !== "traceguard-eval-corpus" || manifest.version !== 1) throw new Error("Unsupported TraceGuard evaluation manifest.");
  const cases = [];
  for (const specification of manifest.cases || []) cases.push(await evaluateCase(specification));
  const report = {
    schema: "traceguard-eval-report",
    version: 1,
    generatedAt: new Date().toISOString(),
    summary: summarize(cases),
    cases,
  };
  if (baselinePath) report.comparison = compareBaseline(JSON.parse(await fs.readFile(path.resolve(baselinePath), "utf8")), report);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  const failed = cases.some(item => item.detected < item.expected || item.falsePositives > item.falsePositiveMax || item.unexpectedHeuristicPaths > 0);
  if (report.comparison?.regressions?.length || failed) process.exitCode = 1;
}

async function evaluateCase(specification) {
  const projectRoot = path.resolve(corpusRoot, specification.projectDir);
  const sourcePaths = (await walk(projectRoot)).filter(fileName => languageForPath(fileName));
  const files = await Promise.all(sourcePaths.map(async absolutePath => ({
    absolutePath,
    relativePath: path.relative(projectRoot, absolutePath).replaceAll("\\", "/"),
    language: languageForPath(absolutePath),
    text: await fs.readFile(absolutePath, "utf8"),
    version: (await fs.stat(absolutePath)).mtimeMs.toString(),
  })));
  const composerPath = path.join(projectRoot, "composer.json");
  const identities = [];
  try {
    const parsed = parseComposerConfigurationText(await fs.readFile(composerPath, "utf8"), projectRoot, composerPath);
    if (parsed.valid) identities.push({ root: projectRoot, identity: parsed.identity });
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const engine = new WorkspaceAnalysisEngine();
  const result = await engine.initializeWorkspace(files, {
    projectIdentitiesByRoot: identities,
    maxDepth: 8,
    maxPaths: 400,
  });
  const findings = result.findingDelta.upsert;
  const matchedIds = new Set();
  let detected = 0;
  let unexpectedHeuristicPaths = 0;
  for (const expected of specification.expected || []) {
    const finding = findings.find(candidate => !matchedIds.has(candidate.id) && matchesExpected(candidate, expected));
    if (!finding) continue;
    matchedIds.add(finding.id);
    detected += 1;
    if (!expected.allowHeuristic && finding.confidence === "low") unexpectedHeuristicPaths += 1;
  }
  const relevant = findings.filter(finding => (specification.expected || []).some(expected => expected.ruleId === finding.ruleId));
  const paths = relevant.flatMap(finding => finding.paths || [finding.path]).filter(Boolean);
  const pathStatuses = paths.map(evaluationPathStatus);
  return {
    id: specification.id,
    language: specification.language,
    repository: specification.repository,
    commit: specification.commit,
    vulnerability: specification.vulnerability,
    expected: (specification.expected || []).length,
    detected,
    falsePositives: relevant.filter(finding => !matchedIds.has(finding.id)).length,
    falsePositiveMax: specification.falsePositiveMax || 0,
    verifiedPaths: pathStatuses.filter(status => status === "verified").length,
    heuristicPaths: pathStatuses.filter(status => status === "heuristic").length,
    unresolvedPaths: pathStatuses.filter(status => status === "unresolved").length,
    unexpectedHeuristicPaths,
    findings: relevant.map(finding => ({ id: finding.id, ruleId: finding.ruleId, relativePath: finding.relativePath, line: finding.line, confidence: finding.confidence })),
  };
}

function evaluationPathStatus(flow) {
  if (flow.sink?.semanticVerification === "candidate" || /unverified/.test(flow.sink?.candidateStatus || "")) return "unresolved";
  if (flow.sink?.semanticVerification === "syntax" || flow.confidence === "review" ||
    (flow.steps || []).some(step => step.kind === "call" && step.candidateMatch && step.candidateMatch !== "high")) return "heuristic";
  return "verified";
}

function matchesExpected(finding, expected) {
  if (finding.ruleId !== expected.ruleId || finding.relativePath !== expected.relativePath) return false;
  if (expected.sinkLine && finding.line !== expected.sinkLine) return false;
  const functions = new Set((finding.path?.steps || []).map(step => step.functionName));
  return (expected.requiredFunctions || []).every(name => functions.has(name));
}

function summarize(cases) {
  return cases.reduce((summary, item) => ({
    expected: summary.expected + item.expected,
    detected: summary.detected + item.detected,
    falsePositives: summary.falsePositives + item.falsePositives,
    verifiedPaths: summary.verifiedPaths + item.verifiedPaths,
    heuristicPaths: summary.heuristicPaths + item.heuristicPaths,
    unresolvedPaths: summary.unresolvedPaths + item.unresolvedPaths,
  }), { expected: 0, detected: 0, falsePositives: 0, verifiedPaths: 0, heuristicPaths: 0, unresolvedPaths: 0 });
}

function compareBaseline(baseline, current) {
  const previous = new Map((baseline.cases || []).map(item => [item.id, item]));
  const regressions = [];
  for (const item of current.cases) {
    const before = previous.get(item.id);
    if (!before) continue;
    if (item.detected < before.detected) regressions.push(`${item.id}: detected ${before.detected} -> ${item.detected}`);
    if (item.falsePositives > before.falsePositives) regressions.push(`${item.id}: false positives ${before.falsePositives} -> ${item.falsePositives}`);
    if (item.verifiedPaths < before.verifiedPaths && item.heuristicPaths > before.heuristicPaths) regressions.push(`${item.id}: verified paths degraded to heuristic`);
  }
  return { regressions };
}

async function walk(directory) {
  const output = [];
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(absolutePath));
    else if (entry.isFile()) output.push(absolutePath);
  }
  return output;
}

main().catch(error => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
