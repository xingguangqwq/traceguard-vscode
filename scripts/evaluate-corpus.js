"use strict";

const fs = require("node:fs/promises");
const path = require("node:path");
const { WorkspaceAnalysisEngine } = require("../src/analysis/workspace-engine");
const { languageForPath } = require("../src/language-support");
const { parseComposerConfigurationText } = require("../src/config/project-identity");
const { pathVerificationStatus } = require("../src/review/finding-pool");

const corpusRoot = path.resolve(process.argv.find(argument => argument.startsWith("--corpus="))?.split("=")[1] || "eval-corpus");
const baselinePath = process.argv.find(argument => argument.startsWith("--baseline="))?.split("=")[1];

async function main() {
  const manifest = JSON.parse(await fs.readFile(path.join(corpusRoot, "manifest.json"), "utf8"));
  validateManifest(manifest);
  const cases = [];
  for (const specification of manifest.cases || []) cases.push(await evaluateCase(specification));
  const report = {
    schema: "traceguard-eval-report",
    version: 1,
    generatedAt: new Date().toISOString(),
    summary: summarize(cases),
    byLanguage: groupSummary(cases, "language"),
    byRule: groupSummary(cases, "ruleFamily"),
    cases,
  };
  if (baselinePath) report.comparison = compareBaseline(JSON.parse(await fs.readFile(path.resolve(baselinePath), "utf8")), report);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  const failed = cases.some(item => item.detected < item.expected || item.falsePositives > item.falsePositiveMax || item.unexpectedHeuristicPaths > 0);
  if (report.comparison?.regressions?.length || failed) process.exitCode = 1;
}

async function evaluateCase(specification, root = corpusRoot) {
  const projectRoot = path.resolve(root, specification.projectDir);
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
  return scoreFindings(specification, findings);
}

function scoreFindings(specification, findings) {
  const checkedRules = specification.checkedRules ? new Set(specification.checkedRules) : undefined;
  const relevant = findings.filter(finding => !checkedRules || checkedRules.has(finding.ruleId));
  const matchedIds = new Set();
  let detected = 0;
  let unexpectedHeuristicPaths = 0;
  for (const expected of specification.expected || []) {
    const finding = relevant.find(candidate => !matchedIds.has(candidate.id) && matchesExpected(candidate, expected));
    if (!finding) continue;
    matchedIds.add(finding.id);
    detected += 1;
    const acceptedProof = expected.allowedProofStatuses || (expected.allowHeuristic ? ["verified", "heuristic", "unresolved"] : ["verified"]);
    if (!findingPaths(finding).some(flow => matchesFunctions(flow, expected) && acceptedProof.includes(evaluationPathStatus(flow)))) unexpectedHeuristicPaths += 1;
  }
  const paths = relevant.flatMap(findingPaths);
  const pathStatuses = paths.map(evaluationPathStatus);
  return {
    id: specification.id,
    language: specification.language,
    ruleFamily: specification.ruleFamily || specification.expected?.[0]?.ruleId || "unspecified-negative",
    scenario: specification.scenario,
    proofLimitation: specification.proofLimitation,
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
  const status = pathVerificationStatus(flow);
  return status === "syntax-only" ? "heuristic" : status;
}

function matchesExpected(finding, expected) {
  if (finding.ruleId !== expected.ruleId || finding.relativePath !== expected.relativePath) return false;
  if (expected.sinkLine && finding.line !== expected.sinkLine) return false;
  return !expected.requiredFunctions?.length || findingPaths(finding).some(flow => matchesFunctions(flow, expected));
}

function findingPaths(finding) {
  return (finding.paths?.length ? finding.paths : [finding.path]).filter(Boolean);
}

function matchesFunctions(flow, expected) {
  const functions = new Set((flow.steps || []).map(step => step.functionName));
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

function groupSummary(cases, property) {
  const groups = new Map();
  for (const item of cases) {
    const key = item[property] || "unspecified";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  return Object.fromEntries([...groups].sort(([a], [b]) => a.localeCompare(b)).map(([key, values]) => {
    const summary = summarize(values);
    return [key, { cases: values.length, ...summary,
      precision: summary.detected + summary.falsePositives ? summary.detected / (summary.detected + summary.falsePositives) : null,
      recall: summary.expected ? summary.detected / summary.expected : null,
      proofFailures: values.reduce((total, item) => total + item.unexpectedHeuristicPaths, 0) }];
  }));
}

function compareBaseline(baseline, current) {
  const previous = new Map((baseline.cases || []).map(item => [item.id, item]));
  const regressions = [];
  const currentIds = new Set(current.cases.map(item => item.id));
  for (const id of previous.keys()) if (!currentIds.has(id)) regressions.push(`${id}: missing baseline case`);
  for (const item of current.cases) {
    const before = previous.get(item.id);
    if (!before) continue;
    if (item.detected < before.detected) regressions.push(`${item.id}: detected ${before.detected} -> ${item.detected}`);
    if (item.falsePositives > before.falsePositives) regressions.push(`${item.id}: false positives ${before.falsePositives} -> ${item.falsePositives}`);
    if (item.verifiedPaths < before.verifiedPaths) regressions.push(`${item.id}: verified paths ${before.verifiedPaths} -> ${item.verifiedPaths}`);
    if (Number.isFinite(before.expected) && item.expected < before.expected) regressions.push(`${item.id}: expected findings removed`);
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

function validateManifest(manifest) {
  if (manifest.schema !== "traceguard-eval-corpus" || manifest.version !== 1) throw new Error("Unsupported TraceGuard evaluation manifest.");
  if (!Array.isArray(manifest.cases) || !manifest.cases.length) throw new Error("Evaluation corpus must not be empty.");
  const ids = new Set();
  for (const item of manifest.cases) {
    if (!item || typeof item.id !== "string" || !item.id || typeof item.projectDir !== "string" || !Array.isArray(item.expected)) throw new Error("Invalid evaluation case.");
    if (ids.has(item.id)) throw new Error(`Duplicate evaluation case: ${item.id}`);
    ids.add(item.id);
    if (item.checkedRules !== undefined && (!Array.isArray(item.checkedRules) || !item.checkedRules.length || item.checkedRules.some(rule => typeof rule !== "string" || !rule))) throw new Error(`${item.id}: checkedRules must be a non-empty rule list.`);
    for (const expected of item.expected) {
      if (expected?.allowedProofStatuses !== undefined && (!Array.isArray(expected.allowedProofStatuses) || !expected.allowedProofStatuses.length ||
        expected.allowedProofStatuses.some(status => !["verified", "heuristic", "unresolved"].includes(status)))) throw new Error(`${item.id}: invalid allowedProofStatuses.`);
      if (expected?.allowedProofStatuses?.some(status => status !== "verified") && !item.proofLimitation) throw new Error(`${item.id}: weaker proof expectations require a documented proofLimitation.`);
      if (!expected || typeof expected.ruleId !== "string" || typeof expected.relativePath !== "string") throw new Error(`${item.id}: invalid expected finding.`);
      if (item.checkedRules && !item.checkedRules.includes(expected.ruleId)) throw new Error(`${item.id}: expected rule is outside checkedRules.`);
    }
  }
}

if (require.main === module) main().catch(error => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});

module.exports = { evaluateCase, scoreFindings, compareBaseline, validateManifest };
