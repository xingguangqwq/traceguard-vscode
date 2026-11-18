"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { execFileSync } = require("node:child_process");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");
const { pathVerificationStatus } = require("../src/review/finding-pool");

function parseExpectedResults(text) {
  const seen = new Set();
  return text.split(/\r?\n/).filter(line => line.trim() && !line.startsWith("#")).map((line, index) => {
    const cells = line.split(",").map(cell => cell.trim());
    const [name, category, truth, cwe] = cells;
    if (cells.length !== 4 || !/^BenchmarkTest\d{5}$/.test(name) || !/^[a-z]+$/.test(category) || !["true", "false"].includes(truth) || !/^\d+$/.test(cwe)) {
      throw new Error(`Invalid expected-results row ${index + 1}`);
    }
    if (seen.has(name)) throw new Error(`Duplicate test case: ${name}`);
    seen.add(name);
    return { name, category, vulnerable: truth === "true", cwe: `CWE-${cwe}` };
  });
}

function metrics(cases, field = "detected") {
  let tp = 0, fn = 0, fp = 0, tn = 0, errors = 0;
  for (const item of cases) {
    // Failed analyses never count as true negatives or ordinary misses.
    if (item.error) { errors++; continue; }
    if (item.vulnerable) { if (item[field]) tp++; else fn++; }
    else if (item[field]) fp++; else tn++;
  }
  const divide = (a, b) => b ? a / b : null;
  const recall = divide(tp, tp + fn), fpr = divide(fp, fp + tn);
  return { tp, fn, fp, tn, errors, precision: divide(tp, tp + fp), recall, fpr, youden: recall === null || fpr === null ? null : recall - fpr };
}

function summarize(cases) {
  return {
    cases: cases.length,
    allFindings: metrics(cases),
    verifiedOnly: metrics(cases, "verified"),
    truncated: cases.filter(item => item.truncated).length,
    byCategory: Object.fromEntries([...new Set(cases.map(item => item.category))].sort().map(category => {
      const selected = cases.filter(item => item.category === category);
      return [category, { cases: selected.length, allFindings: metrics(selected), verifiedOnly: metrics(selected, "verified") }];
    })),
  };
}

function compareBaseline(baseline, report) {
  if (baseline.schema !== "traceguard-owasp-report" || report.schema !== baseline.schema || baseline.version !== report.version || !baseline.complete || !report.complete) {
    throw new Error("Only complete compatible OWASP reports can be compared.");
  }
  if (["commit", "expectedResultsSha256", "sourceSha256"].some(key => baseline.dataset[key] !== report.dataset[key])) {
    throw new Error("OWASP dataset identity differs from the baseline.");
  }
  if (JSON.stringify(baseline.options) !== JSON.stringify(report.options)) throw new Error("OWASP analysis budgets differ from the baseline.");
  const previous = new Map(baseline.cases.map(item => [item.name, item]));
  if (previous.size !== report.cases.length || new Set(report.cases.map(item => item.name)).size !== previous.size) throw new Error("OWASP case coverage differs from the baseline.");
  const regressions = [];
  for (const current of report.cases) {
    const old = previous.get(current.name);
    if (!old || old.vulnerable !== current.vulnerable || old.cwe !== current.cwe || old.sourceSha256 !== current.sourceSha256 || old.category !== current.category) throw new Error(`OWASP case identity differs: ${current.name}`);
    for (const field of ["detected", "verified"]) {
      if (current.vulnerable && old[field] && !current[field]) regressions.push(`${current.name}: lost ${field} true positive`);
      if (!current.vulnerable && !old[field] && current[field]) regressions.push(`${current.name}: new ${field} false positive`);
    }
    if (!old.truncated && current.truncated) regressions.push(`${current.name}: newly truncated analysis`);
  }
  return { regressions };
}

const hash = value => createHash("sha256").update(value).digest("hex");

async function evaluate(root, config) {
  const commit = execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8", windowsHide: true }).trim();
  if (commit !== config.commit) throw new Error(`Expected BenchmarkJava commit ${config.commit}; found ${commit}`);
  const csv = fs.readFileSync(path.join(root, config.expectedResults), "utf8").replace(/\r\n/g, "\n");
  if (hash(csv) !== config.expectedResultsSha256) throw new Error("Expected-results CSV hash differs from the pinned dataset.");
  const rows = parseExpectedResults(csv);
  const supported = rows.filter(row => config.categories[row.category]);
  const sourceRoot = path.join(root, "src/main/java/org/owasp/benchmark/testcode");
  const tree = createHash("sha256");
  const inputs = supported.map(row => {
    if (config.categories[row.category] !== row.cwe) throw new Error(`CWE mismatch for ${row.name}`);
    const filename = path.join(sourceRoot, `${row.name}.java`);
    const text = fs.readFileSync(filename, "utf8").replace(/\r\n/g, "\n");
    tree.update(`${row.name}\0${text}\0`);
    return { row, filename, text };
  });
  const sourceSha256 = tree.digest("hex");
  if (sourceSha256 !== config.sourceSha256 || inputs.length !== config.cases) throw new Error("Pinned source contents or case count differ from the dataset manifest.");
  const cases = [];
  for (const { row, filename, text } of inputs) {
    const item = { ...row, sourceSha256: hash(text), detected: false, verified: false, truncated: false };
    try {
      const analysis = await analyzeTextAsync(text, "java", filename, `${row.name}.java`, {});
      if (analysis.ir?.frontend?.mode !== "ast") throw new Error("Java AST frontend is unavailable or degraded.");
      const result = runDataflowAnalysis([analysis], config.options);
      const relevant = result.findings.filter(finding => finding.cwe === row.cwe);
      item.detected = relevant.length > 0;
      item.verified = relevant.some(finding => (finding.paths || [finding.path]).some(flow => pathVerificationStatus(flow) === "verified"));
      item.truncated = Boolean(result.metadata.explorationTruncated);
      item.truncationReasons = result.metadata.truncationReasons;
    } catch (error) {
      item.error = String(error.message).split(/\r?\n/)[0].slice(0, 300);
    }
    cases.push(item);
    if (cases.length % 250 === 0) process.stderr.write(`OWASP: ${cases.length}/${inputs.length}\n`);
  }
  const skipped = rows.filter(row => !config.categories[row.category]);
  return {
    schema: "traceguard-owasp-report", version: 1, generatedAt: new Date().toISOString(),
    extensionVersion: require("../package.json").version,
    complete: cases.length === supported.length && !cases.some(item => item.error),
    scope: "Per-test-file static analysis. Project helper bodies are not indexed. Findings are review candidates; verifiedOnly is reported separately. Unsupported categories are excluded explicitly.",
    dataset: { repository: config.repository, commit, expectedResultsSha256: hash(csv), sourceSha256, totalCases: rows.length,
      skippedByCategory: Object.fromEntries([...new Set(skipped.map(row => row.category))].sort().map(category => [category, skipped.filter(row => row.category === category).length])) },
    options: config.options, summary: summarize(cases), cases,
  };
}

async function main(args) {
  const allowed = ["root", "output", "baseline"];
  if (args.some(arg => !allowed.some(name => arg.startsWith(`--${name}=`)))) throw new Error("Usage: npm run eval:owasp -- --root=<BenchmarkJava> [--output=<report.json>] [--baseline=<report.json>]");
  const option = name => args.find(arg => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
  const config = require("../eval-corpus/owasp-java.config.json");
  const report = await evaluate(path.resolve(option("root") || ".target-labs/benchmark-java"), config);
  if (option("baseline")) {
    try { report.comparison = compareBaseline(JSON.parse(fs.readFileSync(path.resolve(option("baseline")), "utf8")), report); }
    catch (error) { report.comparison = { regressions: [`Comparison failed: ${error.message}`] }; }
  }
  const output = path.resolve(option("output") || "eval-corpus/owasp-latest-report.json");
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n");
  process.stdout.write(JSON.stringify({ complete: report.complete, summary: report.summary, comparison: report.comparison, output }, null, 2) + "\n");
  if (!report.complete || report.comparison?.regressions.length) process.exitCode = 1;
}

if (require.main === module) main(process.argv.slice(2)).catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
module.exports = { compareBaseline, evaluate, metrics, parseExpectedResults, summarize };
