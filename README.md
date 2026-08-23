# TraceGuard Local SAST

[简体中文](README.zh-CN.md)

TraceGuard is a local, incremental and explainable SAST extension for VS Code. It builds a review queue, follows candidate Source → Sink paths and keeps security decisions beside the code.

It does not report confirmed vulnerabilities. You still read the code and make the decision.

![TraceGuard review queue and editor clues](docs/images/traceguard-code-review.png)

## Start in three minutes

1. Download the VSIX from the [latest release](https://github.com/xingguangqwq/traceguard-vscode/releases/latest). To build 0.7 locally, run `npm run package`.
2. In VS Code, run **Extensions: Install from VSIX** and select the downloaded file.
3. Open a trusted source-code folder.
4. Click the TraceGuard code-trace icon in the Activity Bar.
5. Choose **Build Review Queue**, then open the first P0 or P1 item.

You can also install from PowerShell:

```powershell
code --install-extension .\traceguard-vscode-0.7.3.vsix
```

## What should I read first?

The queue is only an ordering aid:

- **P0 — Review first:** the strongest combinations of entry points, external input and sensitive operations.
- **P1 — High attention:** code with useful security clues that should be checked early.
- **P2 — Review queue:** the remaining functions worth reading.

Open a target and follow this order:

1. Find the entry point: route, controller, handler, command or file-level execution.
2. Identify data controlled by a user or another system.
3. Trace the variable through assignments and conditions.
4. Find where it reaches a database, command, file, network request or deserializer.
5. Check validation, encoding, authentication and authorization on the path.
6. Record what you verified, then mark the target reviewed.

## A small example

```php
function read_file() {
    $name = $_GET['name'];
    return file_get_contents('/uploads/' . $name);
}
```

A first review does not need a complicated rule set. Ask:

- Is `$_GET['name']` externally controlled?
- Does it reach a file operation?
- Is the resulting path normalized and restricted to the intended directory?
- Can `../` or an absolute path change which file is read?

TraceGuard can point out the input and file operation. Deciding whether the complete code is exploitable still requires reading the surrounding logic.

## Useful actions while reading

- **Trace Backward** explains where the selected variable or property path came from.
- **Trace Forward** explains assignments, calls, returns and sensitive operations reached by the selected value.
- **Find Callers / Find Callees** queries the project call graph around the current function.
- **Trace to Entry Point** walks backward to HTTP, CLI or framework entry points.
- **Show Reachable Sinks** lists dangerous operations reachable from the current function.
- **Explain Analysis Here** shows frontend capability, semantic facts and the reason unresolved edges stopped.
- **Show Security Clues Here** lists the clues found in the current function.
- **Add Selection to Audit Notes** saves a relevant code fragment with your reason.
- **Mark Current Target Reviewed** keeps the queue moving.
- **Export Audit Notes** creates a Markdown record of the review.
- **Export Findings as SARIF** writes fingerprints and complete Source → Sink code flows for CI and security platforms.
- **Copy Analysis Path as Markdown / Export Analysis Debug JSON** makes a query reviewable outside the sidebar without hiding heuristic steps.

Finding decisions are stored separately from review coverage. A candidate can be marked reviewed, false positive, accepted risk or suppressed without losing its stable sink identity.

## Why a path is connected

TraceGuard 0.7.3 tracks canonical Access Paths such as `request.body.command`, `options.url` and `items[0]` instead of treating an entire object as one tainted value. Alias assignments rebase descendant fields, exact overwrites kill stale taint, and typed `Map`/array operations describe which element was read or written. Unrelated sibling fields therefore do not become tainted merely because they share an object.

Closures carry captured outer symbols through explicit call edges. TypeScript receiver types distinguish same-named class methods, while interface dispatch stays a bounded candidate set and is marked for review when more than one implementation remains possible.

Every displayed propagation edge records its proof and one of four statuses: `verified`, `syntax-only`, `heuristic` or `unresolved`. A heuristic connection lowers confidence; an unresolved edge is shown as a stopping reason rather than presented as a certain Source → Sink path.

For a cross-file trace, click the action above an indexed function, choose a possible path, then choose any step to open that exact line. `No control seen` means the path has no recognized validation or authorization clue; `Check call target` means a same-named call still needs manual confirmation.

Large projects can adjust `traceguard.flowMaxDepth`, `traceguard.flowMaxPaths`, `traceguard.queryMaxNodes`, `traceguard.maxWorkspaceFiles` and `traceguard.showFlowCodeLens` in VS Code settings. Query results are labeled as truncated when the node limit is reached. Full-workspace indexing starts explicitly from the sidebar by default; enable `traceguard.indexOnStartup` only if the startup cost is acceptable. Unsaved live indexing is also opt-in through `traceguard.liveIndex`; saved files still refresh automatically.

## Project audit semantics

Run **TraceGuard: Open Project Audit Configuration** to create `.traceguard.json`. The file can describe project-specific Sources, Sinks, Sanitizers/Guards, Propagators/Wrappers, rule controls and excluded paths:

```json
{
  "version": 1,
  "sources": [
    { "language": "typescript", "module": "./request", "function": "getUserInput" }
  ],
  "sinks": [
    { "language": "typescript", "module": "./process", "function": "internalExec", "arguments": [0], "kind": "COMMAND_EXEC" }
  ],
  "sanitizers": [
    { "language": "typescript", "module": "./security", "function": "escapeCommand", "arguments": [0], "capability": "SHELL_ESCAPE" }
  ],
  "propagators": [
    { "language": "typescript", "function": "wrapValue", "arguments": [0], "returnsTaint": true }
  ],
  "rules": {
    "potential-open-redirect": false,
    "potential-command-injection": { "severity": "high" }
  },
  "excludePaths": ["generated/**", "**/*.fixture.ts"]
}
```

Prefer `module`, `qualifiedName` or `receiverType` for security-relevant models. A bare function name is intentionally `syntax-only`: it can help discovery, but it cannot become a high-confidence sanitizer or silently suppress a Finding. Invalid edits are shown in Problems and TraceGuard keeps the last valid configuration active.

## Supported languages

- **Tier A — Java / PHP / Python:** the sustained backend-audit focus. Java 0.8 adds AST-native Spring/JAX-RS/Servlet entries, DTO Access Paths, interface-to-implementation dispatch, overload selection, MyBatis/JDBC/JPA and Spring HTTP semantics. PHP and Python keep their AST/dataflow support and are the next languages to receive the same project-level depth.
- **Tier B — JavaScript / TypeScript / JSX / TSX:** retains the existing Tree-sitter and persistent project-level TypeScript Program, import/type resolution, CFG/def-use, framework binding and cross-function flow. New work is regression-driven rather than feature expansion.
- **Tier C — C# / Go:** remains usable for AST functions/callbacks, framework entries, assignments, calls, parameters and returns, with explicit confidence degradation. This tier receives correctness fixes but no active semantic expansion.

Pattern matching remains a fallback for parser failures and a framework/security semantic classifier. Generated code, reflection, dynamic dispatch and project-specific wrappers may still need manual discovery. The sidebar reports AST coverage, parser recovery and skipped files instead of presenting partial analysis as complete.

## Privacy and limits

- Source code is not uploaded.
- The extension does not execute the project being reviewed.
- It has no Python or web-service dependency.
- A highlighted line is a review clue, not proof of a vulnerability.
- A clean queue is not proof that a project is secure.
- Files larger than 2 MB are skipped. Full indexing defaults to 1,000 supported files and can be raised to 8,000 after checking memory on the target project. TraceGuard marks the map as partial whenever either limit affects coverage and never orphans review state from an incomplete scan.
- When Source-to-Sink candidates exceed the configured display limit, TraceGuard keeps higher-impact paths first and labels the result as a prioritized subset.

Review-session JSON may contain snippets that you saved in audit notes. Check the file before sharing or committing it.

## Development

The analysis pipeline has one boundary between language-specific source parsing and shared analysis:

```text
source → language frontend → traceguard-ir → dataflow engine → rules / review projection
```

Language syntax and operation extraction live under `src/frontends/`. Seven Tree-sitter WASM grammars feed the same versioned IR, while JavaScript/TypeScript share an incrementally rebuilt TypeScript Program inside the analysis worker. Pattern parsing is retained only as a degraded fallback and differential checker. Shared CFG, call resolution, propagation facts, summaries, Access Paths and path/query traversal live under `src/dataflow/`; incremental dataflow and rule evaluation run in a persistent worker thread. The CFG models condition evaluation, branch joins, loop back-edges, break/continue, structured exception edges, throw and early-return reachability.

Review targets and findings use symbol- and sink-centered IDs rather than line numbers. `src/analysis/incremental-cache.js` and `src/dataflow/function-summary.js` drive dependency-scoped invalidation. The five core rule families are command injection, SQL injection, path traversal, SSRF and unsafe deserialization; each rule evaluates its own sanitizer/guard capabilities.

```powershell
npm install
npm test
npm run check
npm run benchmark -- --files=1000 --max-rss-mib=512
npm run benchmark -- --fixture=typescript-dependents --files=100 --max-incremental-ms=500 --max-rss-mib=512
npm run test:extension-host
npm run package
npm run verify:package
```

CI also runs `npm run test:extension-host` against the minimum supported VS Code release. Open the extension folder in VS Code and press `F5` for interactive Extension Development Host testing.

[Report a bug](https://github.com/xingguangqwq/traceguard-vscode/issues) · [Contributing](CONTRIBUTING.md) · MIT License
