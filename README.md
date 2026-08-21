# TraceGuard Code Audit Helper

[简体中文](README.zh-CN.md)

New to security code review? TraceGuard gives you a practical place to start. It builds a reading queue inside VS Code, points out code that deserves attention, and keeps your notes with the review.

It does not report confirmed vulnerabilities. You still read the code and make the decision.

![TraceGuard review queue and editor clues](docs/images/traceguard-code-review.png)

## Start in three minutes

1. Download `traceguard-vscode-0.6.0.vsix` from the [latest release](https://github.com/xingguangqwq/traceguard-vscode/releases/latest).
2. In VS Code, run **Extensions: Install from VSIX** and select the downloaded file.
3. Open a trusted source-code folder.
4. Click the TraceGuard code-trace icon in the Activity Bar.
5. Choose **Build Review Queue**, then open the first P0 or P1 item.

You can also install from PowerShell:

```powershell
code --install-extension .\traceguard-vscode-0.6.0.vsix
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

- **Trace Source → Sink across files** follows selected input through direct project calls and opens every step in the chain.
- **Trace Selected Variable** shows input, assignments, conditions, checks and sensitive uses in source order.
- **Show Security Clues Here** lists the clues found in the current function.
- **Add Selection to Audit Notes** saves a relevant code fragment with your reason.
- **Mark Current Target Reviewed** keeps the queue moving.
- **Export Audit Notes** creates a Markdown record of the review.

For a cross-file trace, click the action above an indexed function, choose a possible path, then choose any step to open that exact line. `No control seen` means the path has no recognized validation or authorization clue; `Check call target` means a same-named call still needs manual confirmation.

Large projects can adjust `traceguard.flowMaxDepth`, `traceguard.flowMaxPaths` and `traceguard.showFlowCodeLens` in VS Code settings. Full-workspace indexing starts explicitly from the sidebar by default; enable `traceguard.indexOnStartup` only if the startup cost is acceptable. Unsaved live indexing is also opt-in through `traceguard.liveIndex`; saved files still refresh automatically.

## Supported languages

- Java and JSP
- PHP
- JavaScript and TypeScript
- Python
- C#
- Go

The analysis is based on source text and common framework patterns. Generated code, dynamic calls and project-specific wrappers may need manual discovery.

## Privacy and limits

- Source code is not uploaded.
- The extension does not execute the project being reviewed.
- It has no Python or web-service dependency.
- A highlighted line is a review clue, not proof of a vulnerability.
- A clean queue is not proof that a project is secure.
- Files larger than 2 MB are skipped, and workspace discovery is capped at 8,000 supported files. TraceGuard marks the audit map as partial when either limit affects coverage.
- When Source-to-Sink candidates exceed the configured display limit, TraceGuard keeps higher-impact paths first and labels the result as a prioritized subset.

Review-session JSON may contain snippets that you saved in audit notes. Check the file before sharing or committing it.

## Development

The analysis pipeline has one boundary between language-specific source parsing and shared analysis:

```text
source → language frontend → traceguard-ir → dataflow engine → rules / review projection
```

Language syntax and operation extraction live under `src/frontends/`. Shared call resolution, IR adaptation and path analysis live under `src/dataflow/`; dataflow and rule evaluation run in a worker thread. `src/audit-analyzer.js` is the compatibility-facing orchestration entry and does not parse source itself.

Review targets and IR functions use line-independent best-effort IDs. `src/analysis/incremental-cache.js` and `src/dataflow/function-summary.js` define the version, summary, dependency and invalidation contract for incremental analysis. The current pattern frontend remains a fallback; a future AST frontend can dual-run and emit the same IR without changing the dataflow or rule layers.

```powershell
npm install
npm test
npm run check
npm run benchmark
npm run package
```

CI also runs `npm run test:extension-host` against the minimum supported VS Code release. Open the extension folder in VS Code and press `F5` for interactive Extension Development Host testing.

[Report a bug](https://github.com/xingguangqwq/traceguard-vscode/issues) · [Contributing](CONTRIBUTING.md) · MIT License
