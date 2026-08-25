# TraceGuard Local SAST

[简体中文](README.zh-CN.md)

TraceGuard is a local code-audit extension for VS Code. It builds a review queue and shows candidate Source → Sink paths for Java, PHP, Python and other supported languages.

It reports review candidates, not confirmed vulnerabilities.

![TraceGuard review queue and editor clues](docs/images/traceguard-code-review.png)

## Install

1. Download the VSIX from [Releases](https://github.com/xingguangqwq/traceguard-vscode/releases/latest).
2. Run **Extensions: Install from VSIX** in VS Code.
3. Open a trusted source-code folder.

```powershell
code --install-extension .\traceguard-vscode-0.9.0.vsix
```

## Use

1. Click the TraceGuard icon in the Activity Bar.
2. Choose **Build Review Queue** to index the workspace.
3. Start with **Attack Surface** and **Potential Findings**, then review P0, P1 and P2 targets.
4. Use CodeLens or the Command Palette to trace a selected value backward or forward, find callers/callees, trace to an entry point or show reachable sinks.
5. Open a path step to jump to the corresponding code.
6. Mark findings as reviewed, false positive, accepted risk or suppressed.
7. Export audit notes, review sessions or SARIF when needed.

## Understand the results

- **Attack Surface** lists routes, controllers and other externally reachable entries.
- **Potential Findings** groups candidate security paths by rule and sink.
- **Review Targets** orders functions as P0, P1 or P2 for manual reading; these are review priorities, not vulnerability severity.

Expand a Finding to inspect its Source → Sink steps. Each step shows its file, function and proof status:

- `verified`: backed by direct AST, type or module evidence.
- `syntax-only`: structurally matched, but without complete project-level proof.
- `heuristic`: a plausible target remains and needs manual confirmation.
- `unresolved`: analysis stopped because the call or value could not be followed safely.

LOW/REVIEW findings are deliberately retained when a relevant receiver or call target cannot be fully proven. They cannot act as trusted Guards or silently suppress other findings.

## Language focus

- **Java:** Spring MVC, JAX-RS, Servlet, package/import resolution, interfaces, JDBC/JPA/MyBatis and common command or HTTP sinks.
- **PHP:** Laravel, Symfony, Composer PSR-4, PDO, DB/Eloquent raw queries and command execution.
- **Python:** FastAPI, Django, Pydantic fields, DB-API/SQLAlchemy, subprocess and HTTP clients.
- JavaScript/TypeScript remain supported with AST and project-aware analysis. C# and Go keep common AST and framework-entry support at lower depth.

## Project configuration

Run **TraceGuard: Open Project Audit Configuration** to create `.traceguard.json` for project-specific Sources, Sinks, Guards, rule controls and excluded paths.

```json
{
  "version": 1,
  "excludePaths": ["vendor/**", "generated/**"],
  "rules": {
    "potential-command-injection": { "severity": "high" }
  }
}
```

Each workspace root keeps its own configuration and last valid state. Invalid edits appear in Problems without breaking analysis in other roots.

## Settings and limits

- `traceguard.maxWorkspaceFiles`: maximum files in a full index; default 1,000.
- `traceguard.indexTimeoutSeconds`: full-index timeout; default 300 seconds, `0` disables it.
- `traceguard.liveIndex`: include unsaved editor changes.
- `traceguard.indexOnStartup`: build the workspace index on startup.

Source code stays local and the extension does not execute the reviewed project. Files larger than 2 MB are skipped, and partial coverage is shown explicitly. A clean result is not proof that the project is secure.

See [CHANGELOG.md](CHANGELOG.md) for version details.

[Report a bug](https://github.com/xingguangqwq/traceguard-vscode/issues) · MIT License
