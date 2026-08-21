# Changelog

## 0.6.0

- Prevented strings and line, block and multiline comments from creating fake sources, sinks, calls or security findings.
- Kept higher-impact Source-to-Sink paths ahead of display limits and now disclose candidate truncation in the sidebar, picker, status and report.
- Made workspace indexing transactional: cancellation keeps the previous map, concurrent refreshes share work, and file or size limits are reported as partial coverage.
- Made full startup indexing and unsaved live indexing opt-in, enforced the 2 MB limit for open documents, and synchronized created, deleted and renamed files.
- Fixed portable evidence paths in multi-root workspaces, bounded review-session imports and protected Markdown evidence fences.
- Added a normalized intermediate representation with explicit security semantics; language parsers now emit structure, signals and IR facts only.
- Made registered language frontends the only source-analysis entry, then split syntax/operation extraction, IR projection, call resolution and shared dataflow path analysis into explicit modules; the former flow analyzer remains only as a compatibility facade.
- Added a declarative rule layer that turns source-sink-guard facts into potential findings, kept separate from P0–P2 reading priorities.
- Moved review-target selection and P0–P2 prioritization into a dedicated review layer so parsers no longer rank code and rules no longer feed the queue.
- Split the sidebar into Attack Surface, Potential Findings and Review Targets so entry points, rule matches and reading order stay distinct.
- Added clickable cross-file Source to Sink traces for indexed audit targets and selected variables.
- Added import-, receiver- and file-aware call matching to reduce same-named function mix-ups.
- Added validation and authorization markers, match confidence and uncontrolled-path ordering.
- Added configurable trace depth, result limits and CodeLens visibility.
- Fixed the release workflow uploading a stale hardcoded VSIX name; packaging, CI and the release job now derive the artifact name from the package version.
- Fixed entry-parameter tracing that treated framework response objects such as `res`, `response` and `w` as untrusted input and reported constant redirects or response bodies as findings.
- Fixed inline JavaScript and TypeScript route callbacks, the dominant handler style, being invisible to function indexing, review targets and cross-file traces.
- Moved shared dataflow and rule evaluation to a reusable worker thread so heavier path exploration no longer blocks the Extension Host event loop.
- Made review-target and IR function IDs independent of line numbers, migrated legacy status records, and retain disappeared-target state for 30 days before cleanup.
- Recompute findings when dataflow settings change and roll back to the previous analysis if an asynchronous rebuild fails.
- Added a versioned incremental-cache and function-summary contract for later dependency-scoped recomputation.
- Added an Extension Host activation smoke test to CI and a reproducible synthetic performance baseline.
- Tightened Python/PHP precision: function clues no longer leak from preceding bodies, PHP superglobal fields stay distinct, empty `curl_init()` calls are not sinks, parameterized SQLite calls suppress SQL-injection rules, and Selenium navigation is modeled as a network sink.
- Consolidated multiple candidate paths ending at the same rule and sink while preserving every explainable path behind the finding.

## 0.5.0

- Added ordered selected-variable tracing with input, assignment, condition, validation, security-decision and sensitive-use roles.
- Added temporary editor highlighting for traced symbol occurrences.
- Added portable review-session JSON export and merge import.
- Added Chinese documentation, contribution/security policies, issue templates and GitHub Actions CI packaging.

## 0.4.0

- Replaced shield imagery with a code-trace magnifier identity.
- Added JavaScript, TypeScript, Python, C# and Go alongside Java and PHP.
- Added live current-file indexing, file target picker and function security-clue picker.
- Added next/previous target navigation and faster review-state actions.
- Added an option to hide completed targets from the queue.

## 0.3.0

- Refocused TraceGuard as a lightweight, editor-native code-audit helper.
- Removed the bundled Python scanner, subprocess execution, scan commands, SARIF/baseline settings and custom web workbenches.
- Kept only native VS Code sidebar views, CodeLens, line clues, context-menu actions, review state and audit notes.
- The packaged extension now has no runtime dependency and does not start a service or external process.

## 0.2.0

- Rebuilt the extension around a zero-configuration, local Audit Copilot.
- Automatic attack-surface, function and trust-boundary indexing for Java/PHP.
- P0–P2 human review queue with security-specific checklists and coverage tracking.
- Source, sink, authorization and validation CodeLens/line annotations.
- Persistent evidence notebook and Markdown audit report generation.
- First-run onboarding and automatic Python fallback for the optional rule scanner.

## 0.1.0

- Workspace and current-file Java/PHP security scans.
- Problems diagnostics, evidence relations, hover guidance and quick suppression.
- TraceGuard Activity Bar findings and scan summary views.
- Theme-aware security workbench with source-to-sink evidence chains.
- Scan-on-save, custom rules, baseline support and SARIF export.
- Bundled TraceGuard 0.2.0 Python engine sync and packaging workflow.
