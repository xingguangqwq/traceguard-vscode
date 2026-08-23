# Changelog

## 0.8.0 - 2026-08-23

- Promoted Java, PHP and Python to the Tier A backend-audit focus, moved JavaScript/TypeScript to regression-focused Tier B, and kept C#/Go as correctness-maintained Tier C languages.
- Rebuilt the shared operation CFG around executable condition blocks, feasible branch joins, loop back-edges, `break`/`continue`, structured `try`/multiple-`catch`/`finally` edges, `throw` and early-return reachability. Findings and interactive queries now omit operations proven unreachable by the same graph.
- Added shared control-flow sequence and propagation-fact modules so Backward/Forward queries and Source-to-Sink findings use the same Access Path rebasing, proof status and edge explanation.
- Added AST-native Java Spring MVC, JAX-RS and Servlet entry extraction, including composition of class-level and method-level routes without line-format dependence.
- Added Java type hierarchy facts to IR, interface-to-implementation dispatch, executable-implementation preference and overload scoring by arity and inferred argument type.
- Added JavaBean getter Access Paths such as `body.getCommand()` → `body.command` across assignments, calls and query explanations.
- Added syntax-verified MyBatis dynamic-substitution sinks for `${...}` while keeping bound `#{...}` placeholders out of the SQL-injection path.
- Added Java semantic models for `ProcessBuilder`, JPA `EntityManager`, Spring `JdbcTemplate`, `RestTemplate` and `WebClient` using the existing command-injection, SQL-injection and SSRF rule families.
- Added Tier A regression fixtures for conditional assignments, dead code after return, loop/exception control flow, Spring Controller → Service interface → ServiceImpl → Mapper flow, safe/unsafe MyBatis placeholders, overload disambiguation and Java framework sinks.

## 0.7.3 - 2026-08-23

- Added one canonical Access Path model for object properties, quoted keys, array indexes and dynamic collection elements across frontend, dataflow and interactive queries.
- Added descendant rebasing for aliases and strong updates for exact overwrites, preventing stale taint and unrelated sibling-field contamination.
- Added TypeScript Checker-backed `Map`, `Set` and array propagation effects with exact or wildcard element paths and explicit per-edge proof.
- Added closure capture modeling through explicit synthetic call edges so outer values reach nested callbacks without guessing from names.
- Added receiver-type method disambiguation and bounded interface implementation dispatch; ambiguous targets are retained as review candidates instead of reported as verified calls.
- Added per-propagation `verified`, `syntax-only`, `heuristic` and `unresolved` status, reason and input/output Access Paths to findings, rules and audit-query trees.
- Added regression coverage for container aliases, strong updates, typed collections, closure capture, same-named methods, interface ambiguity and source/call evidence preservation.
- Fixed an idle workspace being shown as permanently indexing; the Review Progress view now distinguishes idle, file discovery, reading, analysis, cancellation, failure and ready states, and links an idle item directly to Build Review Queue.
- Worker timeouts and analysis errors now fail once with a visible error instead of silently repeating the same request, while cancelling workspace indexing terminates the active Worker and retains the previous audit map.

## 0.7.2 - 2026-08-23

- Added versioned `.traceguard.json` project semantics with a bundled JSON Schema, editor validation and a command that creates or opens the configuration.
- Added custom Source, Sink with tainted argument positions, Sanitizer/Guard capability, Propagator and Wrapper models compiled into the same symbol-backed Semantic Model Registry as built-in APIs.
- Added TypeScript Checker support for custom module imports and aliases, plus receiver-type verification in generic Tree-sitter languages; unqualified custom names remain syntax-only and cannot act as high-confidence sanitizers.
- Added rule enable/disable controls, severity overrides and bounded workspace-relative exclusion globs.
- Added atomic configuration reload: invalid or oversized edits produce Problems diagnostics while the last valid analysis model remains active.
- Split configuration fingerprints so semantic-model changes rebuild Frontend IR, while rule-only changes reuse IR and only rerun dataflow/rules.
- Added project-configuration regression coverage for aliases, shadowing, safe same-named receivers, custom sanitizers, Worker reconfiguration, multi-root merge, exclusions and real Extension Host hot reload.

## 0.7.1 - 2026-08-22

- Added one shared interactive audit-query protocol for backward value tracing, forward value tracing, callers, callees, entry-point reachability, reachable sinks and local analysis explanations.
- Added an expandable Audit Queries path tree with click-to-code navigation and explicit `verified`, `syntax-only`, `heuristic` and `unresolved` labels on every step.
- Moved interactive queries into the persistent analysis Worker so results always use the latest incrementally updated workspace IR without copying the workspace back to the Extension Host.
- Added Access Path-aware query propagation for nested properties and array elements without merging unrelated sibling fields.
- Added finding search, Problems-panel diagnostics, Markdown path copying and serializable per-file Analysis Debug JSON export.
- Extended the real Extension Host smoke test to execute an incremental Worker query, render its tree contract, serialize debug facts and verify live Problems diagnostics.

## 0.7.0 - 2026-08-22

- Added Tree-sitter WASM frontends for all supported languages and a persistent project-level TypeScript Program for JavaScript, TypeScript, JSX and TSX import/type resolution, with explicit parser degradation and Pattern fallback reporting.
- Replaced line-based framework route discovery with AST call/argument extraction for JavaScript/TypeScript, PHP, C# Minimal APIs and Go routers, preserving route and handler identity across compact and multiline formatting.
- Added precise line/column/offset spans to AST IR locations and CFG branch ranges so branch dominance no longer changes when multiple statements share one line.
- Added TypeScript module reverse dependencies and consumer IR regeneration when imported types or contextual callback signatures change.
- Added versioned IR symbol keys, anonymous route callback discriminators and platform-aware path identity so overloads, callbacks and case-sensitive POSIX files cannot share review state.
- Added local CFG/def-use, property and collection propagation, branch-scoped guard dominance, function summaries and summary-based cross-function taint flow.
- Added a symbol-backed semantic model registry for Sources, Sinks, Propagators and Guards, including TypeScript Checker alias/shadowing resolution and signature-specific taint argument positions.
- Added cross-function Access Path rebasing for destructured parameters, nested object fields and array indexes without contaminating unrelated sibling fields.
- Added a persistent incremental Worker protocol with file updates/removals, dependency-scoped invalidation, finding/path deltas, crash replay, queued-update coalescing and bounded retained syntax trees.
- Focused the core rule model on command injection, SQL injection, path traversal, SSRF and unsafe deserialization with rule-specific sanitizer/guard capabilities and explainable confidence/heuristic details.
- Downgraded regex-only security matches to review candidates and require AST/symbol or structural proof before a Guard may suppress a finding.
- Added C# Minimal API, Go inline `HandleFunc`, PHP route closure and JavaScript/TypeScript inline route handler identity and entry binding.
- Added sink-centered finding consolidation, reviewed/false-positive/accepted-risk/suppressed decisions, Source → Sink tree expansion and SARIF 2.1.0 export with external suppression semantics.
- Made incomplete index coverage explicit, retained historical review state after partial scans and added configurable workspace file limits with a conservative 1,000-file default.
- Added cross-language vulnerable/safe smoke pairs, packaged-runtime verification, real Extension Host AST/Worker/SARIF coverage, performance gates and bundled third-party license notices.
- Added a 100-file TypeScript dependency-fanout performance gate alongside the 1,000-file independent-route baseline.

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
