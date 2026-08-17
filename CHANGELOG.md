# Changelog

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
