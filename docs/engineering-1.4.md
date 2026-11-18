# TraceGuard 1.4 engineering update

## Checked JavaScript and ownership

`npm run check` now runs syntax validation and `npm run typecheck`. The latter uses TypeScript in strict, no-emit mode with `// @ts-check` and JSDoc. `src/ir/contracts.d.ts` defines locations, values, operations, functions, `callBinding`, discriminated accessor summaries, argument mappings and guard bindings.

Seven production modules are checked: IR factories, access paths, argument binding, callable argument extraction, accessor recognition, guard value versions and AI localization. Negative compile-time assertions reject misspelled fields, invalid parameter kinds, incomplete accessors and passing `symbol` directly to `Array.map`. The last case also exposed a runtime bug: callback indexes and arrays had leaked into symbol types and roles. Frontends now pass only variable names.

This is an incremental migration. The other JavaScript modules still have syntax and runtime regression checks; strict typing does not yet cover the whole engine. Extend `tsconfig.check.json` when migrating another module. The check script fails if a listed production module loses `@ts-check`; do not add blanket `any` or disable checking to silence errors.

Semantic declarations now live in `src/security/models/` by language, while `catalog.js` owns lookup and validation. The original 135 models and per-language precedence were preserved during extraction. Command registration, diagnostics, editor decoration helpers, navigation and Markdown reports now live in `src/ui/`; the controller coordinates their state and lifecycle. Large frontend and path/query modules still require further decomposition.

## Rule additions and evidence limits

There are now ten finding rules. LDAP injection (CWE-90) checks the filter argument of Java JNDI, PHP LDAP and python-ldap search APIs. Base DNs and Java substitution argument arrays do not become filter text. The modeled python-ldap filter escaper protects its returned value, with value-version and sink-scope checks. DN escaping and HTML encoding are not substitutes for filter escaping.

SSTI (CWE-1336) covers Flask string-template rendering, Jinja2 template construction and Twig `createTemplate`. Fixed template source with user-controlled context variables does not trigger the template-source rule. HTML encoding is not a proof that template source is safe. External APIs supplied with keyword arguments remain subject to the frontend's existing signature limitations; this is not complete framework coverage.

Java Servlet response writer chains now preserve response provenance for `write`, `print`, `println` and `append`. Arbitrary file and logging writers are excluded from this model. A recorded flow remains a review item, including encoded or otherwise controlled paths, and does not establish exploitability or the browser's response context. Aliased writer handles and project-specific response wrappers still need additional modeling.

API references: [JNDI DirContext](https://docs.oracle.com/en/java/javase/21/docs/api/java.naming/javax/naming/directory/DirContext.html), [python-ldap filter handling](https://www.python-ldap.org/en/latest/reference/ldap-filter.html), [Flask template rendering](https://flask.palletsprojects.com/en/stable/api/#flask.render_template_string).

XXE, IDOR/authorization policy inference, reflection, dynamic proxies and full DI/AOP resolution are not added by this release. C# and Go retain their current frontend coverage.

## Explicit analysis budgets

The DFS engine remains bounded. Defaults are unchanged: depth 6, 24 CFG paths per function, 32 states per root and 3 seconds per analysis pass. Two advanced resource settings now expose the CFG and per-root state budgets; all flow settings invalidate cached analysis, including callback and async depth. Result metadata includes the chosen budgets and truncation reasons.

For a selected branch-heavy project, a larger resource configuration can be tried:

```json
{
  "traceguard.flowMaxDepth": 12,
  "traceguard.flowMaxSteps": 80,
  "traceguard.flowMaxCfgPathsPerFunction": 96,
  "traceguard.flowMaxStatesPerRoot": 200,
  "traceguard.flowTimeoutMs": 10000
}
```

Larger budgets cost CPU and do not add dynamic-dispatch knowledge. A truncated result must not be interpreted as a clean project.

## External evaluation baseline

The existing 66-case corpus is an internal synthetic regression suite. The added [OWASP Benchmark](https://owasp.org/projects/benchmark) baseline is an independent synthetic benchmark, not a measurement of arbitrary real-world projects.

The manifest pins BenchmarkJava commit `2734ae486356765ea4e45393a28e20bcb5047f8c`, the expected-results CSV hash, normalized source-content hashes, analysis options and 1,537 test cases. Five categories are scored: command injection, SQL injection, path traversal, XSS and LDAP injection. Other categories are explicitly counted as skipped. Each case is analyzed separately; project helper bodies are not indexed and the target application is never executed.

```powershell
git clone https://github.com/OWASP-Benchmark/BenchmarkJava.git .target-labs/benchmark-java
git -C .target-labs/benchmark-java checkout 2734ae486356765ea4e45393a28e20bcb5047f8c
npm run eval:owasp -- --baseline=eval-corpus/owasp-java.baseline.json --output=eval-corpus/owasp-latest-report.json
```

Line endings are normalized before hashing so Windows and Linux use the same dataset identity. Parse/analysis errors are reported separately, never scored as true negatives, and fail the run. Reports separate all candidate findings from paths whose analysis status is `verified`; that status is not an exploitability guarantee. Comparisons reject changed datasets, budgets or case coverage, and fail on a newly missed positive, newly flagged negative, lost verified path or newly truncated case. Improvements are permitted without silently rewriting the baseline.

The first 1.4 run produced these results:

| Scope | TP | FN | FP | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| All findings | 489 | 315 | 212 | 521 | 69.76% | 60.82% |
| Verified paths only | 143 | 661 | 43 | 690 | 76.88% | 17.79% |

All 1,537 cases completed without parser/analysis errors. 97 cases exhausted an exploration budget. These figures expose remaining false positives and misses; they must not be replaced with the internal suite's 100% figures. The weekly/manual GitHub workflow saves the full report and compares it with the committed baseline; it starts running after this workflow is committed and enabled on GitHub.

## AI language and artifact cleanup

AI prompts, report headings and request/key status messages follow `vscode.env.language`: `zh`, `zh-*` and `zh_*` use Chinese; other languages fall back to English. Each request captures its language for consistent streaming and final status. Source evidence is preserved as supplied. Persisted command IDs remain available; repeated sink/sanitizer actions now live under Advanced Semantic Modeling → Model Selected Call.

The stray `&;` packaging entry is removed. Type-check configuration and declarations stay outside the runtime package. `npm run clean:artifacts` previews generated root artifacts older than 24 hours, keeping the two newest VSIX packages. `npm run clean:artifacts -- --apply` removes that list. Cleanup validates canonical paths, refuses links and never selects source files or `.target-labs`.

## Local validation

The Node suite completed with 366 passing tests and one directory-link check skipped because the sandbox cannot create links. Syntax and strict types, the 66-case internal corpus, the real VS Code 1.90 Extension Host and the packaged Worker/runtime checks passed. Java, PHP and Python 1,000-file benchmarks passed the 500 ms incremental and 500 MiB RSS gates. The packaged Worker also checks LDAP, SSTI and Servlet output.
