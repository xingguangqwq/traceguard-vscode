# Contributing

Thanks for helping improve TraceGuard as a focused manual code-review aid.

## Development setup

Requirements: Node.js 20 or newer and VS Code 1.90 or newer.

```bash
npm install
npm test
npm run check
```

Open the extension directory in VS Code and press `F5` to launch an Extension Development Host. Package a local VSIX with `npm run package`.

## Project boundaries

Contributions should keep the extension:

- editor-native and useful during manual review;
- local-only, with no source-code upload;
- free of background services and language runtimes;
- explicit that inferred clues are not confirmed vulnerabilities.

Large scanning engines, remote analysis services and exploit execution are outside this repository’s scope.

## Adding language support

1. Add extensions and VS Code language identifiers in `src/language-support.js`.
2. Add source, sink, authorization and validation clues in `src/audit-analyzer.js`.
3. Add entry-point and function discovery for the language.
4. Include focused positive tests and false-positive regression tests.
5. Keep regular expressions bounded to one source line where possible.

## Pull requests

- Keep changes focused and explain the reviewer workflow they improve.
- Add or update tests for behavior changes.
- Run `npm test`, `npm run check` and `npm run package`.
- Do not commit `node_modules` or generated VSIX files.
- Treat source snippets in exported review sessions as potentially sensitive.
