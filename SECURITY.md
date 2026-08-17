# Security Policy

## Supported versions

Security fixes are applied to the latest released version.

## Reporting a vulnerability

Use GitHub’s private vulnerability reporting feature under the repository’s Security tab. Include the affected version, reproduction steps, impact and any suggested mitigation.

If private reporting is unavailable, open a minimal issue asking the maintainers for a private contact channel. Do not publish exploit details, credentials or private source code in a public issue.

## Security boundaries

TraceGuard reads supported text files through VS Code APIs to create local review navigation. It does not execute project code, start a scanner process, run a server or upload source code.

Exported review-session files can contain code snippets explicitly saved as audit notes. Review those files before sharing or committing them.

TraceGuard’s signals are heuristics for human review. A missing signal is not proof of safety, and a displayed signal is not proof of a vulnerability.
