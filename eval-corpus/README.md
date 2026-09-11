# Backend regression corpus

66 local fixtures: 33 positive and 33 negative cases, with 22 cases per language.
These are minimal static-analysis regressions, not a representative measurement
of real repositories. Fixtures are parsed as source; they are never executed.

The 60 `backend-v1` cases cover command execution, concatenation/interpolation,
strong overwrite, conditional overwrite, aliases, cross-file propagation, SQL,
filesystem paths, SSRF and deserialization. Run `node scripts/build-backend-corpus.js`
from the extension root to reproduce them. This does not update the baseline.

Run `npm run eval:compare` to enforce the 1.1.0 baseline. All unexpected rules
count as false positives, including in negative cases. Missing cases, fewer
expected/detected findings, more false positives or lost verified paths fail.

Some Java JDK receivers, Python builtin `open`, and PHP include-based function
resolution currently carry syntax/heuristic proof. Those cases document their
limitations and still reject unresolved paths. The original unknown-PDO case
intentionally retains an unresolved path. A finding is not proof of exploitability.
