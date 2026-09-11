"use strict";

// Deterministic, human-readable regression fixtures. Expectations are declared
// here before analysis; the generator never reads findings or rewrites baselines.
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "../eval-corpus");
const manifestPath = path.join(root, "manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
manifest.cases = manifest.cases.filter(item => !item.id.startsWith("backend-v1-"));
const rule = name => `potential-${name}`;

const java = body => `import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.sql.Connection;
import java.nio.file.*;
import org.apache.commons.lang3.SerializationUtils;
class Controller {
  @GetMapping("/review")
  void handle(@RequestParam String value, Connection db, RestTemplate client) throws Exception {
${body.split("\n").map(line => `    ${line}`).join("\n")}
  }
}
`;
const php = body => `<?php
function handle(PDO $db) {
    $value = $_GET['value'];
${body.split("\n").map(line => `    ${line}`).join("\n")}
}
`;
const python = body => `from flask import Flask, request
import os
import sqlite3
import requests
import pickle
app = Flask(__name__)
@app.get('/review')
def handle():
    value = request.args.get('value')
${body.split("\n").map(line => `    ${line}`).join("\n")}
`;

const suites = {
  java: { extension: "java", name: "Controller.java", wrap: java, cases: [
    ["command", "command-injection", 'Runtime.getRuntime().exec(value);', 'Runtime.getRuntime().exec("fixed-command");'],
    ["concatenation", "command-injection", 'Runtime.getRuntime().exec("tool " + value);', 'Runtime.getRuntime().exec("tool fixed");'],
    ["overwrite", "command-injection", 'String command = "fixed";\ncommand = value;\nRuntime.getRuntime().exec(command);', 'String command = value;\ncommand = "fixed";\nRuntime.getRuntime().exec(command);'],
    ["branch", "command-injection", 'String command = "fixed";\nif (value != null) { command = value; }\nRuntime.getRuntime().exec(command);', 'String command = value;\nif (value != null) { command = "fixed"; } else { command = "fallback"; }\nRuntime.getRuntime().exec(command);'],
    ["alias", "command-injection", 'String alias = value;\nString command = alias;\nRuntime.getRuntime().exec(command);', 'String alias = value;\nString command = "fixed";\nRuntime.getRuntime().exec(command);'],
    ["cross-file", "command-injection", 'Helper.run(value);', 'Helper.run("fixed");', { "Helper.java": 'class Helper { static void run(String command) throws Exception { Runtime.getRuntime().exec(command); } }\n' }, "Helper.java", ["handle", "run"]],
    ["sql", "sql-injection", 'db.prepareStatement("SELECT * FROM records WHERE id=" + value);', 'db.prepareStatement("SELECT * FROM records WHERE id=?").setString(1, value);'],
    ["path", "path-traversal", 'Files.readString(Path.of(value));', 'Files.readString(Path.of("fixed.txt"));'],
    ["ssrf", "ssrf", 'client.getForObject(value, String.class);', 'client.getForObject("https://example.test/fixed", String.class);'],
    ["deserialize", "unsafe-deserialization", 'SerializationUtils.deserialize(value.getBytes());', 'SerializationUtils.deserialize(new byte[] {1, 2, 3});'],
  ] },
  php: { extension: "php", name: "handler.php", wrap: php, cases: [
    ["command", "command-injection", 'system($value);', "system('fixed-command');"],
    ["concatenation", "command-injection", 'system("tool " . $value);', "system('tool fixed');"],
    ["overwrite", "command-injection", "$command = 'fixed';\n$command = $value;\nsystem($command);", "$command = $value;\n$command = 'fixed';\nsystem($command);"],
    ["branch", "command-injection", "$command = 'fixed';\nif ($value !== null) { $command = $value; }\nsystem($command);", "$command = $value;\nif ($value !== null) { $command = 'fixed'; } else { $command = 'fallback'; }\nsystem($command);"],
    ["alias", "command-injection", '$alias = $value;\n$command = $alias;\nsystem($command);', "$alias = $value;\n$command = 'fixed';\nsystem($command);"],
    ["cross-file", "command-injection", 'runCommand($value);', "runCommand('fixed');", { "helper.php": '<?php\nfunction runCommand($command) { system($command); }\n' }, "helper.php", ["handle", "runCommand"]],
    ["sql", "sql-injection", '$db->query("SELECT * FROM records WHERE id=" . $value);', "$statement = $db->prepare('SELECT * FROM records WHERE id=?');\n$statement->execute([$value]);"],
    ["path", "path-traversal", 'file_get_contents($value);', "file_get_contents('fixed.txt');"],
    ["ssrf", "ssrf", 'curl_init($value);', "curl_init('https://example.test/fixed');"],
    ["deserialize", "unsafe-deserialization", 'unserialize($value);', "unserialize('i:1;');"],
  ] },
  python: { extension: "py", name: "handler.py", wrap: python, cases: [
    ["command", "command-injection", 'os.system(value)', "os.system('fixed-command')"],
    ["concatenation", "command-injection", 'os.system(f"tool {value}")', "os.system('tool fixed')"],
    ["overwrite", "command-injection", "command = 'fixed'\ncommand = value\nos.system(command)", "command = value\ncommand = 'fixed'\nos.system(command)"],
    ["branch", "command-injection", "command = 'fixed'\nif value is not None:\n    command = value\nos.system(command)", "command = value\nif value is not None:\n    command = 'fixed'\nelse:\n    command = 'fallback'\nos.system(command)"],
    ["alias", "command-injection", 'alias = value\ncommand = alias\nos.system(command)', "alias = value\ncommand = 'fixed'\nos.system(command)"],
    ["cross-file", "command-injection", 'run_command(value)', "run_command('fixed')", { "helper.py": 'import os\ndef run_command(command):\n    os.system(command)\n' }, "helper.py", ["handle", "run_command"]],
    ["sql", "sql-injection", 'db = sqlite3.connect(":memory:")\ndb.execute("SELECT * FROM records WHERE id=" + value)', 'db = sqlite3.connect(":memory:")\ndb.execute("SELECT * FROM records WHERE id=?", (value,))'],
    ["path", "path-traversal", 'open(value)', "open('fixed.txt')"],
    ["ssrf", "ssrf", 'requests.get(value)', "requests.get('https://example.test/fixed')"],
    ["deserialize", "unsafe-deserialization", 'pickle.loads(value.encode())', 'pickle.loads(b"I1\\n.")'],
  ] },
};

for (const [language, suite] of Object.entries(suites)) {
  for (const [scenario, kind, vulnerable, safe, helpers = {}, sinkFile = suite.name, functions = ["handle"]] of suite.cases) {
    for (const [variant, body] of [["vulnerable", vulnerable], ["safe", safe]]) {
      const projectDir = `${language}/backend-v1/${scenario}/${variant}`;
      const directory = path.join(root, projectDir);
      fs.mkdirSync(directory, { recursive: true });
      let source = suite.wrap(body);
      if (scenario === "cross-file" && language === "python") source = `from helper import run_command\n${source}`;
      if (scenario === "cross-file" && language === "php") source = source.replace("<?php\n", "<?php\nrequire_once __DIR__ . '/helper.php';\n");
      fs.writeFileSync(path.join(directory, suite.name), source);
      for (const [name, text] of Object.entries(helpers)) fs.writeFileSync(path.join(directory, name), text);
      // Explicit existing capability limits: detection still gates and a
      // syntax/heuristic path is never promoted to verified by this corpus.
      const proofLimitation = language === "java" && (kind === "command-injection" || scenario === "path")
        ? "JDK chained/static receiver models currently provide syntax evidence, without compiler-backed symbol proof."
        : language === "python" && scenario === "path"
          ? "The builtin open call currently has syntax evidence without an independently resolved builtin symbol."
          : language === "php" && scenario === "cross-file"
            ? "The include-backed global function is currently resolved by a nearby-file heuristic, not proven include identity."
            : undefined;
      manifest.cases.push({ id: `backend-v1-${language}-${scenario}-${variant}`, language, projectDir,
        repository: "local-regression-fixture", commit: "backend-v1", scenario, ruleFamily: rule(kind),
        ...(variant === "vulnerable" && proofLimitation ? { proofLimitation } : {}),
        vulnerability: `${variant === "safe" ? "Negative" : "Positive"}: ${scenario} ${kind}`,
        expected: variant === "safe" ? [] : [{ ruleId: rule(kind), relativePath: sinkFile, requiredFunctions: functions,
          allowedProofStatuses: proofLimitation ? ["verified", "heuristic"] : ["verified"] }],
        falsePositiveMax: 0 });
    }
  }
}
fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Wrote ${manifest.cases.length} cases; expectations and baseline were not inferred from analysis.`);
