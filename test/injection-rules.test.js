"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { analyzeTextAsync } = require("../src/audit-analyzer");
const { runDataflowAnalysis } = require("../src/dataflow/pipeline");
const { resolveSemanticCall, validateSemanticCatalog } = require("../src/security/catalog");

async function findings(text, language) {
  const suffix = { java: "java", php: "php", python: "py" }[language];
  const analysis = await analyzeTextAsync(text, language, `C:/repo/injection.${suffix}`, `injection.${suffix}`);
  return runDataflowAnalysis([analysis]).findings;
}

test("the catalog remains valid after splitting models by language", () => assert.deepEqual(validateSemanticCatalog(), []));

test("Java LDAP checks the filter rather than base DN or substitution values", async () => {
  const source = body => `import javax.naming.directory.DirContext;
class Search { void run(HttpServletRequest request, DirContext directory) {
  String input = request.getParameter("q"); ${body}
} }`;
  const unsafe = await findings(source('directory.search("ou=users", "(uid=" + input + ")", controls);'), "java");
  assert.ok(unsafe.some(item => item.cwe === "CWE-90"));
  for (const body of [
    'directory.search(input, "(uid=fixed)", controls);',
    'directory.search("ou=users", "(uid={0})", new Object[]{ input }, controls);',
    'directory.search("ou=users", "(uid=fixed)", input);',
    'directory.search("ou=users", input);',
    'javax.naming.directory.Attributes attrs = new javax.naming.directory.BasicAttributes("uid", input); directory.search("ou=users", attrs, new String[]{"uid"});',
  ]) assert.ok(!(await findings(source(body), "java")).some(item => item.cwe === "CWE-90"), body);
});

test("a resolved unrelated search method is not an LDAP API", () => {
  const match = resolveSemanticCall("java", { function: "search", receiver: "index", arguments: ['"base"', 'input'], symbol: { kind: "local", receiverType: "SearchIndex", verified: true } }, [], "sink");
  assert.equal(match.status, "rejected");
  const attributes = resolveSemanticCall("java", { function: "search", receiver: "directory", arguments: ['"base"', "attributes", "fields"], argumentTypes: ["String", "javax.naming.directory.Attributes", "String[]"], symbol: { receiverType: "javax.naming.directory.DirContext", verified: true } }, [], "sink");
  assert.equal(attributes.status, "rejected");
  assert.match(attributes.reason, /Attributes overload/);
});

test("PHP LDAP tracks only the filter argument", async () => {
  assert.ok((await findings('<?php function run($conn) { $filter = $_GET["q"]; ldap_search($conn, "ou=users", $filter); }', "php")).some(item => item.cwe === "CWE-90"));
  assert.ok(!(await findings('<?php function run($conn) { ldap_search($conn, $_GET["base"], "(uid=fixed)"); }', "php")).some(item => item.cwe === "CWE-90"));
});

test("Python LDAP escaping protects its returned filter and cannot hide the raw input", async () => {
  const source = body => `from flask import request
from ldap.filter import escape_filter_chars
from ldap.ldapobject import LDAPObject
def run(conn: LDAPObject):
    value = request.args.get("q")
    ${body.replaceAll("\n", "\n    ")}
`;
  assert.ok((await findings(source('conn.search_s("ou=users", 2, value)'), "python")).some(item => item.cwe === "CWE-90"));
  assert.ok(!(await findings(source('safe = escape_filter_chars(value)\nconn.search_s("ou=users", 2, safe)'), "python")).some(item => item.cwe === "CWE-90"));
  assert.ok((await findings(source('safe = escape_filter_chars(value)\nconn.search_s("ou=users", 2, value)'), "python")).some(item => item.cwe === "CWE-90"));
});

for (const api of ["flask", "jinja"]) test(`${api} distinguishes template source from template context`, async () => {
  const source = body => `from flask import request, render_template_string
from jinja2 import Template
def run():
    value = request.args.get("template")
    return ${body}
`;
  const unsafe = api === "flask" ? 'render_template_string(value)' : 'Template(value)';
  assert.ok((await findings(source(unsafe), "python")).some(item => item.cwe === "CWE-1336"));
  const safe = api === "flask" ? 'render_template_string("Hello {{ name }}", name=value)' : 'Template("Hello {{ name }}").render(name=value)';
  assert.ok(!(await findings(source(safe), "python")).some(item => item.cwe === "CWE-1336"));
});

test("HTML encoding cannot sanitize server-side template source", async () => {
  const result = await findings('from flask import request, render_template_string\nfrom markupsafe import escape\ndef run():\n    value = request.args.get("t")\n    return render_template_string(escape(value))\n', "python");
  assert.ok(result.some(item => item.cwe === "CWE-1336"));
});

test("local escapers and template lookalikes do not acquire imported API contracts", async () => {
  const escaped = await findings('from flask import request\nfrom ldap.ldapobject import LDAPObject\ndef escape_filter_chars(value):\n    return value\ndef run(conn: LDAPObject):\n    value = request.args.get("q")\n    safe = escape_filter_chars(value)\n    conn.search_s("ou=users", 2, safe)\n', "python");
  assert.ok(escaped.some(item => item.cwe === "CWE-90"));
  const template = await findings('from flask import request\ndef render_template_string(value):\n    return value\ndef run():\n    return render_template_string(request.args.get("q"))\n', "python");
  assert.ok(!template.some(item => item.cwe === "CWE-1336"));
});

test("Twig createTemplate uses template source rather than render context", async () => {
  const result = await findings('<?php function run(\\Twig\\Environment $twig) { $template = $_GET["t"]; $twig->createTemplate($template); }', "php");
  assert.ok(result.some(item => item.cwe === "CWE-1336"));
});
