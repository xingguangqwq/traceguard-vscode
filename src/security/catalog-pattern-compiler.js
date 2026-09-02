"use strict";

function compileCatalogPatterns(models, language, options = {}) {
  const selectedRoles = new Set(options.roles || ["source", "sink", "guard"]);
  return models.filter(model => model.languages.includes(language) && selectedRoles.has(model.role)).flatMap(model => {
    const expressions = new Set();
    for (const syntaxForm of model.syntaxForms || []) {
      const expression = compileSyntaxForm(syntaxForm);
      if (expression) expressions.add(expression);
    }
    for (const qualifiedName of model.qualifiedNames || []) {
      const parts = String(qualifiedName).split(/[.\\/]+/).filter(Boolean);
      if (parts.length < 2 || parts.at(-2).toLowerCase() === "global") continue;
      expressions.add(`${escapePattern(parts.at(-2))}\\s*(?:\\.|->|::)\\s*${escapePattern(parts.at(-1))}\\s*\\(`);
    }
    if ((model.callForms || []).includes("instance-method") && model.patternReceiverAgnostic) {
      for (const callName of model.patternCallNames || model.callNames || []) {
        expressions.add(`(?:\\.|->)\\s*${escapePattern(callName)}\\s*\\(`);
      }
    }
    if ((model.callForms || []).includes("constructor")) {
      for (const callName of model.callNames || []) expressions.add(`\\bnew\\s+${escapePattern(callName)}\\s*\\(`);
    }
    const expectedValues = (model.argumentExpectedValues || [])[0];
    const requiredFirstArgument = (model.requiredArguments || []).some(requirement => requirement.index === 0);
    if (expectedValues?.values?.length && Number.isInteger(expectedValues.index)) {
      const prefix = Array.from({ length: expectedValues.index }, () => "[^,\\r\\n]+,\\s*").join("");
      const values = expectedValues.values.map(escapePattern).join("|");
      for (const callName of model.callNames || []) {
        expressions.add(`(?<![A-Za-z0-9_$])${escapePattern(callName)}\\s*\\(\\s*${prefix}(?:${values})\\b`);
      }
    } else if (requiredFirstArgument) {
      for (const callName of model.callNames || []) expressions.add(`(?<![A-Za-z0-9_$])${escapePattern(callName)}\\s*\\(\\s*(?!\\))`);
    } else if (model.global || model.fallbackByCallName) {
      for (const callName of model.callNames || []) expressions.add(`(?<![A-Za-z0-9_$])${escapePattern(callName)}\\s*\\(`);
    }
    const pattern = expressions.size ? new RegExp(`(?:${[...expressions].join("|")})`) : undefined;
    if (!pattern) return [];
    const kind = model.role === "guard" ? "sanitizer" : model.role;
    return [{
      modelId: model.id,
      kind,
      label: model.id,
      category: model.category || kind,
      pattern,
      confidence: "medium",
      semantic: {
        modelId: model.id,
        modelRole: model.role,
        sourceKind: model.sourceKind,
        sinkKind: model.sinkKind,
        category: model.category,
        guardCapabilities: model.guardCapabilities || [],
        applicableSinkKinds: model.applicableSinkKinds || [],
        exposure: model.exposure,
        label: model.id,
      },
    }];
  });
}

function compileSyntaxForm(form = {}) {
  const alternatives = values => (values || []).map(escapePattern).filter(Boolean).join("|");
  if (form.form === "token") {
    const values = alternatives(form.values);
    return values ? `(?:${values})` : undefined;
  }
  if (["member-access", "member-call"].includes(form.form)) {
    const receivers = alternatives(form.receivers);
    const members = alternatives(form.members);
    if (!receivers || !members) return undefined;
    const call = form.form === "member-call" ? "\\s*\\(" : "\\b";
    return `\\b(?:${receivers})\\s*(?:\\.|->)\\s*(?:${members})${call}`;
  }
  if (form.form === "annotation") {
    const delimiters = alternatives(form.delimiters || ["@"]);
    const names = alternatives(form.names);
    return delimiters && names ? `(?:${delimiters})\\s*(?:${names})\\b` : undefined;
  }
  if (form.form === "keyword") {
    const values = alternatives(form.values);
    return values ? `\\b(?:${values})\\b` : undefined;
  }
  if (form.form === "member-assignment") {
    const members = alternatives(form.members);
    return members ? `(?:\\.|->)\\s*(?:${members})\\s*=` : undefined;
  }
  if (form.form === "method-call") {
    const members = alternatives(form.members);
    return members ? `(?:\\.|->)\\s*(?:${members})\\s*\\(` : undefined;
  }
  if (form.form === "call-with-argument") {
    const callees = alternatives(form.callees);
    const argumentsPattern = alternatives(form.argumentTokens);
    return callees && argumentsPattern ? `(?:${callees})\\s*\\(\\s*(?:${argumentsPattern})` : undefined;
  }
  return undefined;
}

function escapePattern(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = { compileCatalogPatterns, compileSyntaxForm };
