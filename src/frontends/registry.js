"use strict";

const { buildIRScopes } = require("./operation-extractor");
const { buildFileIRFromScopes } = require("./normalized-frontend");
const { parseSourceStructure } = require("./pattern-parser");

const SUPPORTED_LANGUAGES = Object.freeze(["java", "php", "javascript", "typescript", "python", "csharp", "go"]);

class PatternLanguageFrontend {
  constructor(language) {
    this.language = language;
    this.id = `pattern-${language}`;
  }

  parse(input) {
    const lines = String(input.text).split(/\r?\n/);
    const structure = parseSourceStructure(lines, this.language, input.relativePath, input.options);
    const scopes = buildIRScopes(
      lines,
      structure.functions,
      structure.signals,
      this.language,
      input.absolutePath,
      input.relativePath,
      structure.entries,
    );
    return buildFileIRFromScopes({
      absolutePath: input.absolutePath,
      relativePath: input.relativePath,
      language: this.language,
      lines: lines.length,
      entries: structure.entries,
      scopes,
      frontend: {
        id: this.id,
        mode: "pattern",
        capability: "fallback",
        ...(structure.patternDifferential ? { patternDifferential: structure.patternDifferential } : {}),
      },
    });
  }
}

const frontends = new Map(SUPPORTED_LANGUAGES.map(language => [language, new PatternLanguageFrontend(language)]));
const preferredFrontends = new Map();

function frontendForLanguage(language) {
  return frontends.get(language);
}

function registerFrontend(language, frontend) {
  if (!language || typeof frontend?.parse !== "function") throw new TypeError("A language frontend requires a parse function.");
  frontends.set(language, frontend);
}

function registerPreferredFrontend(language, frontend) {
  if (!language || typeof frontend?.parse !== "function") throw new TypeError("A preferred language frontend requires a parse function.");
  preferredFrontends.set(language, frontend);
}

function preferredFrontendForLanguage(language) {
  if (["javascript", "typescript"].includes(language) && !preferredFrontends.has(language)) {
    const { TypeScriptAstFrontend } = require("./typescript-frontend");
    preferredFrontends.set(language, new TypeScriptAstFrontend(language));
  }
  if (["java", "python", "php", "csharp", "go"].includes(language) && !preferredFrontends.has(language)) {
    const { TreeSitterLanguageFrontend } = require("./tree-sitter-frontend");
    preferredFrontends.set(language, new TreeSitterLanguageFrontend(
      language,
      ["java", "php", "python"].includes(language) ? "tier-a" : "tier-c",
    ));
  }
  return preferredFrontends.get(language);
}

async function parseWithBestFrontend(input) {
  const fallback = frontendForLanguage(input.language);
  const preferred = preferredFrontendForLanguage(input.language);
  if (!preferred) return fallback.parse(input);
  try {
    const ir = await preferred.parse(input);
    if (input.options?.differential) {
      const baseline = fallback.parse(input);
      ir.frontend.differential = compareIR(ir, baseline);
    }
    return ir;
  } catch (error) {
    const ir = fallback.parse(input);
    ir.frontend = {
      ...ir.frontend,
      degraded: true,
      degradedReason: String(error?.message || error),
      attemptedFrontend: preferred.id,
    };
    return ir;
  }
}

function compareIR(current, baseline) {
  return {
    functionDelta: current.functions.length - baseline.functions.length,
    operationDelta: current.functions.reduce((total, fn) => total + fn.operations.length, 0) -
      baseline.functions.reduce((total, fn) => total + fn.operations.length, 0),
    entryPointDelta: current.entryPoints.length - baseline.entryPoints.length,
  };
}

module.exports = {
  PatternLanguageFrontend,
  SUPPORTED_LANGUAGES,
  frontendForLanguage,
  parseWithBestFrontend,
  preferredFrontendForLanguage,
  registerFrontend,
  registerPreferredFrontend,
};
