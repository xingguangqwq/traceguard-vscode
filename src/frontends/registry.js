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
    const structure = parseSourceStructure(lines, this.language, input.relativePath);
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
    });
  }
}

const frontends = new Map(SUPPORTED_LANGUAGES.map(language => [language, new PatternLanguageFrontend(language)]));

function frontendForLanguage(language) {
  return frontends.get(language);
}

function registerFrontend(language, frontend) {
  if (!language || typeof frontend?.parse !== "function") throw new TypeError("A language frontend requires a parse function.");
  frontends.set(language, frontend);
}

module.exports = { PatternLanguageFrontend, SUPPORTED_LANGUAGES, frontendForLanguage, registerFrontend };
