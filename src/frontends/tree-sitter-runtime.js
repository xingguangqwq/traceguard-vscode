"use strict";

const { Language, Parser } = require("web-tree-sitter");
const { normalizePath } = require("../identity");

const GRAMMARS = Object.freeze({
  java: "tree-sitter-java/tree-sitter-java.wasm",
  python: "tree-sitter-python/tree-sitter-python.wasm",
  php: "tree-sitter-php/tree-sitter-php.wasm",
  csharp: "tree-sitter-c-sharp/tree-sitter-c_sharp.wasm",
  go: "tree-sitter-go/tree-sitter-go.wasm",
  javascript: "tree-sitter-javascript/tree-sitter-javascript.wasm",
  typescript: "tree-sitter-typescript/tree-sitter-typescript.wasm",
  tsx: "tree-sitter-typescript/tree-sitter-tsx.wasm",
});

class TreeSitterRuntime {
  constructor(options = {}) {
    this.initialized = undefined;
    this.parsers = new Map();
    this.trees = new Map();
    this.maxTrees = Math.max(1, options.maxTrees || 32);
  }

  async parse(input) {
    const grammar = grammarFor(input.language, input.absolutePath || input.relativePath);
    const parser = await this._parser(grammar);
    const key = normalizePath(input.absolutePath);
    const previous = this.trees.get(key);
    let incremental = false;
    let tree;
    if (previous && previous.grammar === grammar && previous.text !== input.text) {
      previous.tree.edit(singleEdit(previous.text, input.text));
      tree = parser.parse(input.text, previous.tree);
      incremental = true;
      previous.tree.delete();
    } else if (previous?.text === input.text) {
      tree = parser.parse(input.text, previous.tree);
      incremental = true;
      previous.tree.delete();
    } else {
      tree = parser.parse(input.text);
    }
    this.trees.delete(key);
    this.trees.set(key, { language: input.language, grammar, text: input.text, tree });
    this._evictTrees();
    return { tree, incremental };
  }

  remove(absolutePath) {
    const key = normalizePath(absolutePath);
    this.trees.get(key)?.tree.delete();
    this.trees.delete(key);
  }

  async _parser(grammar) {
    if (this.parsers.has(grammar)) return this.parsers.get(grammar);
    if (!GRAMMARS[grammar]) throw new Error(`No Tree-sitter WASM grammar is configured for ${grammar}.`);
    const initialization = this.initialized || (this.initialized = Parser.init({
        locateFile: () => require.resolve("web-tree-sitter/web-tree-sitter.wasm"),
      }));
    try {
      await initialization;
    } catch (error) {
      if (this.initialized === initialization) this.initialized = undefined;
      throw error;
    }
    const parser = new Parser();
    parser.setLanguage(await Language.load(require.resolve(GRAMMARS[grammar])));
    this.parsers.set(grammar, parser);
    return parser;
  }

  _evictTrees() {
    while (this.trees.size > this.maxTrees) {
      const oldest = this.trees.keys().next().value;
      this.trees.get(oldest)?.tree.delete();
      this.trees.delete(oldest);
    }
  }
}

function grammarFor(language, filePath) {
  return language === "typescript" && /\.tsx$/i.test(String(filePath || "")) ? "tsx" : language;
}

function singleEdit(before, after) {
  let start = 0;
  const maxPrefix = Math.min(before.length, after.length);
  while (start < maxPrefix && before[start] === after[start]) start += 1;
  let oldEnd = before.length;
  let newEnd = after.length;
  while (oldEnd > start && newEnd > start && before[oldEnd - 1] === after[newEnd - 1]) {
    oldEnd -= 1;
    newEnd -= 1;
  }
  return {
    startIndex: start,
    oldEndIndex: oldEnd,
    newEndIndex: newEnd,
    startPosition: positionAt(before, start),
    oldEndPosition: positionAt(before, oldEnd),
    newEndPosition: positionAt(after, newEnd),
  };
}

function positionAt(text, index) {
  const prefix = String(text).slice(0, index);
  const rows = prefix.split("\n");
  return { row: rows.length - 1, column: rows.at(-1).length };
}

const runtime = new TreeSitterRuntime();

module.exports = { GRAMMARS, TreeSitterRuntime, grammarFor, runtime, singleEdit };
