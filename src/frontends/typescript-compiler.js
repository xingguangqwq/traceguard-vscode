"use strict";

const ts = require("typescript");
const path = require("node:path");
const { normalizePath } = require("../identity");

class TypeScriptProject {
  constructor() {
    this.files = new Map();
    this.program = undefined;
    this.dirty = true;
    this.generation = 0;
    this.moduleDependencies = new Map();
    this.moduleDependents = new Map();
  }

  initialize(files = []) {
    this.files.clear();
    for (const file of files) this._store(file);
    this.program = undefined;
    this.dirty = true;
    this.generation = 0;
    this.moduleDependencies.clear();
    this.moduleDependents.clear();
  }

  update(file) {
    const key = compilerFileKey(file?.absolutePath);
    if (!isJavaScriptOrTypeScript(file) || !key) {
      if (key && this.files.delete(key)) this.dirty = true;
      return;
    }
    const previous = this.files.get(key);
    const next = compilerRecord(file);
    if (previous?.version === next.version && previous.text === next.text && previous.fileName === next.fileName) return;
    this.files.set(key, next);
    this.dirty = true;
  }

  canAnalyzeIsolated(absolutePath, text) {
    const key = compilerFileKey(absolutePath);
    if (!key || !this.files.has(key)) return false;
    if ((this.moduleDependencies.get(key) || new Set()).size) return false;
    if ((this.moduleDependents.get(key) || new Set()).size) return false;
    const record = this.files.get(key);
    const sourceFile = ts.createSourceFile(record.fileName, String(text || ""), ts.ScriptTarget.Latest, true, scriptKindFor(record.fileName, record.language));
    return moduleNamesFromSourceFile(sourceFile).length === 0;
  }

  remove(absolutePath) {
    if (this.files.delete(compilerFileKey(absolutePath))) this.dirty = true;
  }

  modelFor(absolutePath) {
    const record = this.files.get(compilerFileKey(absolutePath));
    if (!record) return undefined;
    this._build();
    const sourceFile = this.program.getSourceFile(record.fileName) ||
      this.program.getSourceFiles().find(candidate => compilerFileKey(candidate.fileName) === compilerFileKey(record.fileName));
    if (!sourceFile) return undefined;
    return {
      sourceFile,
      program: this.program,
      checker: this.program.getTypeChecker(),
      projectMode: true,
      projectFileCount: this.files.size,
      projectGeneration: this.generation,
      standardLibrary: true,
      fileInfoFor: fileName => this.fileInfoFor(fileName),
    };
  }

  dependentsOf(absolutePath) {
    const target = compilerFileKey(absolutePath);
    if (!target) return [];
    this._build();
    const result = new Set();
    const queue = [...(this.moduleDependents.get(target) || [])];
    while (queue.length) {
      const dependent = queue.shift();
      if (!dependent || dependent === target || result.has(dependent)) continue;
      result.add(dependent);
      queue.push(...(this.moduleDependents.get(dependent) || []));
    }
    return [...result];
  }

  fileInfoFor(fileName) {
    const record = this.files.get(compilerFileKey(fileName));
    return record ? {
      absolutePath: record.fileName,
      relativePath: record.relativePath,
      language: record.language,
    } : undefined;
  }

  _store(file) {
    if (!isJavaScriptOrTypeScript(file) || !file?.absolutePath) return;
    this.files.set(compilerFileKey(file.absolutePath), compilerRecord(file));
  }

  _build() {
    if (!this.dirty && this.program) return;
    const options = compilerOptions({ projectMode: true });
    const baseHost = ts.createCompilerHost(options, true);
    const host = {
      ...baseHost,
      fileExists: candidate => this.files.has(compilerFileKey(candidate)) || baseHost.fileExists(candidate),
      readFile: candidate => this.files.get(compilerFileKey(candidate))?.text ?? baseHost.readFile(candidate),
      getSourceFile: (candidate, languageVersion, onError, shouldCreateNewSourceFile) => {
        const current = this.files.get(compilerFileKey(candidate));
        if (current) {
          if (!current.sourceFile || shouldCreateNewSourceFile) {
            current.sourceFile = ts.createSourceFile(current.fileName, current.text, languageVersion, true, scriptKindFor(current.fileName, current.language));
            current.sourceFile.version = current.version;
          }
          return current.sourceFile;
        }
        return baseHost.getSourceFile(candidate, languageVersion, onError, shouldCreateNewSourceFile);
      },
      writeFile: () => {},
    };
    host.resolveModuleNames = (moduleNames, containingFile) => moduleNames.map(moduleName =>
      resolveVirtualModule(this.files, moduleName, containingFile) || ts.resolveModuleName(moduleName, containingFile, options, host).resolvedModule,
    );
    host.resolveModuleNameLiterals = (moduleLiterals, containingFile) => moduleLiterals.map(moduleLiteral => {
      const resolvedModule = resolveVirtualModule(this.files, moduleLiteral.text, containingFile);
      return resolvedModule ? { resolvedModule } : ts.resolveModuleName(moduleLiteral.text, containingFile, options, host);
    });
    const rootNames = [...this.files.values()].map(record => record.fileName);
    this.program = ts.createProgram({ rootNames, options, host, oldProgram: this.program });
    this.dirty = false;
    this.generation += 1;
    this._rebuildModuleDependencies();
  }

  _rebuildModuleDependencies() {
    this.moduleDependencies = new Map();
    this.moduleDependents = new Map();
    for (const [sourceKey, record] of this.files) {
      const sourceFile = this.program.getSourceFile(record.fileName) ||
        this.program.getSourceFiles().find(candidate => compilerFileKey(candidate.fileName) === sourceKey);
      if (!sourceFile) continue;
      const dependencies = new Set();
      for (const moduleName of moduleNamesFromSourceFile(sourceFile)) {
        if (!moduleName) continue;
        const resolved = resolveVirtualModule(this.files, moduleName, sourceFile.fileName);
        const dependencyKey = compilerFileKey(resolved?.resolvedFileName);
        if (dependencyKey && dependencyKey !== sourceKey) dependencies.add(dependencyKey);
      }
      this.moduleDependencies.set(sourceKey, dependencies);
      for (const dependency of dependencies) {
        if (!this.moduleDependents.has(dependency)) this.moduleDependents.set(dependency, new Set());
        this.moduleDependents.get(dependency).add(sourceKey);
      }
    }
  }
}

function createCompilerModel(text, absolutePath, language) {
  const fileName = absolutePath || (language === "typescript" ? "file.ts" : "file.js");
  const options = compilerOptions({ projectMode: false, language });
  const scriptKind = scriptKindFor(fileName, language);
  const sourceFile = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, scriptKind);
  const baseHost = ts.createCompilerHost(options, true);
  const host = {
    ...baseHost,
    fileExists: candidate => compilerFileKey(candidate) === compilerFileKey(fileName) || baseHost.fileExists(candidate),
    readFile: candidate => compilerFileKey(candidate) === compilerFileKey(fileName) ? text : baseHost.readFile(candidate),
    getSourceFile: (candidate, languageVersion, onError, shouldCreateNewSourceFile) =>
      compilerFileKey(candidate) === compilerFileKey(fileName)
        ? sourceFile
        : baseHost.getSourceFile(candidate, languageVersion, onError, shouldCreateNewSourceFile),
    writeFile: () => {},
  };
  const program = ts.createProgram([fileName], options, host);
  return {
    sourceFile: program.getSourceFile(fileName) || sourceFile,
    program,
    checker: program.getTypeChecker(),
    projectMode: false,
    projectFileCount: 1,
    projectGeneration: 0,
    standardLibrary: false,
  };
}

function compilerOptions({ projectMode, language } = {}) {
  return {
    allowJs: projectMode || language === "javascript",
    checkJs: false,
    noLib: !projectMode,
    noResolve: !projectMode,
    skipLibCheck: true,
    target: ts.ScriptTarget.Latest,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Node10,
    jsx: ts.JsxEmit.Preserve,
  };
}

function scriptKindFor(fileName, language) {
  const extension = String(fileName || "").toLowerCase().match(/\.[^.\\/]+$/)?.[0];
  if (extension === ".tsx") return ts.ScriptKind.TSX;
  if ([".ts", ".mts", ".cts"].includes(extension)) return ts.ScriptKind.TS;
  if (extension === ".jsx") return ts.ScriptKind.JSX;
  if ([".js", ".mjs", ".cjs"].includes(extension)) return ts.ScriptKind.JS;
  return language === "typescript" ? ts.ScriptKind.TS : ts.ScriptKind.JS;
}

function isJavaScriptOrTypeScript(file) {
  return ["javascript", "typescript"].includes(file?.language) && typeof file?.text === "string";
}

function compilerRecord(file) {
  return {
    fileName: file.absolutePath,
    relativePath: file.relativePath || path.basename(file.absolutePath),
    language: file.language,
    text: String(file.text || ""),
    version: String(file.version || ""),
    sourceFile: undefined,
  };
}

function compilerFileKey(fileName) {
  return fileName ? normalizePath(fileName) : "";
}

function resolveVirtualModule(files, moduleName, containingFile) {
  if (!moduleName?.startsWith(".") && !path.isAbsolute(moduleName)) return undefined;
  const base = path.resolve(path.dirname(containingFile), moduleName);
  const candidates = path.extname(base)
    ? [base]
    : [base, ...[".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"].map(extension => base + extension),
      ...[".ts", ".tsx", ".js", ".jsx"].map(extension => path.join(base, "index" + extension))];
  for (const candidate of candidates) {
    const record = files.get(compilerFileKey(candidate));
    if (!record) continue;
    return {
      resolvedFileName: record.fileName,
      extension: compilerExtension(record.fileName),
      isExternalLibraryImport: false,
    };
  }
  return undefined;
}

function compilerExtension(fileName) {
  const extension = path.extname(fileName).toLowerCase();
  return {
    ".ts": ts.Extension.Ts,
    ".tsx": ts.Extension.Tsx,
    ".mts": ts.Extension.Mts,
    ".cts": ts.Extension.Cts,
    ".js": ts.Extension.Js,
    ".jsx": ts.Extension.Jsx,
    ".mjs": ts.Extension.Mjs,
    ".cjs": ts.Extension.Cjs,
  }[extension] || ts.Extension.Ts;
}

function moduleNameFromStatement(statement) {
  if ((ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
    return statement.moduleSpecifier.text;
  }
  if (ts.isImportEqualsDeclaration(statement) && ts.isExternalModuleReference(statement.moduleReference) &&
      ts.isStringLiteralLike(statement.moduleReference.expression)) return statement.moduleReference.expression.text;
  return undefined;
}

function moduleNamesFromSourceFile(sourceFile) {
  const result = new Set();
  const visit = node => {
    const statementName = moduleNameFromStatement(node);
    if (statementName) result.add(statementName);
    if (ts.isCallExpression(node) && node.arguments.length && ts.isStringLiteralLike(node.arguments[0])) {
      const dynamicImport = node.expression.kind === ts.SyntaxKind.ImportKeyword;
      const commonJs = ts.isIdentifier(node.expression) && node.expression.text === "require";
      if (dynamicImport || commonJs) result.add(node.arguments[0].text);
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return [...result];
}

module.exports = { TypeScriptProject, compilerOptions, createCompilerModel, moduleNamesFromSourceFile, scriptKindFor };
