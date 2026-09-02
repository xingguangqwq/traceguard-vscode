"use strict";

const ts = require("typescript");
const path = require("node:path");
const { normalizePath } = require("../identity");
const MAX_CACHED_PROJECT_PROGRAMS = 8;

class TypeScriptProject {
  constructor() {
    this.files = new Map();
    this.programs = new Map();
    this.generation = 0;
    this.moduleDependencies = new Map();
    this.moduleDependents = new Map();
    this.standardLibraryPath = undefined;
  }

  initialize(files = [], options = {}) {
    this.standardLibraryPath = options.standardLibraryPath;
    this.files.clear();
    for (const file of files) this._store(file);
    this.programs.clear();
    this.generation = 0;
    this._rebuildModuleDependencies();
  }

  update(file) {
    const key = compilerFileKey(file?.absolutePath);
    if (!isJavaScriptOrTypeScript(file) || !key) {
      if (key) this.remove(file?.absolutePath);
      return;
    }
    const previous = this.files.get(key);
    const next = compilerRecord(file);
    if (previous?.version === next.version && previous.text === next.text && previous.fileName === next.fileName) return;
    this.files.set(key, next);
    this.programs.clear();
    if (previous) this._replaceModuleDependencies(key);
    else this._rebuildModuleDependencies();
  }

  canAnalyzeIsolated(absolutePath, text) {
    const key = compilerFileKey(absolutePath);
    if (!key || !this.files.has(key)) return false;
    if ((this.moduleDependencies.get(key) || new Set()).size) return false;
    if ((this.moduleDependents.get(key) || new Set()).size) return false;
    return moduleNamesFromText(String(text || this.files.get(key)?.text || "")).length === 0;
  }

  remove(absolutePath) {
    const key = compilerFileKey(absolutePath);
    if (!key || !this.files.delete(key)) return;
    this.programs.clear();
    this._rebuildModuleDependencies();
  }

  releasePrograms() {
    this.programs.clear();
  }

  setStandardLibraryPath(value) {
    const normalized = value ? path.resolve(value) : undefined;
    if (normalized === this.standardLibraryPath) return false;
    this.standardLibraryPath = normalized;
    this.programs.clear();
    return true;
  }

  modelFor(absolutePath) {
    const record = this.files.get(compilerFileKey(absolutePath));
    if (!record) return undefined;
    const component = this._componentFor(absolutePath);
    const project = this._buildComponent(component);
    const sourceFile = project.program.getSourceFile(record.fileName) ||
      project.program.getSourceFiles().find(candidate => compilerFileKey(candidate.fileName) === compilerFileKey(record.fileName));
    if (!sourceFile) return undefined;
    return {
      sourceFile,
      program: project.program,
      checker: project.program.getTypeChecker(),
      projectMode: true,
      projectFileCount: component.length,
      projectGeneration: project.generation,
      standardLibrary: Boolean(this.standardLibraryPath),
      fileInfoFor: fileName => this.fileInfoFor(fileName),
    };
  }

  dependentsOf(absolutePath) {
    const target = compilerFileKey(absolutePath);
    if (!target) return [];
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

  _componentFor(absolutePath) {
    const target = compilerFileKey(absolutePath);
    if (!target || !this.files.has(target)) return [];
    const result = new Set();
    const queue = [target];
    while (queue.length) {
      const current = queue.shift();
      if (!current || result.has(current)) continue;
      result.add(current);
      queue.push(...(this.moduleDependencies.get(current) || []));
      queue.push(...(this.moduleDependents.get(current) || []));
    }
    return [...result].sort();
  }

  _buildComponent(component) {
    const componentId = `${this.standardLibraryPath || "<no-lib>"}\n${component.join("\n")}`;
    const cached = this.programs.get(componentId);
    if (cached) {
      this.programs.delete(componentId);
      this.programs.set(componentId, cached);
      return cached;
    }
    const componentFiles = new Map(component.map(key => [key, this.files.get(key)]).filter(([, record]) => record));
    const options = compilerOptions({ projectMode: true });
    const baseHost = ts.createCompilerHost(options, true);
    const host = {
      ...baseHost,
      fileExists: candidate => componentFiles.has(compilerFileKey(candidate)) || baseHost.fileExists(candidate),
      readFile: candidate => componentFiles.get(compilerFileKey(candidate))?.text ?? baseHost.readFile(candidate),
      getSourceFile: (candidate, languageVersion, onError, shouldCreateNewSourceFile) => {
        const current = componentFiles.get(compilerFileKey(candidate));
        if (current) {
          const sourceFile = ts.createSourceFile(current.fileName, current.text, languageVersion, true, scriptKindFor(current.fileName, current.language));
          sourceFile.version = current.version;
          return sourceFile;
        }
        return baseHost.getSourceFile(candidate, languageVersion, onError, shouldCreateNewSourceFile);
      },
      writeFile: () => {},
    };
    host.resolveModuleNames = (moduleNames, containingFile) => moduleNames.map(moduleName =>
      resolveVirtualModule(componentFiles, moduleName, containingFile) || ts.resolveModuleName(moduleName, containingFile, options, host).resolvedModule,
    );
    host.resolveModuleNameLiterals = (moduleLiterals, containingFile) => moduleLiterals.map(moduleLiteral => {
      const resolvedModule = resolveVirtualModule(componentFiles, moduleLiteral.text, containingFile);
      return resolvedModule ? { resolvedModule } : ts.resolveModuleName(moduleLiteral.text, containingFile, options, host);
    });
    const rootNames = [
      ...(this.standardLibraryPath ? [this.standardLibraryPath] : []),
      ...[...componentFiles.values()].map(record => record.fileName),
    ];
    const program = ts.createProgram({ rootNames, options, host });
    this.generation += 1;
    const result = { program, generation: this.generation };
    this.programs.set(componentId, result);
    while (this.programs.size > MAX_CACHED_PROJECT_PROGRAMS) this.programs.delete(this.programs.keys().next().value);
    return result;
  }

  _rebuildModuleDependencies() {
    this.moduleDependencies = new Map();
    this.moduleDependents = new Map();
    for (const sourceKey of this.files.keys()) this._replaceModuleDependencies(sourceKey);
  }

  _replaceModuleDependencies(sourceKey) {
    this._removeModuleDependencies(sourceKey);
    const record = this.files.get(sourceKey);
    if (!record) return;
    const dependencies = new Set();
    for (const moduleName of moduleNamesFromText(record.text)) {
      const resolved = resolveVirtualModule(this.files, moduleName, record.fileName);
      const dependencyKey = compilerFileKey(resolved?.resolvedFileName);
      if (dependencyKey && dependencyKey !== sourceKey) dependencies.add(dependencyKey);
    }
    this.moduleDependencies.set(sourceKey, dependencies);
    for (const dependency of dependencies) {
      if (!this.moduleDependents.has(dependency)) this.moduleDependents.set(dependency, new Set());
      this.moduleDependents.get(dependency).add(sourceKey);
    }
  }

  _removeModuleDependencies(sourceKey) {
    for (const dependency of this.moduleDependencies.get(sourceKey) || []) {
      const dependents = this.moduleDependents.get(dependency);
      dependents?.delete(sourceKey);
      if (!dependents?.size) this.moduleDependents.delete(dependency);
    }
    this.moduleDependencies.delete(sourceKey);
  }
}

function createCompilerModel(text, absolutePath, language, options = {}) {
  const fileName = absolutePath || (language === "typescript" ? "file.ts" : "file.js");
  const compilerConfiguration = compilerOptions({ projectMode: false, language });
  const standardLibraryPath = options.standardLibraryPath ? path.resolve(options.standardLibraryPath) : undefined;
  const scriptKind = scriptKindFor(fileName, language);
  const sourceFile = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, scriptKind);
  const baseHost = ts.createCompilerHost(compilerConfiguration, true);
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
  const program = ts.createProgram([...(standardLibraryPath ? [standardLibraryPath] : []), fileName], compilerConfiguration, host);
  return {
    sourceFile: program.getSourceFile(fileName) || sourceFile,
    program,
    checker: program.getTypeChecker(),
    projectMode: false,
    projectFileCount: 1,
    projectGeneration: 0,
    standardLibrary: Boolean(standardLibraryPath),
  };
}

function createSyntaxModel(text, absolutePath, language) {
  const fileName = absolutePath || (language === "typescript" ? "file.ts" : "file.js");
  return {
    sourceFile: ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, scriptKindFor(fileName, language)),
    program: undefined,
    checker: undefined,
    projectMode: false,
    projectFileCount: 1,
    projectGeneration: 0,
    standardLibrary: false,
    syntaxOnly: true,
  };
}

function compilerOptions({ projectMode, language } = {}) {
  return {
    allowJs: projectMode || language === "javascript",
    checkJs: false,
    // Project programs receive TraceGuard's explicit minimal library asset as
    // a root file. Never let TypeScript pull the full lib.*.d.ts graph.
    noLib: true,
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
  if ((ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)) &&
      statement.moduleSpecifier && ts.isStringLiteralLike(statement.moduleSpecifier)) {
    return statement.moduleSpecifier.text;
  }
  if (ts.isImportEqualsDeclaration(statement) && ts.isExternalModuleReference(statement.moduleReference) &&
      statement.moduleReference.expression && ts.isStringLiteralLike(statement.moduleReference.expression)) {
    return statement.moduleReference.expression.text;
  }
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

function moduleNamesFromText(text) {
  return [...new Set(ts.preProcessFile(String(text || ""), true, true).importedFiles.map(file => file.fileName).filter(Boolean))];
}

module.exports = {
  TypeScriptProject,
  compilerOptions,
  createCompilerModel,
  createSyntaxModel,
  moduleNamesFromSourceFile,
  moduleNamesFromText,
  scriptKindFor,
};
