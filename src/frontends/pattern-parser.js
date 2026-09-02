"use strict";

const { maskNonCodeLines } = require("../source-mask");
const { parameterDescriptors } = require("../identity");
const { compileCatalogPatterns } = require("../security/catalog");
const { SinkKind } = require("../security/semantics");

const JAVASCRIPT_AUXILIARY_PATTERNS = [
  ["auth", "Authentication context", /\b(?:req\.user|request\.user|isAuthenticated|passport\.authenticate|verifyToken|jwt\.verify)\b/],
  ["auth", "Authorization decision", /\b(?:authorize|authorization|hasRole|hasPermission|can|ability\.can)\s*\(/],
  ["sanitizer", "Parameterized SQL", /\.(?:query|execute)\s*\(\s*["'`][\s\S]*?(?:\?|\$\d+)/, undefined, true],
];

// Review hints and compound SQL-shape proofs are frontend evidence, not an API
// registry. All source/sink and callable guard knowledge comes from catalog.
const AUXILIARY_SYNTAX_PATTERNS = {
  java: [
    ["auth", "Authorization annotation", /@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|DenyAll|PermitAll)\b/],
    ["auth", "Security decision", /(?:hasRole|hasAuthority|checkPermission|isAuthenticated|SecurityContextHolder|AccessDecisionManager)\s*\(/],
  ],
  php: [
    ["auth", "Authentication check", /(?:Auth::(?:check|user|guard)|auth\(\)->|is_user_logged_in|wp_verify_nonce)\s*\(?/],
    ["auth", "Authorization decision", /(?:Gate::|->middleware\s*\(\s*["']auth|current_user_can|authorize\s*\(|->can\s*\()/],
    ["sanitizer", "Prepared query", /(?:->prepare\s*\(|mysqli_prepare\s*\(|->bindParam|->bindValue)/],
  ],
  javascript: JAVASCRIPT_AUXILIARY_PATTERNS,
  typescript: JAVASCRIPT_AUXILIARY_PATTERNS,
  python: [
    ["auth", "Authentication decorator", /@(?:login_required|permission_required|user_passes_test|requires_auth)\b/],
    ["auth", "Authentication context", /\b(?:current_user|request\.user|is_authenticated|has_perm|check_permission)\b/],
    ["sanitizer", "Parameterized SQL", /\.(?:execute|executemany)\s*\(\s*(?:[rub]{0,2})?["'][^"'\r\n]*(?:\?|%s|%\([^)]+\)s|:[A-Za-z_]\w*)[^"'\r\n]*["']\s*,/i, undefined, true],
  ],
  csharp: [
    ["auth", "Authorization attribute", /\[(?:Authorize|AllowAnonymous)\b/],
    ["auth", "Authorization decision", /\b(?:User\.Identity|User\.IsInRole|AuthorizeAsync|HasClaim|CheckAccess)\b/],
  ],
  go: [
    ["auth", "Authentication or claims context", /\b(?:jwt|claims|session|authenticated|currentUser)\b/i],
    ["auth", "Authorization decision", /\b(?:authorize|hasRole|hasPermission|CanAccess)\s*\(/],
  ],
};

const ANNOTATION_LANGUAGES = new Set(["java", "python", "csharp", "typescript", "javascript"]);
// Callbacks passed inline to a call, e.g. app.get("/health", (req, res) => { —
// the dominant handler style in JavaScript and TypeScript projects.
const INLINE_CALLBACK = /\(\s*(?:"[^"]*"|'[^']*'|`[^`]*`|[^,()]+)\s*,\s*(?:async\s+)?(?:function\s+([A-Za-z_$][\w$]*)|function)?\s*\(([^)]*)\)\s*(?:=>|\{)/;

function parseSourceStructure(lines, language, relativePath, options = {}) {
  const commentFreeLines = maskNonCodeLines(lines, language, false);
  const signals = collectSignals(lines, language);
  const functions = findFunctions(lines, language);
  for (const fn of functions) {
    fn.signals = signals.filter(signal => signalBelongsToFunction(signal, fn, lines, language));
  }
  const entries = findEntries(commentFreeLines, functions, signals, language, relativePath);
  return {
    signals,
    functions,
    entries,
    patternDifferential: options.differential ? compareCatalogPatternCoverage(lines, language) : undefined,
  };
}

function collectSignals(lines, language, options = {}) {
  const catalogPatterns = compileCatalogPatterns(language)
    .map(entry => [entry.kind, entry.label, entry.pattern, entry.category, false, entry]);
  const patternSource = options.patternSource || "all";
  const patterns = [
    ...(patternSource === "legacy" ? [] : catalogPatterns),
    ...(patternSource === "catalog" ? [] : (AUXILIARY_SYNTAX_PATTERNS[language] || [])),
  ];
  const signals = [];
  const searchableLines = maskNonCodeLines(lines, language);
  const commentFreeLines = patterns.some(pattern => pattern[4]) ? maskNonCodeLines(lines, language, false) : searchableLines;
  lines.forEach((code, index) => {
    const searchable = searchableLines[index];
    const trimmed = code.trim();
    if (!searchable.trim()) return;
    for (const [kind, label, pattern, category, includeStrings, catalogEntry] of patterns) {
      pattern.lastIndex = 0;
      const candidate = includeStrings ? commentFreeLines[index] : searchable;
      const match = pattern.exec(candidate);
      if (match &&
        !(kind === "sink" && matchesFunctionDeclaration(candidate, match.index, language)) &&
        !isStaticPhpSink(language, kind, label, code, catalogEntry)) {
        const resolvedCategory = category || kind;
        const duplicate = signals.find(signal => signal.line === index + 1 && signal.kind === kind && signal.category === resolvedCategory);
        // Catalog declarations are authoritative when both generations match.
        // Keep distinct legacy labels only when no catalog model owns the hit.
        if (duplicate && (catalogEntry || duplicate.catalogModelId)) continue;
        signals.push({
          kind,
          label,
          category: resolvedCategory,
          line: index + 1,
          code: trimmed,
          ...(catalogEntry ? {
            catalogModelId: catalogEntry.modelId,
            confidence: catalogEntry.confidence,
            semantic: catalogEntry.semantic,
          } : {}),
        });
      }
    }
  });
  const seen = new Set();
  return signals.filter(signal => {
    const key = [signal.kind, signal.category, signal.line, signal.label, signal.code].join(":");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function compareCatalogPatternCoverage(lines, language) {
  const legacy = collectSignals(lines, language, { patternSource: "legacy" });
  const catalog = collectSignals(lines, language, { patternSource: "catalog" });
  const legacyKeys = new Set(legacy.map(patternCoverageKey));
  const catalogKeys = new Set(catalog.map(patternCoverageKey));
  const summarize = signal => ({
    kind: signal.kind,
    category: signal.category,
    line: signal.line,
    label: signal.label,
    modelId: signal.catalogModelId,
  });
  const legacyOnly = legacy.filter(signal => !catalogKeys.has(patternCoverageKey(signal)));
  const catalogOnly = catalog.filter(signal => !legacyKeys.has(patternCoverageKey(signal)));
  return {
    legacySignals: legacy.length,
    catalogSignals: catalog.length,
    coveredLegacySignals: legacy.length - legacyOnly.length,
    legacyOnlyCount: legacyOnly.length,
    catalogOnlyCount: catalogOnly.length,
    legacyOnly: legacyOnly.slice(0, 20).map(summarize),
    catalogOnly: catalogOnly.slice(0, 20).map(summarize),
  };
}

function patternCoverageKey(signal) {
  return [signal.kind, signal.category, signal.line].join(":");
}

function isStaticPhpSink(language, kind, label, code, catalogEntry) {
  if (language !== "php" || kind !== "sink") return false;
  const sinkKind = catalogEntry?.semantic?.sinkKind;
  if (label === "HTTP response output" || sinkKind === SinkKind.RESPONSE_OUTPUT) {
    const output = String(code).match(/\b(?:echo|print)\b([\s\S]*?)(?:;|\?>|$)/i);
    return Boolean(output && isStaticPhpExpression(output[1]));
  }
  if (label === "Filesystem operation" || sinkKind === SinkKind.FILE_ACCESS) {
    const include = String(code).match(/\b(?:include|include_once|require|require_once)\b\s*\(?([\s\S]*?)(?:\)?\s*;|\?>|$)/i);
    return Boolean(include && isStaticPhpExpression(include[1]));
  }
  if (label === "HTTP response header" || sinkKind === SinkKind.REDIRECT) {
    const header = String(code).match(/\bheader\s*\(([\s\S]*?)\)\s*(?:;|\?>|$)/i);
    return Boolean(header && isStaticPhpExpression(header[1]));
  }
  return false;
}

function isStaticPhpExpression(value) {
  const input = String(value || "");
  let masked = "";
  let quote = "";
  let escaped = false;
  let interpolated = false;
  for (let index = 0; index < input.length; index += 1) {
    const character = input[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      else if (quote === '"' && character === "$" && /[A-Za-z_{]/.test(input[index + 1] || "")) interpolated = true;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      masked += "0";
    } else {
      masked += character;
    }
  }
  if (quote || interpolated) return false;
  const remainder = masked
    .replace(/\b(?:true|false|null|__DIR__|__FILE__|DIRECTORY_SEPARATOR)\b/gi, "")
    .replace(/\b[A-Z_][A-Z0-9_]*\b/g, "")
    .replace(/[\d\s.(),+\-*/%?:\[\]]/g, "");
  return remainder.length === 0;
}

function signalBelongsToFunction(signal, fn, lines, language) {
  if (signal.line >= fn.line && signal.line <= fn.endLine) return true;
  if (!ANNOTATION_LANGUAGES.has(language) || signal.line >= fn.line || signal.line < Math.max(1, fn.line - 8)) return false;
  return /^\s*(?:@|\[)/.test(lines[signal.line - 1] || "");
}

function findFunctions(lines, language) {
  const functions = [];
  const searchableLines = maskNonCodeLines(lines, language);
  searchableLines.forEach((code, index) => {
    let match;
    if (language === "java") {
      match = code.match(/^\s*(?:(?:public|protected|private)\s+)(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?[\w<>\[\],.?]+\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/);
    } else if (language === "php") {
      match = code.match(/^\s*(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+&?\s*([A-Za-z_]\w*)\s*\(([^)]*)\)/i);
    } else if (language === "javascript" || language === "typescript") {
      match = code.match(/^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/) ||
        code.match(/^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>/) ||
        code.match(INLINE_CALLBACK) ||
        code.match(/^\s*(?:(?:public|private|protected|static|async|readonly|override)\s+)*([A-Za-z_$][\w$]*)\s*\((.*)\)\s*(?::[^={]+)?\s*\{/);
      if (match?.[3] && match[2] === undefined) match[2] = match[3];
    } else if (language === "python") {
      match = code.match(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(?:->[^:]+)?\s*:/);
    } else if (language === "csharp") {
      match = code.match(/^\s*(?:(?:public|private|protected|internal|static|async|virtual|override|sealed|new|partial|extern|unsafe)\s+)+(?:[\w<>,.?\[\]]+\s+)([A-Za-z_]\w*)\s*\(([^)]*)\)/);
    } else if (language === "go") {
      match = code.match(/^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)/);
    }
    if (!match || /^(?:if|for|while|switch|catch|with)$/.test(match[1])) return;
    functions.push({
      name: match[1] || "callback",
      parameters: match[2] || "",
      parameterDescriptors: parameterDescriptors(match[2] || "", language),
      line: index + 1,
      endLine: language === "python" ? findIndentedBlockEnd(lines, index) : findBlockEnd(searchableLines, index),
      signals: [],
    });
  });
  attachEnclosingScopes(functions, lines, searchableLines, language);
  return functions;
}

function matchesFunctionDeclaration(code, matchIndex, language) {
  const prefix = String(code || "").slice(0, matchIndex);
  if (language === "python") return /^\s*(?:async\s+)?def\s+$/.test(prefix);
  if (language === "php") return /^\s*(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+&?\s*$/.test(prefix);
  return false;
}

function attachEnclosingScopes(functions, lines, searchableLines, language) {
  const types = findTypeScopes(lines, searchableLines, language);
  for (const fn of functions) {
    const containingTypes = types
      .filter(type => type.line <= fn.line && type.endLine >= fn.endLine)
      .sort((left, right) => (right.endLine - right.line) - (left.endLine - left.line));
    const containingFunctions = functions
      .filter(parent => parent !== fn && parent.line < fn.line && parent.endLine >= fn.endLine)
      .sort((left, right) => left.line - right.line);
    const receiver = language === "go" ? goReceiverType(searchableLines[fn.line - 1]) : undefined;
    fn.enclosingScope = [
      ...containingTypes.map(type => type.name),
      ...containingFunctions.map(parent => parent.name),
      receiver,
    ].filter(Boolean).join(".") || "<file>";
  }

}

function findTypeScopes(lines, searchableLines, language) {
  const scopes = [];
  searchableLines.forEach((code, index) => {
    let match;
    if (language === "python") match = code.match(/^\s*class\s+([A-Za-z_]\w*)\b/);
    else if (["java", "javascript", "typescript", "csharp", "php"].includes(language)) {
      match = code.match(/\b(?:class|interface|enum|record|struct|trait)\s+([A-Za-z_$][\w$]*)\b/i);
    }
    if (!match) return;
    scopes.push({
      name: match[1],
      line: index + 1,
      endLine: language === "python" ? findIndentedBlockEnd(lines, index) : findBlockEnd(searchableLines, index),
    });
  });
  return scopes;
}

function goReceiverType(code) {
  const receiver = String(code || "").match(/^\s*func\s*\(\s*[A-Za-z_]\w*\s+\*?([A-Za-z_]\w*)/);
  return receiver?.[1];
}

function findBlockEnd(lines, startIndex) {
  let depth = 0;
  let opened = false;
  let inBlockComment = false;
  for (let index = startIndex; index < lines.length; index += 1) {
    let code = lines[index].replace(/(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*"|`(?:\\.|[^`\\])*`)/g, "");
    while (code) {
      if (inBlockComment) {
        const end = code.indexOf("*/");
        if (end === -1) { code = ""; break; }
        inBlockComment = false;
        code = code.slice(end + 2);
        continue;
      }
      const commentStart = code.search(/\/[/*]/);
      if (commentStart === -1) break;
      if (code[commentStart + 1] === "/") { code = code.slice(0, commentStart); break; }
      const end = code.indexOf("*/", commentStart + 2);
      if (end === -1) { code = code.slice(0, commentStart); inBlockComment = true; break; }
      code = code.slice(0, commentStart) + code.slice(end + 2);
    }
    for (const character of code) {
      if (character === "{") { depth += 1; opened = true; }
      else if (character === "}") depth -= 1;
    }
    if (opened && depth <= 0) return index + 1;
    if (!opened && index > startIndex + 3) return startIndex + 1;
  }
  return lines.length;
}

function findIndentedBlockEnd(lines, startIndex) {
  const baseIndent = lines[startIndex].match(/^\s*/)[0].replaceAll("\t", "    ").length;
  for (let index = startIndex + 1; index < lines.length; index += 1) {
    const trimmed = lines[index].trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const indent = lines[index].match(/^\s*/)[0].replaceAll("\t", "    ").length;
    if (indent <= baseIndent && !trimmed.startsWith("@")) return index;
  }
  return lines.length;
}

function findEntries(lines, functions, signals, language, relativePath) {
  if (language === "java") return findJavaEntries(lines, functions);
  if (language === "php") return findPhpEntries(lines, functions, signals, relativePath);
  if (language === "javascript" || language === "typescript") return findJavascriptEntries(lines, functions);
  if (language === "python") return findPythonEntries(lines, functions);
  if (language === "csharp") return findCsharpEntries(lines, functions);
  if (language === "go") return findGoEntries(lines, functions);
  return [];
}

function findJavaEntries(lines, functions) {
  const entries = [];
  for (const fn of functions) {
    const context = lines.slice(Math.max(0, fn.line - 8), fn.line).join(" ");
    const mapping = context.match(/@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(([^)]*)\))?/);
    const jaxMethod = context.match(/@(GET|POST|PUT|DELETE|PATCH)\b/);
    const servletMethod = fn.name.match(/^do(Get|Post|Put|Delete|Patch)$/);
    if (!mapping && !jaxMethod && !servletMethod) continue;
    let method = "ANY";
    if (mapping) method = mapping[1] === "RequestMapping" ? (mapping[2]?.match(/RequestMethod\.(GET|POST|PUT|DELETE|PATCH)/)?.[1] || "ANY") : mapping[1].replace("Mapping", "").toUpperCase();
    else if (jaxMethod) method = jaxMethod[1];
    else method = servletMethod[1].toUpperCase();
    const route = (mapping?.[2]?.match(/["']([^"']+)["']/) || context.match(/@Path\s*\(\s*["']([^"']+)["']/))?.[1] || fn.name;
    entries.push(entry(method, route, fn.line, fn));
  }
  return entries;
}

function findPhpEntries(lines, functions, signals, relativePath) {
  const entries = [];
  lines.forEach((code, index) => {
    const match = code.match(/(?:Route::|\$app->)(get|post|put|delete|patch|any)\s*\(\s*["']([^"']+)["']/i);
    if (match) entries.push(entry(match[1].toUpperCase(), match[2], index + 1, containingFunction(functions, index + 1)));
  });
  if (!entries.length && signals.some(signal => signal.kind === "source")) {
    const firstSource = signals.find(signal => signal.kind === "source");
    const fn = containingFunction(functions, firstSource.line);
    entries.push(entry("REQUEST", relativePath, fn?.line || firstSource.line, fn));
  }
  return entries;
}

function findJavascriptEntries(lines, functions) {
  const entries = [];
  lines.forEach((code, index) => {
    const route = code.match(/\b(?:app|router|server|fastify)\.(get|post|put|delete|patch|options|all|use)\s*\(\s*["'`]([^"'`]+)["'`]/i);
    if (route) entries.push(entry(route[1].toUpperCase(), route[2], index + 1, containingFunction(functions, index + 1)));
  });
  for (const fn of functions) {
    const context = lines.slice(Math.max(0, fn.line - 7), fn.line).join(" ");
    const nest = context.match(/@(Get|Post|Put|Delete|Patch|Options|All)\s*\(\s*["']?([^"')\s]*)/i);
    const exportedMethod = /^(GET|POST|PUT|DELETE|PATCH|OPTIONS)$/.test(fn.name) && /\bexport\b/.test(lines[fn.line - 1]);
    if (nest) entries.push(entry(nest[1].toUpperCase(), nest[2] || fn.name, fn.line, fn));
    else if (exportedMethod) entries.push(entry(fn.name, fn.name, fn.line, fn));
  }
  return dedupeEntries(entries);
}

function findPythonEntries(lines, functions) {
  const entries = [];
  for (const fn of functions) {
    const context = lines.slice(Math.max(0, fn.line - 8), fn.line).join(" ");
    const route = context.match(/@(?:app|router|blueprint|bp)\.(get|post|put|delete|patch|options|route)\s*\(\s*["']([^"']+)["']([^)]*)/i);
    if (route) {
      const method = route[1].toLowerCase() === "route" ? (route[3].match(/["'](GET|POST|PUT|DELETE|PATCH|OPTIONS)["']/i)?.[1]?.toUpperCase() || "ANY") : route[1].toUpperCase();
      const item = entry(method, route[2], fn.line, fn);
      item.framework = route[1].toLowerCase() === "route" ? "flask" : "fastapi";
      entries.push(item);
    } else if (/\brequest\b/.test(fn.parameters)) {
      const item = entry("REQUEST", fn.name, fn.line, fn);
      item.framework = "django";
      entries.push(item);
    }
  }
  return entries;
}

function findCsharpEntries(lines, functions) {
  const entries = [];
  lines.forEach((code, index) => {
    const minimal = code.match(/\b\w+\.Map(Get|Post|Put|Delete|Patch|Methods?)\s*\(\s*["']([^"']+)["']/i);
    if (!minimal) return;
    const fn = containingFunction(functions, index + 1);
    entries.push(entry(minimal[1].toUpperCase().replace("METHODS", "ANY"), minimal[2], index + 1, fn));
  });
  for (const fn of functions) {
    const context = lines.slice(Math.max(0, fn.line - 8), fn.line).join(" ");
    const methodMatch = context.match(/\[Http(Get|Post|Put|Delete|Patch|Options)(?:\s*\(\s*["']([^"']*)["'])?/i);
    const routeMatch = context.match(/\[Route\s*\(\s*["']([^"']+)["']/i);
    if (!methodMatch && !routeMatch) continue;
    entries.push(entry(methodMatch ? methodMatch[1].toUpperCase() : "ANY", methodMatch?.[2] || routeMatch?.[1] || fn.name, fn.line, fn));
  }
  return dedupeEntries(entries);
}

function findGoEntries(lines, functions) {
  const entries = [];
  lines.forEach((code, index) => {
    const direct = code.match(/\b(?:http\.)?HandleFunc\s*\(\s*["']([^"']+)["']\s*,\s*(?:func\b|([A-Za-z_]\w*))/);
    const router = code.match(/\b\w+\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|Any|HandleFunc)\s*\(\s*["']([^"']+)["']\s*,\s*(?:func\b|([A-Za-z_]\w*))/);
    if (direct) {
      const fn = direct[2] ? functions.find(candidate => candidate.name === direct[2]) : containingFunction(functions, index + 1);
      entries.push(entry("REQUEST", direct[1], fn?.line || index + 1, fn));
    } else if (router) {
      const fn = router[3] ? functions.find(candidate => candidate.name === router[3]) : containingFunction(functions, index + 1);
      const methods = code.match(/\.Methods\s*\(\s*["'](GET|POST|PUT|DELETE|PATCH|OPTIONS)/i);
      const method = router[1].toLowerCase() === "handlefunc" ? (methods?.[1]?.toUpperCase() || "ANY") : router[1].toUpperCase();
      entries.push(entry(method, router[2], fn?.line || index + 1, fn));
    }
  });
  for (const fn of functions) {
    if (/\b(?:http\.ResponseWriter|\*http\.Request|\*gin\.Context|echo\.Context)\b/.test(fn.parameters) && !entries.some(item => item.functionLine === fn.line)) {
      entries.push(entry("REQUEST", fn.name, fn.line, fn));
    }
  }
  return entries;
}

function entry(method, route, line, fn) {
  return {
    title: `${method} ${route}`,
    method,
    route,
    line,
    endLine: fn?.endLine || line,
    functionLine: fn?.line,
    functionName: fn?.name,
    functionId: fn?.id,
    symbolKey: fn?.symbolKey,
  };
}

function containingFunction(functions, line) {
  return functions
    .filter(fn => line >= fn.line && line <= fn.endLine)
    .sort((left, right) => (left.endLine - left.line) - (right.endLine - right.line))[0];
}

function dedupeEntries(entries) {
  const seen = new Set();
  return entries.filter(item => {
    const key = `${item.method}:${item.route}:${item.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { collectSignals, compareCatalogPatternCoverage, findEntries, findFunctions, parseSourceStructure };
