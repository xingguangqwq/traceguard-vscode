"use strict";

const crypto = require("crypto");
const path = require("path");

const JAVASCRIPT_PATTERNS = [
  ["source", "HTTP request data", /\breq(?:uest)?\.(?:body|query|params|headers|cookies|files)\b|\b(?:searchParams|formData)\.(?:get|getAll)\s*\(/],
  ["source", "Framework-bound request data", /@(?:Body|Query|Param|Headers|Req|Request|UploadedFile)\s*\(/],
  ["source", "Process or event input", /\bprocess\.argv\b|\bevent\.(?:data|body|queryStringParameters|pathParameters)\b/],
  ["sink", "SQL / persistence operation", /\.(?:query|execute|raw|\$queryRaw|\$executeRaw)\s*\(/, "database"],
  ["sink", "Operating-system command", /\b(?:exec|execSync|spawn|spawnSync|fork)\s*\(|\bchild_process\./, "command"],
  ["sink", "Dynamic JavaScript execution", /\b(?:eval|Function)\s*\(|setTimeout\s*\(\s*[^,]+\s*,/, "expression"],
  ["sink", "Filesystem operation", /\bfs(?:\.promises)?\.(?:readFile|writeFile|appendFile|unlink|rename|copyFile|createReadStream|createWriteStream)\s*\(/, "file"],
  ["sink", "Outbound network request", /\b(?:fetch|axios\.(?:get|post|put|patch|delete)|https?\.(?:get|request))\s*\(/, "network"],
  ["sink", "Redirect target", /\b(?:res|response)\.redirect\s*\(/, "redirect"],
  ["sink", "HTML or response output", /\.(?:innerHTML|outerHTML)\s*=|\b(?:res|response)\.(?:send|write|end)\s*\(/, "output"],
  ["auth", "Authentication context", /\b(?:req\.user|request\.user|isAuthenticated|passport\.authenticate|verifyToken|jwt\.verify)\b/],
  ["auth", "Authorization decision", /\b(?:authorize|authorization|hasRole|hasPermission|can|ability\.can)\s*\(/],
  ["sanitizer", "Schema or input validation", /\b(?:validate|sanitize|escape|parse|safeParse)\s*\(|\b(?:joi|zod|yup|validator)\b/i],
  ["sanitizer", "HTML sanitization", /\b(?:DOMPurify\.sanitize|sanitizeHtml|encodeURIComponent|escapeHtml)\s*\(/],
  ["sanitizer", "Canonical path check", /\bpath\.(?:normalize|resolve|basename)\s*\(/],
  ["sanitizer", "Parameterized SQL", /\.(?:query|execute)\s*\(\s*["'`][\s\S]*?(?:\?|\$\d+)/],
];

const SIGNAL_PATTERNS = {
  java: [
    ["source", "HTTP parameter", /(?:getParameter|getHeader|getCookies|getQueryString|getInputStream|getReader|getPathInfo|getRequestURI)\s*\(/],
    ["source", "Framework-bound request data", /@(?:RequestParam|PathVariable|RequestBody|CookieValue|RequestHeader|ModelAttribute)\b/],
    ["sink", "SQL / persistence operation", /\.(?:executeQuery|executeUpdate|execute|createNativeQuery|createQuery)\s*\(/, "database"],
    ["sink", "Operating-system command", /(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(/, "command"],
    ["sink", "Filesystem operation", /(?:new\s+File|Paths\.get|Path\.of|Files\.(?:read|write|delete|copy|move|newInputStream|newOutputStream))\s*\(/, "file"],
    ["sink", "Outbound network request", /(?:new\s+(?:URL|URI)|URI\.create|\.getForObject|\.getForEntity|WebClient\.create|HttpRequest\.newBuilder)\s*\(/, "network"],
    ["sink", "Native deserialization", /\.readObject\s*\(/, "deserialization"],
    ["sink", "Dynamic expression", /\.parseExpression\s*\(/, "expression"],
    ["sink", "Redirect target", /\.sendRedirect\s*\(/, "redirect"],
    ["sink", "Directory lookup", /\.(?:lookup|search)\s*\(/, "directory"],
    ["auth", "Authorization annotation", /@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|DenyAll|PermitAll)\b/],
    ["auth", "Security decision", /(?:hasRole|hasAuthority|checkPermission|isAuthenticated|SecurityContextHolder|AccessDecisionManager)\s*\(/],
    ["sanitizer", "Parameterized statement", /(?:PreparedStatement|prepareStatement|\.set(?:String|Int|Long|Object)\s*\()/],
    ["sanitizer", "Validation constraint", /@(?:Valid|Validated|Pattern|Size|Min|Max|NotNull)\b/],
    ["sanitizer", "Canonical path check", /(?:normalize|toRealPath|getCanonicalPath)\s*\(/],
    ["sanitizer", "Output encoding", /(?:Encode\.forHtml|HtmlUtils\.htmlEscape|StringEscapeUtils\.escapeHtml)\s*\(/],
  ],
  php: [
    ["source", "HTTP request data", /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b/],
    ["source", "Raw request body", /php:\/\/input/],
    ["sink", "SQL / persistence operation", /(?:mysqli_query\s*\(|->(?:query|exec)\s*\()/, "database"],
    ["sink", "Operating-system command", /\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(/, "command"],
    ["sink", "Dynamic PHP execution", /\b(?:eval|assert)\s*\(/, "expression"],
    ["sink", "Filesystem operation", /\b(?:include|include_once|require|require_once|file_get_contents|readfile|fopen|unlink|copy|rename|move_uploaded_file)\s*\(?/, "file"],
    ["sink", "Outbound network request", /(?:curl_init\s*\(|curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,)/, "network"],
    ["sink", "Object deserialization", /\bunserialize\s*\(/, "deserialization"],
    ["sink", "HTTP response output", /\b(?:echo|print)\b/, "output"],
    ["sink", "HTTP response header", /\bheader\s*\(/, "redirect"],
    ["auth", "Authentication check", /(?:Auth::(?:check|user|guard)|auth\(\)->|is_user_logged_in|wp_verify_nonce)\s*\(?/],
    ["auth", "Authorization decision", /(?:Gate::|->middleware\s*\(\s*["']auth|current_user_can|authorize\s*\(|->can\s*\()/],
    ["sanitizer", "Prepared query", /(?:->prepare\s*\(|mysqli_prepare\s*\(|->bindParam|->bindValue)/],
    ["sanitizer", "Validated input", /(?:filter_input|filter_var|->validate\s*\(|Validator::make)\s*\(/],
    ["sanitizer", "Output encoding", /\b(?:htmlspecialchars|htmlentities|esc_html|e)\s*\(/],
    ["sanitizer", "Shell argument escaping", /\b(?:escapeshellarg|escapeshellcmd)\s*\(/],
    ["sanitizer", "Canonical path check", /\b(?:realpath|basename)\s*\(/],
  ],
  javascript: JAVASCRIPT_PATTERNS,
  typescript: JAVASCRIPT_PATTERNS,
  python: [
    ["source", "HTTP request data", /\brequest\.(?:args|form|values|json|data|files|cookies|headers|GET|POST|body)\b/],
    ["source", "Framework-bound request data", /\b(?:Query|Path|Body|Form|Header|Cookie)\s*\(/],
    ["source", "Process or console input", /\b(?:sys\.argv|os\.environ|getenv\s*\(|input\s*\()/],
    ["sink", "SQL / persistence operation", /\.(?:execute|executemany|raw)\s*\(/, "database"],
    ["sink", "Operating-system command", /\b(?:os\.(?:system|popen)|subprocess\.(?:run|Popen|call|check_output|check_call))\s*\(/, "command"],
    ["sink", "Dynamic Python execution", /\b(?:eval|exec|compile)\s*\(/, "expression"],
    ["sink", "Filesystem operation", /\b(?:open|Path)\s*\(|\.(?:read_text|write_text|read_bytes|write_bytes|unlink|rename)\s*\(/, "file"],
    ["sink", "Outbound network request", /\b(?:requests|httpx)\.(?:get|post|put|patch|delete|request)\s*\(|\burllib\.request\.urlopen\s*\(/, "network"],
    ["sink", "Object deserialization", /\b(?:pickle|dill)\.loads?\s*\(|\byaml\.(?:load|unsafe_load)\s*\(/, "deserialization"],
    ["sink", "Redirect target", /\bredirect\s*\(/, "redirect"],
    ["auth", "Authentication decorator", /@(?:login_required|permission_required|user_passes_test|requires_auth)\b/],
    ["auth", "Authentication context", /\b(?:current_user|request\.user|is_authenticated|has_perm|check_permission)\b/],
    ["sanitizer", "Schema or form validation", /\.(?:is_valid|validate|model_validate)\s*\(|\b(?:BaseModel|Serializer|Form)\b/],
    ["sanitizer", "Output sanitization", /\b(?:bleach\.clean|html\.escape|markupsafe\.escape)\s*\(/],
    ["sanitizer", "Safe filename or canonical path", /\b(?:secure_filename|resolve|normpath|basename)\s*\(/],
  ],
  csharp: [
    ["source", "HTTP request data", /\bRequest\.(?:Query|Form|Headers|Cookies|Body|Path)\b/],
    ["source", "Framework-bound request data", /\[(?:FromBody|FromQuery|FromRoute|FromForm|FromHeader)\b/],
    ["sink", "SQL / persistence operation", /\b(?:SqlCommand|FromSqlRaw|ExecuteSqlRaw)\b|\.(?:ExecuteReader|ExecuteScalar|ExecuteNonQuery)\s*\(/, "database"],
    ["sink", "Operating-system command", /\b(?:Process\.Start|new\s+ProcessStartInfo)\b/, "command"],
    ["sink", "Filesystem operation", /\b(?:File|Directory)\.(?:Read|Write|Delete|Move|Copy|Open|Create)|\bPath\.Combine\s*\(/, "file"],
    ["sink", "Outbound network request", /\bHttpClient\b|\.(?:GetAsync|PostAsync|SendAsync)\s*\(/, "network"],
    ["sink", "Object deserialization", /\b(?:BinaryFormatter|LosFormatter|NetDataContractSerializer)\b|\.Deserialize\s*\(/, "deserialization"],
    ["sink", "Redirect target", /\b(?:Redirect|RedirectToAction|Response\.Redirect)\s*\(/, "redirect"],
    ["auth", "Authorization attribute", /\[(?:Authorize|AllowAnonymous)\b/],
    ["auth", "Authorization decision", /\b(?:User\.Identity|User\.IsInRole|AuthorizeAsync|HasClaim|CheckAccess)\b/],
    ["sanitizer", "Model validation", /\bModelState\.IsValid\b|\[(?:Required|RegularExpression|Range|StringLength)\b/],
    ["sanitizer", "Output encoding", /\b(?:HtmlEncoder\.Default\.Encode|WebUtility\.HtmlEncode|HttpUtility\.HtmlEncode)\s*\(/],
    ["sanitizer", "Canonical path check", /\bPath\.GetFullPath\s*\(/],
  ],
  go: [
    ["source", "HTTP request data", /\br\.(?:FormValue|PostFormValue)\s*\(|\br\.URL\.Query\s*\(|\br\.Header\.Get\s*\(|json\.NewDecoder\s*\(\s*r\.Body/],
    ["source", "Framework request parameter", /\b(?:c|ctx)\.(?:Param|Query|PostForm|GetHeader|Bind|ShouldBind)\s*\(/],
    ["source", "Process input", /\bos\.(?:Args|Getenv)\b/],
    ["sink", "SQL / persistence operation", /\b(?:db|tx)\.(?:Query|QueryRow|Exec|Prepare)(?:Context)?\s*\(/, "database"],
    ["sink", "Operating-system command", /\bexec\.Command(?:Context)?\s*\(/, "command"],
    ["sink", "Filesystem operation", /\bos\.(?:Open|OpenFile|ReadFile|WriteFile|Remove|Rename|Create)\s*\(/, "file"],
    ["sink", "Outbound network request", /\bhttp\.(?:Get|Post|NewRequest)\s*\(|\bclient\.Do\s*\(/, "network"],
    ["sink", "Template trust bypass", /\btemplate\.(?:HTML|JS|URL)\s*\(/, "output"],
    ["sink", "Native deserialization", /\b(?:gob|xml)\.NewDecoder\b|\.Decode\s*\(/, "deserialization"],
    ["auth", "Authentication or claims context", /\b(?:jwt|claims|session|authenticated|currentUser)\b/i],
    ["auth", "Authorization decision", /\b(?:authorize|hasRole|hasPermission|CanAccess)\s*\(/],
    ["sanitizer", "Typed input conversion", /\bstrconv\.(?:Atoi|ParseInt|ParseUint|ParseBool)\s*\(/],
    ["sanitizer", "Path canonicalization", /\bfilepath\.(?:Clean|Abs|Base)\s*\(/],
    ["sanitizer", "Output encoding", /\bhtml\.EscapeString\s*\(/],
  ],
};

const SENSITIVE_PATH = /(?:auth|login|admin|upload|download|payment|billing|token|secret|config|account|user|permission|session|webhook|callback)/i;
const ANNOTATION_LANGUAGES = new Set(["java", "python", "csharp", "typescript", "javascript"]);

function analyzeText(text, language, absolutePath, relativePath = path.basename(absolutePath)) {
  const lines = String(text).split(/\r?\n/);
  const signals = collectSignals(lines, language);
  const functions = findFunctions(lines, language);
  for (const fn of functions) {
    const annotationStart = ANNOTATION_LANGUAGES.has(language) ? Math.max(1, fn.line - 8) : fn.line;
    fn.signals = signals.filter(signal => signal.line >= annotationStart && signal.line <= fn.endLine);
  }
  const entries = findEntries(lines, functions, signals, language, relativePath);
  const entryFunctionLines = new Set(entries.map(entry => entry.functionLine).filter(Boolean));
  const items = [];

  for (const entry of entries) {
    const fn = functions.find(candidate => candidate.line === entry.functionLine);
    const scopedSignals = fn?.signals || signals.filter(signal => Math.abs(signal.line - entry.line) <= 35);
    items.push(makeAuditItem({
      kind: "endpoint",
      title: entry.title,
      functionName: fn?.name || entry.functionName || "request handler",
      line: entry.line,
      endLine: fn?.endLine || entry.endLine || entry.line,
      signals: scopedSignals,
      absolutePath,
      relativePath,
      language,
      sensitivePath: SENSITIVE_PATH.test(relativePath),
    }));
  }

  for (const fn of functions) {
    if (entryFunctionLines.has(fn.line)) continue;
    const hasSensitiveFlow = fn.signals.some(signal => signal.kind === "sink") ||
      (fn.signals.some(signal => signal.kind === "source") && SENSITIVE_PATH.test(`${relativePath} ${fn.name}`));
    if (!hasSensitiveFlow) continue;
    items.push(makeAuditItem({
      kind: "function",
      title: `${fn.name}()`,
      functionName: fn.name,
      line: fn.line,
      endLine: fn.endLine,
      signals: fn.signals,
      absolutePath,
      relativePath,
      language,
      sensitivePath: SENSITIVE_PATH.test(`${relativePath} ${fn.name}`),
    }));
  }

  const coveredLines = new Set(functions.flatMap(fn => Array.from({ length: Math.max(0, fn.endLine - fn.line + 1) }, (_, index) => fn.line + index)));
  const globalSensitive = signals.filter(signal => signal.kind === "sink" && !coveredLines.has(signal.line));
  if (globalSensitive.length && !items.some(item => item.kind === "endpoint")) {
    items.push(makeAuditItem({
      kind: "file",
      title: `File-level execution: ${path.basename(relativePath)}`,
      functionName: "global scope",
      line: globalSensitive[0].line,
      endLine: lines.length,
      signals: signals.filter(signal => !coveredLines.has(signal.line)),
      absolutePath,
      relativePath,
      language,
      sensitivePath: SENSITIVE_PATH.test(relativePath),
    }));
  }

  return { absolutePath, relativePath, language, lines: lines.length, signals, functions, entries, items };
}

function collectSignals(lines, language) {
  const patterns = SIGNAL_PATTERNS[language] || [];
  const signals = [];
  lines.forEach((code, index) => {
    const trimmed = code.trim();
    if (!trimmed || /^(?:\/\/|#|\*|\/\*)/.test(trimmed)) return;
    for (const [kind, label, pattern, category] of patterns) {
      if (pattern.test(code)) signals.push({ kind, label, category: category || kind, line: index + 1, code: trimmed });
    }
  });
  return signals;
}

function traceIdentifier(text, identifier, signals = []) {
  if (!/^[A-Za-z_$][\w$]*$/.test(identifier || "")) return [];
  const lines = String(text).split(/\r?\n/);
  const escaped = identifier.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`(?<![\\w$])${escaped}(?![\\w$])`, "g");
  const trace = [];
  lines.forEach((code, index) => {
    const trimmed = code.trim();
    if (!trimmed || /^(?:\/\/|#|\*|\/\*)/.test(trimmed)) return;
    const lineSignals = signals.filter(signal => signal.line === index + 1);
    let match;
    while ((match = pattern.exec(code))) {
      if (/(?:\.|->|::)\s*$/.test(code.slice(0, match.index))) continue;
      trace.push({
        line: index + 1,
        column: match.index + 1,
        endColumn: match.index + identifier.length + 1,
        code: trimmed,
        role: traceRole(code, identifier, lineSignals),
        signals: lineSignals.map(signal => ({ kind: signal.kind, label: signal.label, category: signal.category })),
      });
    }
  });
  return trace;
}

function traceRole(code, identifier, signals) {
  if (signals.some(signal => signal.kind === "source")) return "input";
  if (signals.some(signal => signal.kind === "sink")) return "sensitive-use";
  if (signals.some(signal => signal.kind === "sanitizer")) return "validation";
  if (signals.some(signal => signal.kind === "auth")) return "security-decision";
  const escaped = identifier.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (new RegExp(`(?:const|let|var|final|String|int|long|bool|boolean|:=)?\\s*(?<![\\w$])${escaped}(?![\\w$])\\s*(?::[^=]+)?=`).test(code)) return "assignment";
  if (/\b(?:if|else if|while|switch|case|match)\b/.test(code)) return "condition";
  if (new RegExp(`(?:function|def|func|public|private|protected|internal).*\\([^)]*(?<![\\w$])${escaped}(?![\\w$])`).test(code)) return "parameter";
  return "reference";
}

function findFunctions(lines, language) {
  const functions = [];
  lines.forEach((code, index) => {
    let match;
    if (language === "java") {
      match = code.match(/^\s*(?:(?:public|protected|private)\s+)(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?[\w<>\[\],.?]+\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/);
    } else if (language === "php") {
      match = code.match(/^\s*(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+&?\s*([A-Za-z_]\w*)\s*\(([^)]*)\)/i);
    } else if (language === "javascript" || language === "typescript") {
      match = code.match(/^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/) ||
        code.match(/^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>/) ||
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
      name: match[1],
      parameters: match[2] || "",
      line: index + 1,
      endLine: language === "python" ? findIndentedBlockEnd(lines, index) : findBlockEnd(lines, index),
      signals: [],
    });
  });
  return functions;
}

function findBlockEnd(lines, startIndex) {
  let depth = 0;
  let opened = false;
  for (let index = startIndex; index < lines.length; index += 1) {
    const sanitized = lines[index].replace(/(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)/g, "");
    for (const character of sanitized) {
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
      entries.push(entry(method, route[2], fn.line, fn));
    } else if (/\brequest\b/.test(fn.parameters)) {
      entries.push(entry("REQUEST", fn.name, fn.line, fn));
    }
  }
  return entries;
}

function findCsharpEntries(lines, functions) {
  const entries = [];
  for (const fn of functions) {
    const context = lines.slice(Math.max(0, fn.line - 8), fn.line).join(" ");
    const methodMatch = context.match(/\[Http(Get|Post|Put|Delete|Patch|Options)(?:\s*\(\s*["']([^"']*)["'])?/i);
    const routeMatch = context.match(/\[Route\s*\(\s*["']([^"']+)["']/i);
    if (!methodMatch && !routeMatch) continue;
    entries.push(entry(methodMatch ? methodMatch[1].toUpperCase() : "ANY", methodMatch?.[2] || routeMatch?.[1] || fn.name, fn.line, fn));
  }
  return entries;
}

function findGoEntries(lines, functions) {
  const entries = [];
  lines.forEach((code, index) => {
    const direct = code.match(/\b(?:http\.)?HandleFunc\s*\(\s*["']([^"']+)["']\s*,\s*([A-Za-z_]\w*)/);
    const router = code.match(/\b\w+\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|Any|HandleFunc)\s*\(\s*["']([^"']+)["']\s*,\s*([A-Za-z_]\w*)/);
    if (direct) {
      const fn = functions.find(candidate => candidate.name === direct[2]);
      entries.push(entry("REQUEST", direct[1], fn?.line || index + 1, fn));
    } else if (router) {
      const fn = functions.find(candidate => candidate.name === router[3]);
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
  return { title: `${method} ${route}`, method, route, line, endLine: fn?.endLine || line, functionLine: fn?.line, functionName: fn?.name };
}

function containingFunction(functions, line) {
  return functions.find(fn => line >= fn.line && line <= fn.endLine);
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

function makeAuditItem(input) {
  const sources = input.signals.filter(signal => signal.kind === "source");
  const sinks = input.signals.filter(signal => signal.kind === "sink");
  const auth = input.signals.filter(signal => signal.kind === "auth");
  const sanitizers = input.signals.filter(signal => signal.kind === "sanitizer");
  const categories = [...new Set(sinks.map(signal => signal.category))];
  let score = input.kind === "endpoint" ? 18 : 5;
  score += Math.min(16, sources.length * 4) + Math.min(27, sinks.length * 9);
  if (sources.length && sinks.some(signal => ["command", "expression", "deserialization"].includes(signal.category))) score += 10;
  if (input.kind === "endpoint" && sinks.length && !auth.length) score += 10;
  if (sources.length && sinks.length && !sanitizers.length) score += 8;
  if (input.sensitivePath) score += 5;
  const priority = score >= 50 ? "P0" : score >= 32 ? "P1" : "P2";
  const reasons = [];
  if (input.kind === "endpoint") reasons.push("Externally reachable entry point");
  if (sources.length) reasons.push(`${sources.length} untrusted input signal${sources.length > 1 ? "s" : ""}`);
  if (sinks.length) reasons.push(`${sinks.length} sensitive operation${sinks.length > 1 ? "s" : ""}: ${categories.join(", ")}`);
  if (input.kind === "endpoint" && !auth.length) reasons.push("No obvious authorization decision in local scope");
  if (sources.length && sinks.length && !sanitizers.length) reasons.push("No obvious validation or encoding signal in local scope");
  if (input.sensitivePath) reasons.push("Security-sensitive file or function name");
  return {
    id: shortHash(`${input.relativePath}:${input.line}:${input.kind}:${input.functionName}`),
    ...input,
    score,
    priority,
    reasons,
    categories,
    counts: { sources: sources.length, sinks: sinks.length, auth: auth.length, sanitizers: sanitizers.length },
    checklist: buildChecklist({ sources, sinks, auth, sanitizers }),
  };
}

function buildChecklist(groups) {
  return [
    { id: "boundary", label: "Identify caller, trust boundary and expected input", state: groups.sources.length ? "inspect" : "unknown", evidence: `${groups.sources.length} input signal(s)` },
    { id: "authentication", label: "Confirm authentication is required and enforced", state: groups.auth.length ? "observed" : "inspect", evidence: groups.auth[0]?.label || "No local authentication signal" },
    { id: "authorization", label: "Verify object- and action-level authorization", state: "inspect", evidence: "Requires reviewer confirmation" },
    { id: "validation", label: "Trace validation, canonicalization and output encoding", state: groups.sanitizers.length ? "observed" : "inspect", evidence: groups.sanitizers[0]?.label || "No local validation signal" },
    { id: "sinks", label: "Trace every sensitive operation back to its source", state: groups.sinks.length ? "inspect" : "unknown", evidence: `${groups.sinks.length} sensitive operation(s)` },
    { id: "failure", label: "Review failure paths, logging and sensitive data exposure", state: "inspect", evidence: "Manual review required" },
  ];
}

function buildAuditModel(analyses) {
  const items = analyses.flatMap(analysis => analysis.items).sort((a, b) => priorityNumber(a.priority) - priorityNumber(b.priority) || b.score - a.score || a.relativePath.localeCompare(b.relativePath));
  const entries = analyses.flatMap(analysis => analysis.entries.map(item => ({ ...item, absolutePath: analysis.absolutePath, relativePath: analysis.relativePath, language: analysis.language })));
  const signals = analyses.flatMap(analysis => analysis.signals);
  return {
    indexed_at: new Date().toISOString(),
    files: analyses.length,
    lines: analyses.reduce((total, analysis) => total + analysis.lines, 0),
    functions: analyses.reduce((total, analysis) => total + analysis.functions.length, 0),
    entries,
    signals,
    items,
    languages: analyses.reduce((counts, analysis) => ({ ...counts, [analysis.language]: (counts[analysis.language] || 0) + 1 }), {}),
  };
}

function priorityNumber(priority) {
  return { P0: 0, P1: 1, P2: 2 }[priority] ?? 3;
}

function shortHash(value) {
  return crypto.createHash("sha1").update(value).digest("hex").slice(0, 16);
}

module.exports = { SIGNAL_PATTERNS, analyzeText, buildAuditModel, collectSignals, findEntries, findFunctions, shortHash, traceIdentifier };
