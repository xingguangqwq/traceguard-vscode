"use strict";

const { GuardCapability, SinkKind, SourceKind, sourceExposureForKind } = require("./semantics");
const { argumentConstraintRejection } = require("./argument-constraints");
const { SYNTAX_SEMANTIC_MODELS } = require("./syntax-models");
const { SUPPLEMENTAL_SEMANTIC_MODELS } = require("./supplemental-models");
const { COLLECTION_SEMANTIC_MODELS } = require("./collection-models");
const { compileCatalogPatterns: compilePatterns } = require("./catalog-pattern-compiler");

const SemanticRole = Object.freeze({
  SOURCE: "source",
  SINK: "sink",
  PROPAGATOR: "propagator",
  GUARD: "guard",
});

const SEMANTIC_MODELS = Object.freeze([
  sourceModel({
    id: "javascript.deno.environment",
    languages: ["javascript", "typescript"],
    moduleNames: [],
    qualifiedNames: ["Deno.env.get"],
    receiverTypes: ["Deno.Env"],
    callNames: ["get"],
    taintArguments: [],
    sourceKind: SourceKind.PROCESS_INPUT,
    callForms: ["global-member"],
  }),
  sinkModel({
    id: "node.child_process.command",
    languages: ["javascript", "typescript"],
    moduleNames: ["child_process", "node:child_process"],
    qualifiedNames: ["child_process.exec", "child_process.execSync"],
    callNames: ["exec", "execSync"],
    taintArguments: [0],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["named-import", "namespace-import", "default-import-member", "require-destructure", "require-member"],
    fallbackByCallName: true,
  }),
  sinkModel({
    id: "node.child_process.spawn",
    languages: ["javascript", "typescript"],
    moduleNames: ["child_process", "node:child_process"],
    qualifiedNames: ["child_process.spawn", "child_process.spawnSync", "child_process.fork"],
    callNames: ["spawn", "spawnSync", "fork"],
    taintArguments: [0, 1],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["named-import", "namespace-import", "default-import-member", "require-destructure", "require-member"],
    fallbackByCallName: true,
  }),
  sinkModel({
    id: "node.fs.file-access",
    languages: ["javascript", "typescript"],
    moduleNames: ["fs", "node:fs", "fs/promises", "node:fs/promises"],
    qualifiedNames: ["fs.readFile", "fs.writeFile", "fs.appendFile", "fs.unlink", "fs.createReadStream", "fs.createWriteStream"],
    callNames: ["readFile", "writeFile", "appendFile", "unlink", "createReadStream", "createWriteStream"],
    taintArguments: [0],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["named-import", "namespace-import", "default-import-member", "require-destructure", "require-member"],
  }),
  sinkModel({
    id: "node.fs.path-transfer",
    languages: ["javascript", "typescript"],
    moduleNames: ["fs", "node:fs", "fs/promises", "node:fs/promises"],
    qualifiedNames: ["fs.rename", "fs.copyFile"],
    callNames: ["rename", "copyFile"],
    taintArguments: [0, 1],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["named-import", "namespace-import", "default-import-member", "require-destructure", "require-member"],
  }),
  sinkModel({
    id: "web.fetch.request",
    languages: ["javascript", "typescript"],
    moduleNames: [],
    qualifiedNames: ["global.fetch", "fetch"],
    callNames: ["fetch"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["global"],
    global: true,
  }),
  sinkModel({
    id: "node.http.request",
    languages: ["javascript", "typescript"],
    moduleNames: ["http", "node:http", "https", "node:https"],
    qualifiedNames: ["http.get", "http.request", "https.get", "https.request"],
    receiverTypes: [],
    callNames: ["get", "request"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["named-import", "namespace-import", "default-import-member", "require-member"],
    requiresModuleIdentity: true,
  }),
  propagatorModel({
    id: "javascript.global.string-conversion",
    languages: ["javascript", "typescript"],
    moduleNames: [],
    qualifiedNames: ["global.String", "global.decodeURIComponent", "global.encodeURIComponent"],
    callNames: ["String", "decodeURIComponent", "encodeURIComponent"],
    taintArguments: [0],
    callForms: ["global"],
    global: true,
  }),
  sourceModel({
    id: "php.framework.request-input",
    languages: ["php"],
    moduleNames: ["Illuminate\\Http", "Symfony\\Component\\HttpFoundation"],
    qualifiedNames: ["Request.input", "Request.get", "Request.query", "Request.post", "ParameterBag.get", "InputBag.get"],
    receiverTypes: ["Request", "Illuminate\\Http\\Request", "Symfony\\Component\\HttpFoundation\\Request", "ParameterBag", "InputBag"],
    callNames: ["input", "get", "query", "post", "string", "integer", "boolean"],
    taintArguments: [],
    sourceKind: SourceKind.HTTP_INPUT,
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
    patternCallNames: ["input", "get", "post", "string", "integer", "boolean"],
  }),
  sinkModel({
    id: "php.pdo.dynamic-query",
    languages: ["php"],
    moduleNames: ["PDO"],
    qualifiedNames: ["PDO.query", "PDO.exec", "PDO.prepare"],
    receiverTypes: ["PDO"],
    callNames: ["query", "exec", "prepare"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
  }),
  sinkModel({
    id: "php.laravel.dynamic-query",
    languages: ["php"],
    moduleNames: ["Illuminate\\Support\\Facades\\DB", "Illuminate\\Database"],
    qualifiedNames: ["DB.select", "DB.statement", "DB.unprepared", "Builder.selectRaw", "Builder.whereRaw", "Builder.orderByRaw", "Builder.havingRaw"],
    receiverTypes: ["DB", "Connection", "Builder", "Eloquent\\Builder"],
    callNames: ["select", "statement", "unprepared", "selectRaw", "whereRaw", "orderByRaw", "havingRaw"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["static-method", "instance-method"],
    patternReceiverAgnostic: true,
  }),
  sinkModel({
    id: "php.runtime.command",
    languages: ["php"],
    moduleNames: [],
    qualifiedNames: ["system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"],
    receiverTypes: [],
    callNames: ["system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"],
    taintArguments: [0],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["function"],
    global: true,
  }),
  sinkModel({
    id: "php.mysqli.dynamic-query",
    languages: ["php"],
    moduleNames: ["mysqli"],
    qualifiedNames: ["mysqli.query", "mysqli.real_query", "mysqli.multi_query"],
    receiverTypes: ["mysqli"],
    callNames: ["query", "real_query", "multi_query"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
  }),
  sinkModel({
    id: "php.mysqli.procedural-query",
    languages: ["php"],
    moduleNames: [],
    qualifiedNames: ["mysqli_query", "mysqli_real_query", "mysqli_multi_query"],
    receiverTypes: [],
    callNames: ["mysqli_query", "mysqli_real_query", "mysqli_multi_query"],
    taintArguments: [1],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["function"],
    global: true,
  }),
  sinkModel({
    id: "php.filesystem.access",
    languages: ["php"],
    moduleNames: [],
    qualifiedNames: ["file_get_contents", "file_put_contents", "readfile", "fopen", "unlink", "mkdir", "rmdir"],
    receiverTypes: [],
    callNames: ["file_get_contents", "file_put_contents", "readfile", "fopen", "unlink", "mkdir", "rmdir"],
    taintArguments: [0],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["function"],
    global: true,
  }),
  sinkModel({
    id: "php.filesystem.transfer",
    languages: ["php"],
    moduleNames: [],
    qualifiedNames: ["copy", "rename"],
    receiverTypes: [],
    callNames: ["copy", "rename"],
    taintArguments: [0, 1],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["function"],
    global: true,
  }),
  sinkModel({
    id: "php.filesystem.upload-target",
    languages: ["php"],
    moduleNames: [],
    qualifiedNames: ["move_uploaded_file"],
    receiverTypes: [],
    callNames: ["move_uploaded_file"],
    taintArguments: [1],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["function"],
    global: true,
  }),
  sinkModel({
    id: "php.runtime.unserialize",
    languages: ["php"],
    moduleNames: [],
    qualifiedNames: ["unserialize"],
    receiverTypes: [],
    callNames: ["unserialize"],
    taintArguments: [0],
    sinkKind: SinkKind.DESERIALIZATION,
    category: "deserialization",
    callForms: ["function"],
    global: true,
    rejectWhen: [{
      when: { argument: { index: 1, pattern: `["']allowed_classes["']\\s*=>\\s*(?:false|\\[\\s*\\])`, flags: "i" } },
      reason: "unserialize explicitly disables object construction with allowed_classes.",
    }],
  }),
  sinkModel({
    id: "php.curl.request",
    languages: ["php"],
    moduleNames: [],
    qualifiedNames: ["curl_init"],
    receiverTypes: [],
    callNames: ["curl_init"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["function"],
    global: true,
    requiredArguments: [{ index: 0, reason: "The call creates a handle without a request target." }],
  }),
  sinkModel({
    id: "php.guzzle.verb-request",
    languages: ["php"],
    moduleNames: ["GuzzleHttp\\Client", "GuzzleHttp\\ClientInterface"],
    qualifiedNames: ["GuzzleHttp\\Client.get", "GuzzleHttp\\Client.post", "GuzzleHttp\\ClientInterface.get"],
    receiverTypes: ["GuzzleHttp\\Client", "GuzzleHttp\\ClientInterface", "Client", "ClientInterface"],
    callNames: ["get", "post", "put", "patch", "delete", "head", "options"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["instance-method"],
    requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "php.guzzle.generic-request",
    languages: ["php"],
    moduleNames: ["GuzzleHttp\\Client", "GuzzleHttp\\ClientInterface"],
    qualifiedNames: ["GuzzleHttp\\Client.request", "GuzzleHttp\\ClientInterface.request"],
    receiverTypes: ["GuzzleHttp\\Client", "GuzzleHttp\\ClientInterface", "Client", "ClientInterface"],
    callNames: ["request", "requestAsync"],
    taintArguments: [1],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["instance-method"],
    requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "php.laravel.http-verb-request",
    languages: ["php"],
    moduleNames: ["Illuminate\\Support\\Facades\\Http", "Illuminate\\Http\\Client"],
    qualifiedNames: ["Illuminate\\Support\\Facades\\Http.get", "Illuminate\\Support\\Facades\\Http.post", "Http.get", "Http.post", "PendingRequest.get", "PendingRequest.post"],
    receiverTypes: ["Illuminate\\Support\\Facades\\Http", "Illuminate\\Http\\Client\\PendingRequest", "Http", "PendingRequest"],
    callNames: ["get", "post", "put", "patch", "delete", "head", "send"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["static-method", "instance-method"],
  }),
  sinkModel({
    id: "php.laravel.http-generic-request",
    languages: ["php"],
    moduleNames: ["Illuminate\\Support\\Facades\\Http", "Illuminate\\Http\\Client"],
    qualifiedNames: ["Illuminate\\Support\\Facades\\Http.request", "Http.request", "PendingRequest.request"],
    receiverTypes: ["Illuminate\\Support\\Facades\\Http", "Illuminate\\Http\\Client\\PendingRequest", "Http", "PendingRequest"],
    callNames: ["request"],
    taintArguments: [1],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["static-method", "instance-method"],
  }),
  sinkModel({
    id: "php.symfony.http-client-request",
    languages: ["php"],
    moduleNames: ["Symfony\\Contracts\\HttpClient", "Symfony\\Component\\HttpClient"],
    qualifiedNames: ["Symfony\\Contracts\\HttpClient\\HttpClientInterface.request", "Symfony\\Component\\HttpClient\\HttpClient.request", "HttpClientInterface.request", "HttpClient.request"],
    receiverTypes: ["Symfony\\Contracts\\HttpClient\\HttpClientInterface", "Symfony\\Component\\HttpClient\\HttpClient", "HttpClientInterface", "HttpClient"],
    callNames: ["request"],
    taintArguments: [1],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "python.os.command",
    languages: ["python"],
    moduleNames: ["os"],
    qualifiedNames: ["os.system", "os.popen"],
    receiverTypes: [],
    callNames: ["system", "popen"],
    taintArguments: [0],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["module-function"],
  }),
  sinkModel({
    id: "python.subprocess.command",
    languages: ["python"],
    moduleNames: ["subprocess"],
    qualifiedNames: ["subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "subprocess.check_call"],
    receiverTypes: [],
    callNames: ["run", "Popen", "call", "check_output", "check_call"],
    taintArguments: [0],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["module-function"],
    rejectWhen: [{
      when: {
        all: [
          { argument: { index: 0, pattern: `^[[(]\\s*(?:[rubf]{0,2})?["']`, flags: "i" } },
          { not: { anyArgument: { pattern: "^shell\\s*=\\s*true$", flags: "i" } } },
        ],
      },
      reason: "A constant executable is invoked through an argv list with shell expansion disabled.",
    }],
  }),
  sinkModel({
    id: "python.dbapi.dynamic-query",
    languages: ["python"],
    moduleNames: ["sqlite3", "aiosqlite", "psycopg", "psycopg2", "pymysql", "mysqldb", "asyncpg", "sqlalchemy", "sqlalchemy.orm", "sqlalchemy.ext.asyncio", "django.db"],
    qualifiedNames: ["Cursor.execute", "Cursor.executemany", "Connection.execute", "Session.execute"],
    receiverTypes: ["Cursor", "Connection", "Session", "AsyncSession"],
    callNames: ["execute", "executemany"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
    requiresModuleIdentity: true,
    patternReceiverAgnostic: true,
  }),
  sinkModel({
    id: "python.django.raw-query",
    languages: ["python"],
    moduleNames: ["django.db", "django.db.models"],
    qualifiedNames: ["django.db.models.QuerySet.raw", "django.db.models.RawQuerySet.raw", "django.db.models.Manager.raw"],
    receiverTypes: ["django.db.models.QuerySet", "django.db.models.RawQuerySet", "django.db.models.Manager", "QuerySet", "RawQuerySet", "Manager"],
    callNames: ["raw"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
    requiresModuleIdentity: true,
    patternReceiverAgnostic: true,
  }),
  sinkModel({
    id: "python.http.request",
    languages: ["python"],
    moduleNames: ["requests", "httpx", "urllib.request", "aiohttp"],
    qualifiedNames: ["requests.get", "requests.post", "httpx.get", "httpx.post", "httpx.AsyncClient.get", "urllib.request.urlopen", "aiohttp.ClientSession.get"],
    receiverTypes: ["Session", "Client", "AsyncClient", "ClientSession"],
    callNames: ["get", "post", "put", "patch", "delete", "head", "options", "urlopen"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["module-function", "instance-method"],
    requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "python.http.generic-request",
    languages: ["python"],
    moduleNames: ["requests", "httpx", "aiohttp"],
    qualifiedNames: ["requests.request", "httpx.request", "httpx.Client.request", "httpx.AsyncClient.request", "aiohttp.ClientSession.request"],
    receiverTypes: ["Session", "Client", "AsyncClient", "ClientSession"],
    callNames: ["request"],
    taintArguments: [1],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["module-function", "instance-method"],
    requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "python.filesystem.open",
    languages: ["python"],
    moduleNames: ["builtins"],
    qualifiedNames: ["open", "builtins.open"],
    receiverTypes: [],
    callNames: ["open"],
    taintArguments: [0],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["global"],
    global: true,
  }),
  sinkModel({
    id: "python.os.filesystem-access",
    languages: ["python"],
    moduleNames: ["os"],
    qualifiedNames: ["os.remove", "os.unlink", "os.mkdir", "os.rmdir", "os.listdir", "os.scandir"],
    receiverTypes: [],
    callNames: ["remove", "unlink", "mkdir", "rmdir", "listdir", "scandir"],
    taintArguments: [0],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["module-function"],
    requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "python.os.filesystem-transfer",
    languages: ["python"],
    moduleNames: ["os"],
    qualifiedNames: ["os.rename", "os.replace"],
    receiverTypes: [],
    callNames: ["rename", "replace"],
    taintArguments: [0, 1],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["module-function"],
    requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "python.pathlib.access",
    languages: ["python"],
    moduleNames: ["pathlib"],
    qualifiedNames: ["pathlib.Path.read_text", "pathlib.Path.write_text", "pathlib.Path.read_bytes", "pathlib.Path.write_bytes", "pathlib.Path.unlink", "pathlib.Path.open"],
    receiverTypes: ["pathlib.Path", "Path"],
    callNames: ["read_text", "write_text", "read_bytes", "write_bytes", "unlink", "open"],
    taintArguments: [],
    taintReceiver: true,
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["instance-method"],
    requiresModuleIdentity: true,
  }),
  sinkModel({
    id: "python.pathlib.transfer",
    languages: ["python"],
    moduleNames: ["pathlib"],
    qualifiedNames: ["pathlib.Path.rename", "pathlib.Path.replace"],
    receiverTypes: ["pathlib.Path", "Path"],
    callNames: ["rename", "replace"],
    taintArguments: [0],
    taintReceiver: true,
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["instance-method"],
    requiresModuleIdentity: true,
  }),
  propagatorModel({
    id: "python.pathlib.construct",
    languages: ["python"],
    moduleNames: ["pathlib"],
    qualifiedNames: ["pathlib.Path", "Path"],
    receiverTypes: ["pathlib.Path", "Path"],
    callNames: ["Path"],
    taintArguments: [],
    taintRestFrom: 0,
    callForms: ["constructor", "function"],
    requiresModuleIdentity: true,
  }),
  propagatorModel({
    id: "node.path.value-propagation",
    languages: ["javascript", "typescript"],
    moduleNames: ["path", "node:path", "path/posix", "path/win32"],
    qualifiedNames: ["path.join", "path.resolve", "path.normalize", "path.basename"],
    callNames: ["join", "resolve", "normalize", "basename"],
    taintArguments: [],
    taintRestFrom: 0,
    callForms: ["named-import", "namespace-import", "default-import-member", "require-member"],
  }),
  sinkModel({
    id: "java.lang.Runtime.exec",
    languages: ["java"],
    moduleNames: ["java.lang"],
    qualifiedNames: ["java.lang.Runtime.exec", "Runtime.exec", "java.lang.Runtime.getRuntime().exec", "Runtime.getRuntime().exec"],
    receiverTypes: ["java.lang.Runtime", "Runtime"],
    callNames: ["exec"],
    taintArguments: [0, 1],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
  }),
  sinkModel({
    id: "java.lang.ProcessBuilder.command",
    languages: ["java"],
    moduleNames: ["java.lang"],
    qualifiedNames: ["java.lang.ProcessBuilder", "ProcessBuilder"],
    receiverTypes: ["java.lang.ProcessBuilder", "ProcessBuilder"],
    callNames: ["ProcessBuilder", "command"],
    taintArguments: [],
    taintRestFrom: 0,
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["constructor", "instance-method"],
    rejectWhen: [{
      when: {
        all: [
          { argumentCountAtLeast: 2 },
          { argument: { index: 0, literalValue: true } },
          { any: [
            { argument: { index: 0, literalValue: true, pattern: "^(?!(?:ba|z|k|c|da)?sh$|cmd(?:\\.exe)?$|powershell(?:\\.exe)?$|pwsh$)", flags: "i" } },
            { not: { anyArgument: { fromIndex: 1, pattern: `^\\s*["'](?:-c|/c|-command)["']\\s*$`, flags: "i" } } },
          ] },
        ],
      },
      reason: "A constant executable receives argv elements without a shell command string.",
    }],
  }),
  sinkModel({
    id: "java.nio.file.Files.access",
    languages: ["java"],
    moduleNames: ["java.nio.file.Files"],
    qualifiedNames: ["java.nio.file.Files.readString", "java.nio.file.Files.readAllBytes", "java.nio.file.Files.writeString", "java.nio.file.Files.delete", "java.nio.file.Files.newInputStream", "java.nio.file.Files.newOutputStream"],
    receiverTypes: ["java.nio.file.Files", "Files"],
    callNames: ["readString", "readAllBytes", "readAllLines", "writeString", "write", "delete", "deleteIfExists", "newInputStream", "newOutputStream", "list", "walk"],
    taintArguments: [0],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["static-method"],
  }),
  propagatorModel({
    id: "java.net.URLDecoder.decode",
    languages: ["java"],
    moduleNames: ["java.net.URLDecoder"],
    qualifiedNames: ["java.net.URLDecoder.decode", "URLDecoder.decode"],
    receiverTypes: ["java.net.URLDecoder", "URLDecoder"],
    callNames: ["decode"],
    taintArguments: [0],
    callForms: ["static-method"],
  }),
  sourceModel({
    id: "java.servlet.request-input",
    languages: ["java"],
    moduleNames: ["jakarta.servlet.http.HttpServletRequest", "javax.servlet.http.HttpServletRequest"],
    qualifiedNames: [
      "jakarta.servlet.http.HttpServletRequest.getParameter", "javax.servlet.http.HttpServletRequest.getParameter",
      "jakarta.servlet.http.HttpServletRequest.getHeader", "javax.servlet.http.HttpServletRequest.getHeader",
      "jakarta.servlet.http.HttpServletRequest.getCookies", "javax.servlet.http.HttpServletRequest.getCookies",
      "jakarta.servlet.http.HttpServletRequest.getQueryString", "javax.servlet.http.HttpServletRequest.getQueryString",
      "jakarta.servlet.http.HttpServletRequest.getInputStream", "javax.servlet.http.HttpServletRequest.getInputStream",
      "jakarta.servlet.http.HttpServletRequest.getReader", "javax.servlet.http.HttpServletRequest.getReader",
      "jakarta.servlet.http.HttpServletRequest.getPathInfo", "javax.servlet.http.HttpServletRequest.getPathInfo",
      "jakarta.servlet.http.HttpServletRequest.getRequestURI", "javax.servlet.http.HttpServletRequest.getRequestURI",
    ],
    receiverTypes: ["jakarta.servlet.http.HttpServletRequest", "javax.servlet.http.HttpServletRequest", "HttpServletRequest"],
    callNames: ["getParameter", "getHeader", "getCookies", "getQueryString", "getInputStream", "getReader", "getPathInfo", "getRequestURI"],
    taintArguments: [],
    sourceKind: SourceKind.HTTP_INPUT,
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
  }),
  propagatorModel({
    id: "spring.multipart.filename",
    languages: ["java"],
    moduleNames: ["org.springframework.web.multipart.MultipartFile"],
    qualifiedNames: ["org.springframework.web.multipart.MultipartFile.getOriginalFilename", "MultipartFile.getOriginalFilename"],
    receiverTypes: ["org.springframework.web.multipart.MultipartFile", "MultipartFile"],
    callNames: ["getOriginalFilename"],
    taintReceiver: true,
    returnType: "java.lang.String",
    callForms: ["instance-method"],
  }),
  propagatorModel({
    id: "java.nio.file.Path.resolve",
    languages: ["java"],
    moduleNames: ["java.nio.file.Path"],
    qualifiedNames: ["java.nio.file.Path.resolve", "Path.resolve"],
    receiverTypes: ["java.nio.file.Path", "Path"],
    callNames: ["resolve"],
    taintArguments: [0],
    taintReceiver: true,
    returnType: "java.nio.file.Path",
    callForms: ["instance-method"],
  }),
  propagatorModel({
    id: "java.nio.file.Files.createTempDirectory",
    languages: ["java"],
    moduleNames: ["java.nio.file.Files"],
    qualifiedNames: ["java.nio.file.Files.createTempDirectory", "Files.createTempDirectory"],
    receiverTypes: ["java.nio.file.Files", "Files"],
    callNames: ["createTempDirectory"],
    taintArguments: [0],
    returnType: "java.nio.file.Path",
    callForms: ["static-method"],
  }),
  propagatorModel({
    id: "java.nio.file.Path.toFile",
    languages: ["java"],
    moduleNames: ["java.nio.file.Path"],
    qualifiedNames: ["java.nio.file.Path.toFile", "Path.toFile"],
    receiverTypes: ["java.nio.file.Path", "Path"],
    callNames: ["toFile"],
    taintReceiver: true,
    returnType: "java.io.File",
    callForms: ["instance-method"],
  }),
  propagatorModel({
    id: "java.io.File.construct",
    languages: ["java"],
    moduleNames: ["java.io.File"],
    qualifiedNames: ["java.io.File", "File"],
    receiverTypes: ["java.io.File", "File"],
    callNames: ["File"],
    taintArguments: [0, 1],
    returnType: "java.io.File",
    callForms: ["constructor"],
  }),
  propagatorModel({
    id: "java.util.zip.ZipFile.construct",
    languages: ["java"],
    moduleNames: ["java.util.zip.ZipFile"],
    qualifiedNames: ["java.util.zip.ZipFile", "ZipFile"],
    receiverTypes: ["java.util.zip.ZipFile", "ZipFile"],
    callNames: ["ZipFile"],
    taintArguments: [0],
    returnType: "java.util.zip.ZipFile",
    callForms: ["constructor"],
  }),
  propagatorModel({
    id: "java.util.zip.ZipFile.entries",
    languages: ["java"],
    moduleNames: ["java.util.zip.ZipFile"],
    qualifiedNames: ["java.util.zip.ZipFile.entries", "ZipFile.entries"],
    receiverTypes: ["java.util.zip.ZipFile", "ZipFile"],
    callNames: ["entries"],
    taintReceiver: true,
    returnType: "java.util.Enumeration",
    callForms: ["instance-method"],
  }),
  propagatorModel({
    id: "java.util.Enumeration.nextElement",
    languages: ["java"],
    moduleNames: ["java.util.Enumeration"],
    qualifiedNames: ["java.util.Enumeration.nextElement", "Enumeration.nextElement"],
    receiverTypes: ["java.util.Enumeration", "Enumeration"],
    callNames: ["nextElement"],
    taintReceiver: true,
    callForms: ["instance-method"],
  }),
  propagatorModel({
    id: "java.util.zip.ZipEntry.name",
    languages: ["java"],
    moduleNames: ["java.util.zip.ZipEntry"],
    qualifiedNames: ["java.util.zip.ZipEntry.getName", "ZipEntry.getName"],
    receiverTypes: ["java.util.zip.ZipEntry", "ZipEntry"],
    callNames: ["getName"],
    taintReceiver: true,
    returnType: "java.lang.String",
    callForms: ["instance-method"],
  }),
  propagatorModel({
    id: "java.util.zip.ZipFile.input-stream",
    languages: ["java"],
    moduleNames: ["java.util.zip.ZipFile"],
    qualifiedNames: ["java.util.zip.ZipFile.getInputStream", "ZipFile.getInputStream"],
    receiverTypes: ["java.util.zip.ZipFile", "ZipFile"],
    callNames: ["getInputStream"],
    taintArguments: [0],
    taintReceiver: true,
    returnType: "java.io.InputStream",
    callForms: ["instance-method"],
  }),
  propagatorModel({
    id: "java.net.URL.construct",
    languages: ["java"],
    moduleNames: ["java.net.URL"],
    qualifiedNames: ["java.net.URL", "URL"],
    receiverTypes: ["java.net.URL", "URL"],
    callNames: ["URL"],
    taintArguments: [0],
    returnType: "java.net.URL",
    callForms: ["constructor"],
  }),
  propagatorModel({
    id: "java.nio.file.Path.construct",
    languages: ["java"],
    moduleNames: ["java.nio.file.Path", "java.nio.file.Paths"],
    qualifiedNames: ["java.nio.file.Path.of", "java.nio.file.Paths.get", "Path.of", "Paths.get"],
    receiverTypes: ["java.nio.file.Path", "java.nio.file.Paths", "Path", "Paths"],
    callNames: ["of", "get"],
    taintArguments: [],
    taintRestFrom: 0,
    callForms: ["static-method"],
  }),
  sinkModel({
    id: "java.nio.file.Files.transfer",
    languages: ["java"],
    moduleNames: ["java.nio.file.Files"],
    qualifiedNames: ["java.nio.file.Files.copy", "java.nio.file.Files.move"],
    receiverTypes: ["java.nio.file.Files", "Files"],
    callNames: ["copy", "move"],
    taintArguments: [0, 1],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["static-method"],
  }),
  sinkModel({
    id: "java.io.file-stream",
    languages: ["java"],
    moduleNames: ["java.io.FileInputStream", "java.io.FileOutputStream", "java.io.RandomAccessFile"],
    qualifiedNames: ["java.io.FileInputStream", "java.io.FileOutputStream", "java.io.RandomAccessFile", "FileInputStream", "FileOutputStream", "RandomAccessFile"],
    receiverTypes: ["java.io.FileInputStream", "java.io.FileOutputStream", "java.io.RandomAccessFile", "FileInputStream", "FileOutputStream", "RandomAccessFile"],
    callNames: ["FileInputStream", "FileOutputStream", "RandomAccessFile"],
    taintArguments: [0],
    sinkKind: SinkKind.FILE_ACCESS,
    category: "file",
    callForms: ["constructor"],
  }),
  sinkModel({
    id: "java.io.ObjectInputStream.deserialize",
    languages: ["java"],
    moduleNames: ["java.io.ObjectInputStream", "java.beans.XMLDecoder"],
    qualifiedNames: ["java.io.ObjectInputStream.readObject", "java.beans.XMLDecoder.readObject", "ObjectInputStream.readObject", "XMLDecoder.readObject"],
    receiverTypes: ["java.io.ObjectInputStream", "java.beans.XMLDecoder", "ObjectInputStream", "XMLDecoder"],
    callNames: ["readObject"],
    taintArguments: [],
    taintReceiver: true,
    sinkKind: SinkKind.DESERIALIZATION,
    category: "deserialization",
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
  }),
  sinkModel({
    id: "java.commons.SerializationUtils.deserialize",
    languages: ["java"],
    moduleNames: ["org.apache.commons.lang3.SerializationUtils"],
    qualifiedNames: ["org.apache.commons.lang3.SerializationUtils.deserialize", "SerializationUtils.deserialize"],
    receiverTypes: ["org.apache.commons.lang3.SerializationUtils", "SerializationUtils"],
    callNames: ["deserialize"],
    taintArguments: [0],
    sinkKind: SinkKind.DESERIALIZATION,
    category: "deserialization",
    callForms: ["static-method"],
  }),
  sinkModel({
    id: "java.net.URL.request",
    languages: ["java"],
    moduleNames: ["java.net.URL"],
    qualifiedNames: ["java.net.URL.openConnection", "java.net.URL.openStream", "URL.openConnection", "URL.openStream"],
    receiverTypes: ["java.net.URL", "URL"],
    callNames: ["openConnection", "openStream"],
    taintArguments: [],
    taintReceiver: true,
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["instance-method"],
  }),
  propagatorModel({
    id: "auth0.jwt.decode",
    languages: ["java"],
    moduleNames: ["com.auth0.jwt.JWT"],
    qualifiedNames: ["com.auth0.jwt.JWT.decode", "JWT.decode"],
    receiverTypes: ["com.auth0.jwt.JWT", "JWT"],
    callNames: ["decode"],
    taintArguments: [0],
    returnType: "com.auth0.jwt.interfaces.DecodedJWT",
    callForms: ["static-method"],
  }),
  propagatorModel({
    id: "auth0.jwt.header-claim",
    languages: ["java"],
    moduleNames: ["com.auth0.jwt.interfaces.DecodedJWT"],
    qualifiedNames: ["com.auth0.jwt.interfaces.DecodedJWT.getHeaderClaim", "DecodedJWT.getHeaderClaim"],
    receiverTypes: ["com.auth0.jwt.interfaces.DecodedJWT", "DecodedJWT"],
    callNames: ["getHeaderClaim"],
    taintReceiver: true,
    returnType: "com.auth0.jwt.interfaces.Claim",
    callForms: ["instance-method"],
  }),
  propagatorModel({
    id: "auth0.jwt.claim-string",
    languages: ["java"],
    moduleNames: ["com.auth0.jwt.interfaces.Claim"],
    qualifiedNames: ["com.auth0.jwt.interfaces.Claim.asString", "Claim.asString"],
    receiverTypes: ["com.auth0.jwt.interfaces.Claim", "Claim"],
    callNames: ["asString"],
    taintReceiver: true,
    returnType: "java.lang.String",
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "auth0.jwk.remote-provider",
    languages: ["java"],
    moduleNames: ["com.auth0.jwk.JwkProviderBuilder"],
    qualifiedNames: ["com.auth0.jwk.JwkProviderBuilder", "JwkProviderBuilder"],
    receiverTypes: ["com.auth0.jwk.JwkProviderBuilder", "JwkProviderBuilder"],
    callNames: ["JwkProviderBuilder"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["constructor"],
  }),
  sinkModel({
    id: "java.net.http.HttpRequest.uri",
    languages: ["java"],
    moduleNames: ["java.net.http.HttpRequest"],
    qualifiedNames: ["java.net.http.HttpRequest.newBuilder", "HttpRequest.newBuilder"],
    receiverTypes: ["java.net.http.HttpRequest", "HttpRequest"],
    callNames: ["newBuilder"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["static-method"],
  }),
  sinkModel({
    id: "python.pickle.deserialize",
    languages: ["python"],
    moduleNames: ["pickle", "_pickle", "dill"],
    qualifiedNames: ["pickle.loads", "pickle.load", "_pickle.loads", "dill.loads", "dill.load"],
    callNames: ["loads", "load"],
    taintArguments: [0],
    sinkKind: SinkKind.DESERIALIZATION,
    category: "deserialization",
    callForms: ["module-function"],
  }),
  sinkModel({
    id: "python.yaml.deserialize",
    languages: ["python"],
    moduleNames: ["yaml"],
    qualifiedNames: ["yaml.load", "yaml.unsafe_load", "yaml.full_load"],
    callNames: ["load", "unsafe_load", "full_load"],
    taintArguments: [0],
    sinkKind: SinkKind.DESERIALIZATION,
    category: "deserialization",
    callForms: ["module-function"],
    rejectWhen: [{
      when: {
        namedArgument: {
          names: ["Loader", "loader"],
          pattern: "^(?:yaml\\.)?(?:C?SafeLoader)$",
          flags: "i",
        },
      },
      reason: "yaml.load uses an explicitly safe loader.",
    }],
  }),
  sinkModel({
    id: "java.sql.Statement.executeQuery",
    languages: ["java"],
    moduleNames: ["java.sql"],
    qualifiedNames: ["java.sql.Statement.executeQuery", "Statement.executeQuery"],
    receiverTypes: ["java.sql.Statement", "Statement", "java.sql.PreparedStatement", "PreparedStatement"],
    callNames: ["executeQuery", "executeUpdate", "execute"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
  }),
  sinkModel({
    id: "java.sql.Connection.prepareStatement",
    languages: ["java"],
    moduleNames: ["java.sql"],
    qualifiedNames: [
      "java.sql.Connection.prepareStatement", "Connection.prepareStatement",
      "java.sql.Connection.prepareCall", "Connection.prepareCall",
    ],
    receiverTypes: ["java.sql.Connection", "Connection"],
    callNames: ["prepareStatement", "prepareCall"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
  }),
  sinkModel({
    id: "java.persistence.EntityManager.dynamic-query",
    languages: ["java"],
    moduleNames: ["jakarta.persistence", "javax.persistence"],
    qualifiedNames: ["jakarta.persistence.EntityManager.createQuery", "jakarta.persistence.EntityManager.createNativeQuery", "javax.persistence.EntityManager.createQuery", "javax.persistence.EntityManager.createNativeQuery", "EntityManager.createQuery", "EntityManager.createNativeQuery"],
    receiverTypes: ["jakarta.persistence.EntityManager", "javax.persistence.EntityManager", "EntityManager"],
    callNames: ["createQuery", "createNativeQuery"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
  }),
  sinkModel({
    id: "spring.jdbc.JdbcTemplate.dynamic-query",
    languages: ["java"],
    moduleNames: ["org.springframework.jdbc.core"],
    qualifiedNames: ["org.springframework.jdbc.core.JdbcTemplate.query", "org.springframework.jdbc.core.JdbcTemplate.queryForObject", "org.springframework.jdbc.core.JdbcTemplate.queryForLong", "org.springframework.jdbc.core.JdbcTemplate.queryForRowSet", "org.springframework.jdbc.core.JdbcTemplate.queryForList", "org.springframework.jdbc.core.JdbcTemplate.queryForMap", "org.springframework.jdbc.core.JdbcTemplate.update", "org.springframework.jdbc.core.JdbcTemplate.execute", "JdbcTemplate.query", "JdbcTemplate.queryForObject", "JdbcTemplate.queryForLong", "JdbcTemplate.queryForRowSet", "JdbcTemplate.queryForList", "JdbcTemplate.queryForMap", "JdbcTemplate.update", "JdbcTemplate.execute"],
    receiverTypes: ["org.springframework.jdbc.core.JdbcTemplate", "JdbcTemplate", "NamedParameterJdbcTemplate"],
    callNames: ["query", "queryForObject", "queryForLong", "queryForRowSet", "queryForList", "queryForMap", "update", "batchUpdate", "execute"],
    taintArguments: [0],
    sinkKind: SinkKind.SQL_QUERY,
    category: "database",
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
  }),
  sinkModel({
    id: "spring.web.RestTemplate.request",
    languages: ["java"],
    moduleNames: ["org.springframework.web.client"],
    qualifiedNames: ["RestTemplate.getForObject", "RestTemplate.getForEntity", "RestTemplate.postForObject", "RestTemplate.exchange", "RestTemplate.execute"],
    receiverTypes: ["org.springframework.web.client.RestTemplate", "RestTemplate"],
    callNames: ["getForObject", "getForEntity", "postForObject", "postForEntity", "exchange", "execute"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
    patternCallNames: ["getForObject", "getForEntity", "postForObject", "postForEntity", "exchange"],
  }),
  sinkModel({
    id: "spring.web.WebClient.uri",
    languages: ["java"],
    moduleNames: ["org.springframework.web.reactive.function.client"],
    qualifiedNames: ["WebClient.uri", "RequestHeadersUriSpec.uri", "RequestBodyUriSpec.uri"],
    receiverTypes: ["WebClient", "RequestHeadersUriSpec", "RequestBodyUriSpec", "UriSpec"],
    callNames: ["uri"],
    taintArguments: [0],
    sinkKind: SinkKind.HTTP_REQUEST,
    category: "network",
    callForms: ["instance-method"],
  }),
  sinkModel({
    id: "go.os_exec.Command",
    languages: ["go"],
    moduleNames: ["os/exec"],
    qualifiedNames: ["os/exec.Command", "exec.Command"],
    callNames: ["Command"],
    taintArguments: [],
    taintRestFrom: 0,
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["package-function"],
  }),
  sinkModel({
    id: "go.os_exec.CommandContext",
    languages: ["go"],
    moduleNames: ["os/exec"],
    qualifiedNames: ["os/exec.CommandContext", "exec.CommandContext"],
    callNames: ["CommandContext"],
    taintArguments: [],
    taintRestFrom: 1,
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["package-function"],
  }),
  sinkModel({
    id: "dotnet.System.Diagnostics.Process.Start",
    languages: ["csharp"],
    moduleNames: ["System.Diagnostics"],
    qualifiedNames: ["System.Diagnostics.Process.Start", "Process.Start"],
    receiverTypes: ["System.Diagnostics.Process", "Process"],
    callNames: ["Start"],
    taintArguments: [0, 1],
    sinkKind: SinkKind.COMMAND_EXEC,
    category: "command",
    callForms: ["static-method"],
  }),
  guardModel({
    id: "javascript.escape_html.output",
    languages: ["javascript", "typescript"],
    moduleNames: ["escape-html", "html-escaper"],
    qualifiedNames: ["escape-html.escapeHtml", "html-escaper.escape", "html-escaper.escapeHtml"],
    callNames: ["escapeHtml", "escape"],
    taintArguments: [0],
    guardCapabilities: [GuardCapability.OUTPUT_ENCODING],
    applicableSinkKinds: [SinkKind.RESPONSE_OUTPUT],
    callForms: ["default-import", "named-import", "require"],
  }),
  guardModel({
    id: "java.sql.PreparedStatement.bind",
    languages: ["java"],
    moduleNames: ["java.sql"],
    qualifiedNames: ["java.sql.PreparedStatement.setString", "PreparedStatement.setString"],
    receiverTypes: ["java.sql.PreparedStatement", "PreparedStatement"],
    callNames: ["setString", "setInt", "setLong", "setObject"],
    taintArguments: [1],
    guardCapabilities: [GuardCapability.SQL_PARAMETERIZATION],
    applicableSinkKinds: [SinkKind.SQL_QUERY],
    receiverScoped: true,
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
  }),
  guardModel({
    id: "javascript.numeric-conversion",
    languages: ["javascript", "typescript"],
    moduleNames: [],
    qualifiedNames: ["global.Number", "global.parseInt", "global.parseFloat"],
    callNames: ["Number", "parseInt", "parseFloat"],
    taintArguments: [0],
    guardCapabilities: [GuardCapability.NUMERIC_ONLY],
    applicableSinkKinds: [SinkKind.COMMAND_EXEC, SinkKind.SQL_QUERY],
    callForms: ["global"],
    global: true,
    fallbackByCallName: true,
  }),
  guardModel({
    id: "javascript.regex-whitelist.test",
    languages: ["javascript", "typescript"],
    moduleNames: [],
    qualifiedNames: ["RegExp.test"],
    receiverTypes: ["RegExp"],
    callNames: ["test"],
    taintArguments: [0],
    guardCapabilities: [GuardCapability.WHITELIST_PATTERN],
    applicableSinkKinds: [
      SinkKind.COMMAND_EXEC, SinkKind.SQL_QUERY, SinkKind.FILE_ACCESS, SinkKind.HTTP_REQUEST,
      SinkKind.RESPONSE_OUTPUT, SinkKind.REDIRECT, SinkKind.DESERIALIZATION, SinkKind.DYNAMIC_EXEC,
    ],
    callForms: ["instance-method"],
    fallbackByCallName: true,
    regexLiteralReceiver: true,
    requireAnchoredWhitelist: true,
  }),
  guardModel({
    id: "php.numeric-conversion",
    languages: ["php"],
    moduleNames: [],
    qualifiedNames: ["intval", "floatval"],
    callNames: ["intval", "floatval"],
    taintArguments: [0],
    guardCapabilities: [GuardCapability.NUMERIC_ONLY],
    applicableSinkKinds: [SinkKind.COMMAND_EXEC, SinkKind.SQL_QUERY],
    callForms: ["function"],
    global: true,
    fallbackByCallName: true,
  }),
  guardModel({
    id: "php.numeric-filter",
    languages: ["php"],
    moduleNames: [],
    qualifiedNames: ["filter_var"],
    callNames: ["filter_var"],
    taintArguments: [0],
    guardCapabilities: [GuardCapability.NUMERIC_ONLY],
    applicableSinkKinds: [SinkKind.COMMAND_EXEC, SinkKind.SQL_QUERY],
    callForms: ["function"],
    global: true,
    fallbackByCallName: true,
    argumentExpectedValues: [{
      index: 1,
      values: ["FILTER_VALIDATE_INT", "FILTER_VALIDATE_FLOAT"],
      matchMode: "identifier",
      reason: "filter_var is numeric-only only with FILTER_VALIDATE_INT or FILTER_VALIDATE_FLOAT.",
    }],
  }),
  guardModel({
    id: "python.numeric-conversion",
    languages: ["python"],
    moduleNames: ["builtins"],
    qualifiedNames: ["builtins.int", "builtins.float", "int", "float"],
    callNames: ["int", "float"],
    taintArguments: [0],
    guardCapabilities: [GuardCapability.NUMERIC_ONLY],
    applicableSinkKinds: [SinkKind.COMMAND_EXEC, SinkKind.SQL_QUERY],
    callForms: ["function"],
    global: true,
    fallbackByCallName: true,
  }),
  ...SYNTAX_SEMANTIC_MODELS,
  ...SUPPLEMENTAL_SEMANTIC_MODELS,
]);

const CATALOG_SCHEMA_VERSION = 1;

const STRUCTURAL_SEMANTIC_MODELS = Object.freeze([
  Object.freeze({
    id: "structural.collection-safe-join",
    role: SemanticRole.GUARD,
    languages: ["php"],
    factKind: "fixed-numeric-collection-join",
    guardCapabilities: [
      GuardCapability.NUMERIC_ONLY,
      GuardCapability.FIXED_COLLECTION,
      GuardCapability.ALL_ELEMENTS,
      GuardCapability.SAFE_JOIN,
    ],
    applicableSinkKinds: [SinkKind.COMMAND_EXEC],
    label: "Validated fixed collection rebuilt with literal separators",
  }),
]);

function sinkModel(input) {
  return Object.freeze({
    role: SemanticRole.SINK,
    returnsTaint: false,
    receiverTypes: [],
    taintReceiver: false,
    ...input,
  });
}

function sourceModel(input) {
  return Object.freeze({
    role: SemanticRole.SOURCE,
    returnsTaint: true,
    receiverTypes: [],
    taintReceiver: false,
    exposure: sourceExposureForKind(input.sourceKind),
    ...input,
  });
}

function guardModel(input) {
  return Object.freeze({
    role: SemanticRole.GUARD,
    returnsTaint: false,
    receiverTypes: [],
    taintReceiver: false,
    ...input,
  });
}

function propagatorModel(input) {
  return Object.freeze({
    role: SemanticRole.PROPAGATOR,
    returnsTaint: true,
    receiverTypes: [],
    taintReceiver: false,
    taintArguments: [],
    ...input,
  });
}

function resolveSemanticCall(language, call = {}, customModels = [], expectedRole) {
  const identity = call.symbol || {};
  const semanticName = identity.exportName || call.function;
  const registry = [...SEMANTIC_MODELS, ...(Array.isArray(customModels) ? customModels.filter(validCustomModel) : [])];
  const candidates = registry.filter(model =>
    model.languages.includes(language) &&
    (!expectedRole || model.role === expectedRole) &&
    model.callNames.some(name => canonical(name) === canonical(semanticName)));
  if (!candidates.length) return { status: "none" };

  if (identity.shadowed && !candidates.some(model => model.custom && model.customUnqualified)) {
    const reviewCandidate = isDynamicReceiverType(identity.receiverType) &&
      candidates.find(model => model.patternReceiverAgnostic);
    if (reviewCandidate) return resolution(reviewCandidate, "candidate", identity, call);
    return {
      status: "rejected",
      reason: "The call name resolves to a local declaration that shadows a modeled security API.",
      candidates: candidates.map(model => model.id),
    };
  }

  for (const model of candidates) {
    if (call.receiver && model.global) continue;
    if (model.custom && model.customUnqualified && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "syntax", identity, call);
    }
    // A receiver type declared in .traceguard.json is an explicit project contract.
    // It remains authoritative when the frontend can read the declared type name but
    // the corresponding source/dependency is absent from the workspace.
    if (model.custom && identity.receiverType && receiverMatches(model, identity.receiverType)) {
      return resolution(model, "verified", identity, call);
    }
    if (model.global && identity.kind === "global" && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "verified", identity, call);
    }
    if (model.global && !call.receiver && !identity.shadowed && !identity.qualifiedName && !identity.moduleName &&
      [undefined, "unresolved"].includes(identity.kind) && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "syntax", identity, call);
    }
    if (identity.moduleName && moduleMatches(model, identity.moduleName) && exportMatches(model, identity.exportName || call.function)) {
      return resolution(model, "verified", identity, call);
    }
    // A regular-expression literal receiver is stronger evidence than any
    // inferred type: under noLib the checker reports `{}` for RegExp, so this
    // check runs before type-based resolution for models that opt in.
    if (model.regexLiteralReceiver && call.receiver && isRegexLiteralReceiver(call.receiver)) {
      // WHITELIST_PATTERN models only trust anchored character-class-only
      // patterns (`^[a-z0-9]+$`); anything looser resolves to nothing, so the
      // flow stays reviewable instead of being silently suppressed.
      if (model.requireAnchoredWhitelist && !isAnchoredWhitelistRegex(call.receiver)) continue;
      return resolution(model, "syntax", { ...identity, qualifiedName: `${call.receiver}.${semanticName}` }, call);
    }
    if (!model.requiresModuleIdentity && !identity.unresolvedType && identity.qualifiedName && qualifiedMatches(model, identity.qualifiedName)) {
      return resolution(model, identity.verified ? "verified" : "syntax", identity, call);
    }
    if (!model.requiresModuleIdentity && identity.receiverType && receiverMatches(model, identity.receiverType)) {
      return resolution(model, identity.verified ? "verified" : "syntax", identity, call);
    }
    if (call.receiver && (!identity.receiverType || isDynamicReceiverType(identity.receiverType))) {
      const receiverEvidence = explicitSyntaxReceiverEvidence(model, call.receiver);
      if (receiverEvidence) {
        return resolution(model, receiverEvidence, { ...identity, qualifiedName: `${call.receiver}.${semanticName}` }, call);
      }
    }
    if (!model.requiresModuleIdentity && call.receiver &&
      (!identity.receiverType || isDynamicReceiverType(identity.receiverType)) && inferredSyntaxReceiverMatches(model, call.receiver)) {
      return resolution(model, "syntax", { ...identity, qualifiedName: `${call.receiver}.${semanticName}` }, call);
    }
  }

  if (expectedRole === SemanticRole.GUARD && identity.receiverType && !isDynamicReceiverType(identity.receiverType)) return {
    status: "rejected",
    reason: "The declared receiver type does not match any catalog or project-configured guard model.",
    candidates: candidates.map(model => model.id),
  };

  if (["java", "php", "python"].includes(language) && identity.receiverType && isDynamicReceiverType(identity.receiverType)) return {
    status: "candidate",
    reason: "The receiver has only a dynamic or top-level type, so the security API identity could not be proven.",
    candidates: candidates.map(model => model.id),
    candidateModels: candidates,
  };

  if (identity.kind === "local" || identity.kind === "import" || identity.kind === "require") return {
    status: "rejected",
    reason: "The resolved symbol does not match the module or receiver type required by the semantic model.",
    candidates: candidates.map(model => model.id),
  };

  if (identity.verified && identity.receiverType) return {
    status: "rejected",
    reason: "The resolved receiver type does not match the semantic model.",
    candidates: candidates.map(model => model.id),
  };

  const patternCandidates = candidates.filter(model => model.patternReceiverAgnostic);
  if (["javascript", "typescript"].includes(language) && call.receiver && patternCandidates.length &&
    (!identity.verified || isDynamicReceiverType(identity.receiverType))) {
    if (patternCandidates.length === 1) return resolution(patternCandidates[0], "candidate", identity, call);
    return {
      status: "candidate",
      reason: "The receiver is unresolved; catalog-declared pattern fallbacks remain review candidates only.",
      candidates: patternCandidates.map(model => model.id),
      candidateModels: patternCandidates,
    };
  }

  if (["javascript", "typescript"].includes(language) && call.receiver) return {
    status: "rejected",
    reason: "A member-call name matched, but TypeScript could not prove the required module or receiver identity.",
    candidates: candidates.map(model => model.id),
  };

  return {
    status: "candidate",
    reason: "A name pattern matched, but module and receiver identity could not be proven.",
    candidates: candidates.map(model => model.id),
    candidateModels: candidates,
  };
}

function validCustomModel(model) {
  return Boolean(model && model.custom && Array.isArray(model.languages) && Array.isArray(model.callNames) && model.role);
}

function resolution(model, status, identity, call) {
  const policyRejection = argumentConstraintRejection(model, call);
  if (policyRejection) return {
    status: "rejected",
    reason: policyRejection,
    model,
    candidates: [model.id],
  };
  const boundedStatus = model.interactiveCertainty === "review" ||
    (model.interactiveCertainty === "verified" && model.role === SemanticRole.GUARD && status !== "verified")
    ? "candidate"
    : status;
  return {
    status: boundedStatus,
    model,
    identity,
    certainty: boundedStatus === "verified" ? "high" : boundedStatus === "candidate" ? "low" : "medium",
  };
}

function moduleMatches(model, value) {
  const actual = normalizeModule(value);
  return model.moduleNames.some(moduleName => normalizeModule(moduleName) === actual);
}

function exportMatches(model, value) {
  return model.callNames.some(name => canonical(name) === canonical(value));
}

function qualifiedMatches(model, value) {
  const actual = canonicalQualified(value);
  return model.qualifiedNames.some(name => canonicalQualified(name) === actual || actual.endsWith(`.${canonicalQualified(name)}`));
}

function receiverMatches(model, value) {
  const actual = canonicalQualified(value);
  return model.receiverTypes.some(type => {
    const expected = canonicalQualified(type);
    return actual === expected || actual.endsWith(`.${expected}`);
  });
}

function explicitSyntaxReceiverEvidence(model, value) {
  const actual = canonicalQualified(value);
  if ((model.verifiedSyntaxReceiverNames || []).some(name => receiverExpressionMatches(actual, canonicalQualified(name)))) {
    return "verified";
  }
  if ((model.syntaxReceiverNames || []).some(name => receiverExpressionMatches(actual, canonicalQualified(name)))) {
    return "syntax";
  }
  return undefined;
}

function inferredSyntaxReceiverMatches(model, value) {
  const actual = canonicalQualified(value);
  const receiverNames = [
    ...model.moduleNames.flatMap(moduleName => {
      const normalized = normalizeModule(moduleName);
      return [normalized, normalized.split("/").at(-1)];
    }),
    ...model.receiverTypes.map(type => canonicalQualified(type)),
    ...model.qualifiedNames.map(name => canonicalQualified(name).split(".").slice(0, -1).join(".")),
  ].filter(Boolean);
  return receiverNames.some(expected => receiverExpressionMatches(actual, expected));
}

function receiverExpressionMatches(actual, expected) {
  return Boolean(expected && (actual === expected || actual.endsWith(`.${expected}`) || actual.startsWith(`${expected}.`)));
}

function normalizeModule(value) {
  return String(value || "").replace(/^node:/, "").replaceAll("\\", "/").toLowerCase();
}

function canonicalQualified(value) {
  return String(value || "").replace(/\s+/g, "").replace(/^[*&]+/, "").replace(/::|->/g, ".").toLowerCase();
}

function canonical(value) {
  return String(value || "").replace(/[^A-Za-z0-9_$]/g, "").toLowerCase();
}

function isDynamicReceiverType(value) {
  return new Set(["?", "any", "mixed", "object", "java.lang.object", "dynamic", "unknown"])
    .has(canonicalQualified(value));
}

// A regular-expression literal receiver (`/^[a-z]+$/.test(value)`) is direct
// evidence that the callee is RegExp.prototype.test — no import resolution
// is required because the literal cannot be anything else.
function isRegexLiteralReceiver(value) {
  return /^\/.+\/[a-z]*$/i.test(String(value || "").trim());
}

// An anchored, character-class-only pattern (`^[a-z0-9_-]+$`) is a real
// whitelist: it cannot match shell metacharacters or SQL operators. Escaped
// classes like \d \w are accepted; `.`, `*`, `?`, groups and alternation are
// rejected because they weaken the guarantee.
function isAnchoredWhitelistRegex(value) {
  const match = /^\/(.+)\/[a-z]*$/.exec(String(value || "").trim());
  if (!match) return false;
  let body = match[1];
  if (!body.startsWith("^") || !body.endsWith("$")) return false;
  body = body.slice(1, -1);
  body = body.replace(/\\./g, "").replace(/\[[^\]]*\]/g, "");
  return !/[.*?()|/]|\{[^}]*\?/.test(body);
}

function validateSemanticCatalog(models = SEMANTIC_MODELS) {
  const issues = [];
  const ids = new Set();
  const roles = new Set(Object.values(SemanticRole));
  for (const [index, model] of (models || []).entries()) {
    const at = model?.id || `catalog[${index}]`;
    if (!model || typeof model !== "object") { issues.push(`${at}: entry must be an object`); continue; }
    if (!model.id || typeof model.id !== "string") issues.push(`${at}: id is required`);
    else if (ids.has(model.id)) issues.push(`${at}: duplicate id`);
    else ids.add(model.id);
    if (!roles.has(model.role)) issues.push(`${at}: unknown role ${model.role}`);
    for (const field of ["languages", "callNames", "qualifiedNames", "moduleNames", "receiverTypes", "taintArguments"]) {
      if (!Array.isArray(model[field])) issues.push(`${at}: ${field} must be an array`);
    }
    if (model.syntaxReceiverNames !== undefined && !Array.isArray(model.syntaxReceiverNames)) {
      issues.push(`${at}: syntaxReceiverNames must be an array when declared`);
    }
    if (model.verifiedSyntaxReceiverNames !== undefined && !Array.isArray(model.verifiedSyntaxReceiverNames)) {
      issues.push(`${at}: verifiedSyntaxReceiverNames must be an array when declared`);
    }
    if (model.regexLiteralReceiver !== undefined && typeof model.regexLiteralReceiver !== "boolean") {
      issues.push(`${at}: regexLiteralReceiver must be a boolean when declared`);
    }
    if (model.requireAnchoredWhitelist !== undefined && typeof model.requireAnchoredWhitelist !== "boolean") {
      issues.push(`${at}: requireAnchoredWhitelist must be a boolean when declared`);
    }
    if (Array.isArray(model.taintArguments) && model.taintArguments.some(value => !Number.isInteger(value) || value < 0)) {
      issues.push(`${at}: taintArguments must contain non-negative integers`);
    }
    if (model.role === SemanticRole.SOURCE && !model.sourceKind) issues.push(`${at}: sourceKind is required for sources`);
    if (model.role === SemanticRole.SINK && !model.sinkKind) issues.push(`${at}: sinkKind is required for sinks`);
    if (model.role === SemanticRole.GUARD && !model.guardCapabilities?.length) issues.push(`${at}: guardCapabilities are required for guards`);
    if (model.role === SemanticRole.GUARD && !model.applicableSinkKinds?.length) issues.push(`${at}: applicableSinkKinds are required for guards`);
    if (model.applicableSinkKinds?.some(value => !Object.values(SinkKind).includes(value))) {
      issues.push(`${at}: applicableSinkKinds contains an unknown sink kind`);
    }
  }
  return issues;
}

function resolveStructuralSemantic(factKind, language) {
  return STRUCTURAL_SEMANTIC_MODELS.find(model => model.factKind === factKind && model.languages.includes(language));
}

function compileCatalogPatterns(language, options = {}) {
  return compilePatterns(options.models || SEMANTIC_MODELS, language, options);
}

const catalogIssues = validateSemanticCatalog();
if (catalogIssues.length) throw new Error(`Invalid TraceGuard semantic catalog: ${catalogIssues.join("; ")}`);

// Conventional request-object root names used to infer that a parameter bound
// from a call-site argument carries request-controlled data. Signals already
// cover exact source shapes (`req.query`, `$_GET`); these roots cover helper
// functions that receive the whole request object and read fields inside.
const CONVENTIONAL_REQUEST_ROOTS = Object.freeze(new Set([
  "req", "request", "_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "ctx", "context",
]));

module.exports = {
  CATALOG_SCHEMA_VERSION,
  COLLECTION_SEMANTIC_MODELS,
  CONVENTIONAL_REQUEST_ROOTS,
  SEMANTIC_MODELS,
  STRUCTURAL_SEMANTIC_MODELS,
  SemanticRole,
  compileCatalogPatterns,
  resolveSemanticCall,
  resolveStructuralSemantic,
  validateSemanticCatalog,
};
