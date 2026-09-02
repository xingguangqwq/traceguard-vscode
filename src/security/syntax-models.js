"use strict";

const { SourceKind, sourceExposureForKind } = require("./semantics");

function source(input) {
  return Object.freeze({
    role: "source",
    returnsTaint: true,
    receiverTypes: [],
    taintReceiver: false,
    taintArguments: [],
    qualifiedNames: [],
    moduleNames: [],
    callNames: [],
    callForms: [],
    exposure: sourceExposureForKind(input.sourceKind),
    ...input,
  });
}

// Non-call entry syntax cannot be inferred from qualified API names. It is
// still declared as semantic data here and compiled generically by catalog.js;
// pattern-parser must not own a second definition of these sources.
const SYNTAX_SEMANTIC_MODELS = Object.freeze([
  source({
    id: "java.framework.bound-request",
    languages: ["java"],
    sourceKind: SourceKind.HTTP_INPUT,
    syntaxForms: [{
      form: "annotation",
      delimiters: ["@"],
      names: ["RequestParam", "PathVariable", "RequestBody", "CookieValue", "RequestHeader", "ModelAttribute"],
    }],
  }),
  source({
    id: "php.superglobal.request-input",
    languages: ["php"],
    sourceKind: SourceKind.HTTP_INPUT,
    syntaxForms: [{
      form: "token",
      values: ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER"],
    }],
  }),
  source({
    id: "php.raw-request-body",
    languages: ["php"],
    sourceKind: SourceKind.HTTP_INPUT,
    syntaxForms: [{ form: "token", values: ["php://input"] }],
  }),
  source({
    id: "javascript.framework.request-members",
    languages: ["javascript", "typescript"],
    sourceKind: SourceKind.HTTP_INPUT,
    syntaxForms: [{
      form: "member-access",
      receivers: ["req", "request"],
      members: ["body", "query", "params", "headers", "cookies", "files"],
    }, {
      form: "member-call",
      receivers: ["searchParams", "formData"],
      members: ["get", "getAll"],
    }],
  }),
  source({
    id: "javascript.framework.bound-request",
    languages: ["javascript", "typescript"],
    sourceKind: SourceKind.HTTP_INPUT,
    syntaxForms: [{
      form: "annotation",
      delimiters: ["@"],
      names: ["Body", "Query", "Param", "Headers", "Req", "Request", "UploadedFile"],
    }],
  }),
  source({
    id: "javascript.process-event-input",
    languages: ["javascript", "typescript"],
    sourceKind: SourceKind.PROCESS_INPUT,
    syntaxForms: [{ form: "member-access", receivers: ["process"], members: ["argv"] }, {
      form: "member-access",
      receivers: ["event"],
      members: ["data", "body", "queryStringParameters", "pathParameters"],
    }],
  }),
  source({
    id: "python.framework.request-members",
    languages: ["python"],
    sourceKind: SourceKind.HTTP_INPUT,
    syntaxForms: [{
      form: "member-access",
      receivers: ["request"],
      members: ["args", "form", "values", "json", "data", "files", "cookies", "headers", "GET", "POST", "body"],
    }],
  }),
  source({
    id: "python.framework.bound-request",
    languages: ["python"],
    sourceKind: SourceKind.HTTP_INPUT,
    global: true,
    fallbackByCallName: true,
    qualifiedNames: ["Query", "Body", "Form", "Header", "Cookie"],
    callNames: ["Query", "Body", "Form", "Header", "Cookie"],
    callForms: ["function"],
  }),
  source({
    id: "python.process-members",
    languages: ["python"],
    sourceKind: SourceKind.PROCESS_INPUT,
    syntaxForms: [{
      form: "member-access",
      receivers: ["sys", "os"],
      members: ["argv", "environ"],
    }],
  }),
  source({
    id: "python.environment-input",
    languages: ["python"],
    sourceKind: SourceKind.PROCESS_INPUT,
    moduleNames: ["os"],
    qualifiedNames: ["os.getenv"],
    callNames: ["getenv"],
    callForms: ["module-function"],
  }),
  source({
    id: "python.console-input",
    languages: ["python"],
    sourceKind: SourceKind.PROCESS_INPUT,
    global: true,
    fallbackByCallName: true,
    qualifiedNames: ["input"],
    callNames: ["input"],
    callForms: ["function"],
  }),
  source({
    id: "csharp.framework.request-members",
    languages: ["csharp"],
    sourceKind: SourceKind.HTTP_INPUT,
    syntaxForms: [{
      form: "member-access",
      receivers: ["Request"],
      members: ["Query", "Form", "Headers", "Cookies", "Body", "Path"],
    }, {
      form: "annotation",
      delimiters: ["["],
      names: ["FromBody", "FromQuery", "FromRoute", "FromForm", "FromHeader"],
    }],
  }),
  source({
    id: "go.http.request-input",
    languages: ["go"],
    sourceKind: SourceKind.HTTP_INPUT,
    qualifiedNames: [
      "http.Request.FormValue", "http.Request.PostFormValue", "url.Values.Get", "http.Header.Get",
      "gin.Context.Param", "gin.Context.Query", "gin.Context.PostForm", "gin.Context.GetHeader",
    ],
    receiverTypes: ["http.Request", "url.Values", "http.Header", "gin.Context"],
    callNames: ["FormValue", "PostFormValue", "Get", "Param", "Query", "PostForm", "GetHeader", "Bind", "ShouldBind"],
    callForms: ["instance-method"],
    patternReceiverAgnostic: true,
    patternCallNames: ["FormValue", "PostFormValue", "Param", "Query", "PostForm", "GetHeader", "Bind", "ShouldBind"],
    syntaxForms: [{ form: "member-call", receivers: ["r.URL"], members: ["Query"] }, {
      form: "member-call", receivers: ["r.Header"], members: ["Get"]
    }, {
      form: "call-with-argument", callees: ["json.NewDecoder"], argumentTokens: ["r.Body"]
    }],
  }),
  source({
    id: "go.process-input",
    languages: ["go"],
    sourceKind: SourceKind.PROCESS_INPUT,
    moduleNames: ["os"],
    qualifiedNames: ["os.Getenv"],
    callNames: ["Getenv"],
    callForms: ["module-function"],
    syntaxForms: [{ form: "member-access", receivers: ["os"], members: ["Args"] }],
  }),
]);

module.exports = { SYNTAX_SEMANTIC_MODELS };
