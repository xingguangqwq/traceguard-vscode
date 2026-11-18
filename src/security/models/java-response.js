"use strict";

const { SinkKind } = require("../semantics");
const { sinkModel, propagatorModel } = require("../model-factories");

// A semantic receiver tag preserves response provenance. An arbitrary file or
// logging PrintWriter must not become an HTTP response sink merely by its type.
const RESPONSE_WRITER = "traceguard.servlet.ResponseWriter";
const JAVA_RESPONSE_MODELS = Object.freeze([
  propagatorModel({
    id: "java.servlet.response-writer", languages: ["java"],
    moduleNames: ["javax.servlet", "javax.servlet.http", "jakarta.servlet", "jakarta.servlet.http"],
    qualifiedNames: ["ServletResponse.getWriter", "HttpServletResponse.getWriter"],
    receiverTypes: ["ServletResponse", "HttpServletResponse"],
    callNames: ["getWriter"], callForms: ["instance-method"],
    returnsTaint: false, returnType: RESPONSE_WRITER, requiresReceiverIdentity: true,
  }),
  sinkModel({
    id: "java.servlet.response-body", languages: ["java"], moduleNames: [],
    qualifiedNames: [`${RESPONSE_WRITER}.write`, `${RESPONSE_WRITER}.print`, `${RESPONSE_WRITER}.println`, `${RESPONSE_WRITER}.append`],
    receiverTypes: [RESPONSE_WRITER],
    callNames: ["write", "print", "println", "append"], callForms: ["instance-method"],
    taintArguments: [0], sinkKind: SinkKind.RESPONSE_OUTPUT, category: "output",
    requiredArguments: [{ index: 0 }],
    requiresReceiverIdentity: true,
  }),
]);

module.exports = { JAVA_RESPONSE_MODELS };
