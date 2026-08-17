"use strict";

const path = require("path");

const LANGUAGE_SUPPORT = [
  { analysis: "java", label: "Java", vscode: ["java"], extensions: [".java", ".jsp", ".jspx"] },
  { analysis: "php", label: "PHP", vscode: ["php"], extensions: [".php", ".phtml", ".php3", ".php4", ".php5", ".inc"] },
  { analysis: "javascript", label: "JavaScript", vscode: ["javascript", "javascriptreact"], extensions: [".js", ".jsx", ".mjs", ".cjs"] },
  { analysis: "typescript", label: "TypeScript", vscode: ["typescript", "typescriptreact"], extensions: [".ts", ".tsx"] },
  { analysis: "python", label: "Python", vscode: ["python"], extensions: [".py"] },
  { analysis: "csharp", label: "C#", vscode: ["csharp"], extensions: [".cs"] },
  { analysis: "go", label: "Go", vscode: ["go"], extensions: [".go"] },
];

const SUPPORTED_SELECTORS = LANGUAGE_SUPPORT.flatMap(item => item.vscode.map(language => ({ language, scheme: "file" })));
const SUPPORTED_LABEL = "Java, PHP, JavaScript/TypeScript, Python, C# or Go";

function languageForPath(filePath) {
  const extension = path.extname(filePath).toLowerCase();
  return LANGUAGE_SUPPORT.find(item => item.extensions.includes(extension))?.analysis;
}

module.exports = { LANGUAGE_SUPPORT, SUPPORTED_LABEL, SUPPORTED_SELECTORS, languageForPath };
