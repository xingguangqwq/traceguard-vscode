"use strict";

// Line masker used by signal matching. String contents are blanked so regex
// signals only fire on code. Template-literal interpolations (${...}) in
// JavaScript/TypeScript are the exception: the enclosed expression is real
// code and must stay visible, so frames are tracked on a stack.

function maskNonCodeLines(lines, language = "javascript", maskStrings = true) {
  const supportsHashComments = language === "python" || language === "php";
  const supportsBackticks = ["javascript", "typescript", "go"].includes(language);
  const supportsInterpolation = ["javascript", "typescript"].includes(language);
  let inBlockComment = false;
  const frames = [];

  const isStringOpener = character => character === '"' || character === "'" ||
    (supportsBackticks && character === "`");

  return lines.map(rawLine => {
    const line = String(rawLine);
    const output = [...line];
    const mask = (start, end) => {
      for (let offset = start; offset < Math.min(end, output.length); offset += 1) output[offset] = " ";
    };

    for (let index = 0; index < line.length;) {
      if (inBlockComment) {
        const end = line.indexOf("*/", index);
        if (end === -1) { mask(index, line.length); index = line.length; continue; }
        mask(index, end + 2);
        inBlockComment = false;
        index = end + 2;
        continue;
      }

      const frame = frames[frames.length - 1];

      if (frame?.type === "interp") {
        const character = line[index];
        if (character === "{") {
          frame.braceDepth += 1;
          index += 1;
          continue;
        }
        if (character === "}") {
          if (maskStrings) mask(index, index + 1);
          if (frame.braceDepth === 1) {
            frames.pop();
            frames.push({ type: "string", token: frame.resume, escaped: false });
          } else {
            frame.braceDepth -= 1;
          }
          index += 1;
          continue;
        }
        const triple = line.startsWith('"""', index) ? '"""' : line.startsWith("'''", index) ? "'''" : "";
        if (triple) {
          if (maskStrings) mask(index, index + 3);
          frames.push({ type: "string", token: triple, escaped: false });
          index += 3;
          continue;
        }
        if (isStringOpener(character)) {
          if (maskStrings) mask(index, index + 1);
          frames.push({ type: "string", token: character, escaped: false });
          index += 1;
          continue;
        }
        index += 1;
        continue;
      }

      if (frame?.type === "string") {
        const token = frame.token;
        if (token.length === 3 && line.startsWith(token, index)) {
          if (maskStrings) mask(index, index + 3);
          frames.pop();
          index += 3;
          continue;
        }
        const character = line[index];
        if (maskStrings) mask(index, index + 1);
        if (supportsInterpolation && token === "`" && !frame.escaped && character === "$" && line[index + 1] === "{") {
          if (maskStrings) mask(index, index + 2);
          frames.pop();
          frames.push({ type: "interp", braceDepth: 1, resume: token });
          index += 2;
          continue;
        }
        if (token.length === 1 && !frame.escaped && character === token) {
          frames.pop();
          index += 1;
          continue;
        }
        frame.escaped = token.length === 1 ? (!frame.escaped && character === "\\") : false;
        index += 1;
        continue;
      }

      if (line.startsWith("/*", index)) {
        const end = line.indexOf("*/", index + 2);
        if (end === -1) {
          mask(index, line.length);
          inBlockComment = true;
          index = line.length;
        } else {
          mask(index, end + 2);
          index = end + 2;
        }
        continue;
      }
      if (line.startsWith("//", index) || (supportsHashComments && line[index] === "#")) {
        mask(index, line.length);
        break;
      }

      const triple = line.startsWith('"""', index) ? '"""' : line.startsWith("'''", index) ? "'''" : "";
      if (triple) {
        if (maskStrings) mask(index, index + 3);
        frames.push({ type: "string", token: triple, escaped: false });
        index += 3;
        continue;
      }
      const character = line[index];
      if (isStringOpener(character)) {
        if (maskStrings) output[index] = " ";
        frames.push({ type: "string", token: character, escaped: false });
      }
      index += 1;
    }

    for (let i = frames.length - 1; i >= 0; i -= 1) {
      const frame = frames[i];
      if (frame.type === "string" && frame.token.length === 1 && frame.token !== "`") frames.splice(i, 1);
      else break;
    }
    return output.join("");
  });
}

module.exports = { maskNonCodeLines };
