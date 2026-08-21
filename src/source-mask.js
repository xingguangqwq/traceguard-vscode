"use strict";

function maskNonCodeLines(lines, language = "javascript", maskStrings = true) {
  const supportsHashComments = language === "python" || language === "php";
  const supportsBackticks = ["javascript", "typescript", "go"].includes(language);
  let inBlockComment = false;
  let stringToken = "";
  let multilineString = false;

  return lines.map(rawLine => {
    const line = String(rawLine);
    const output = [...line];
    let escaped = false;
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

      if (stringToken) {
        const tokenLength = stringToken.length;
        if (tokenLength === 3 && line.startsWith(stringToken, index)) {
          if (maskStrings) mask(index, index + tokenLength);
          stringToken = "";
          multilineString = false;
          index += tokenLength;
          continue;
        }
        const character = line[index];
        if (maskStrings) mask(index, index + 1);
        if (tokenLength === 1 && !escaped && character === stringToken) {
          stringToken = "";
          multilineString = false;
        }
        if (tokenLength === 1) {
          if (!escaped && character === "\\") escaped = true;
          else escaped = false;
        }
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
        stringToken = triple;
        multilineString = true;
        if (maskStrings) mask(index, index + 3);
        index += 3;
        continue;
      }
      const character = line[index];
      if (character === '"' || character === "'" || (supportsBackticks && character === "`")) {
        stringToken = character;
        multilineString = character === "`";
        if (maskStrings) output[index] = " ";
      }
      index += 1;
    }

    if (stringToken && !multilineString) stringToken = "";
    return output.join("");
  });
}

module.exports = { maskNonCodeLines };
