"use strict";

function argumentConstraintRejection(model, call = {}) {
  const args = call.arguments || [];
  if (model.staticOperandSafe && (model.taintArguments || []).length &&
    model.taintArguments.every(index => (call.argumentConstants || []).some(item => item?.index === index))) {
    return "Every security-sensitive operand is a literal constant.";
  }
  for (const requirement of model.requiredArguments || []) {
    const value = args[requirement.index];
    if (value !== undefined && String(value).trim() !== "") continue;
    return requirement.reason || `Argument ${requirement.index} is required.`;
  }
  for (const expectation of model.argumentExpectedValues || []) {
    const value = String(args[expectation.index] || "").trim();
    if ((expectation.values || []).some(expected => expectedValueMatches(value, expected, expectation.matchMode))) continue;
    return expectation.reason || `Argument ${expectation.index} does not match the declared values.`;
  }
  for (const rejection of model.rejectWhen || []) {
    if (conditionMatches(rejection.when, args)) return rejection.reason || "The call matches a declared safe-call exclusion.";
  }
  return undefined;
}

function conditionMatches(condition, args) {
  if (!condition) return false;
  if (condition.all) return condition.all.every(item => conditionMatches(item, args));
  if (condition.any) return condition.any.some(item => conditionMatches(item, args));
  if (condition.not) return !conditionMatches(condition.not, args);
  if (condition.argumentCountAtLeast !== undefined) return args.length >= condition.argumentCountAtLeast;
  if (condition.argument) return argumentMatches(args[condition.argument.index], condition.argument);
  if (condition.namedArgument) {
    const names = new Set((condition.namedArgument.names || []).map(value => String(value).toLowerCase()));
    const value = args.map(splitNamedArgument).find(item => item && names.has(item.name.toLowerCase()))?.value;
    return argumentMatches(value, condition.namedArgument);
  }
  if (condition.anyArgument) {
    const values = args.slice(condition.anyArgument.fromIndex || 0);
    return values.some(value => argumentMatches(value, condition.anyArgument));
  }
  return false;
}

function argumentMatches(value, matcher = {}) {
  if (value === undefined) return false;
  let candidate = String(value).trim();
  if (matcher.literalValue) {
    const literal = literalStringValue(candidate);
    if (literal === undefined) return false;
    candidate = literal;
  }
  if (!matcher.pattern) return true;
  const matched = new RegExp(matcher.pattern, matcher.flags || "").test(candidate);
  return matcher.negate ? !matched : matched;
}

function expectedValueMatches(actual, expected, matchMode) {
  if (matchMode === "identifier") {
    return new RegExp(`(?:^|[^A-Za-z0-9_])${escapePattern(expected)}(?:$|[^A-Za-z0-9_])`).test(actual);
  }
  return actual === String(expected);
}

function splitNamedArgument(value) {
  const match = String(value || "").trim().match(/^([A-Za-z_]\w*)\s*=\s*([\s\S]+)$/);
  return match ? { name: match[1], value: match[2].trim() } : undefined;
}

function literalStringValue(value) {
  const match = String(value || "").trim().match(/^(?:[rubf]{0,2})?(["'])([\s\S]*)\1$/i);
  return match ? match[2] : undefined;
}

function escapePattern(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = { argumentConstraintRejection, conditionMatches };
