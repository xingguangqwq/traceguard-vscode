"use strict";
// @ts-check

/** @typedef {import('../ir/contracts').BindingFunction} BindingFunction */
/** @typedef {import('../ir/contracts').CallArguments} CallArguments */
/** @typedef {import('../ir/contracts').ArgumentBinding} ArgumentBinding */
/** @typedef {import('../ir/contracts').BindingResult} BindingResult */
/** @typedef {import('../ir/contracts').AccessPathSegment} AccessPathSegment */
/** @typedef {import('../ir/contracts').CallBinding & {name: string, index: number}} BoundParameter */

const { appendAccessPath, normalizeAccessPath, pathFeeds, relativeAccessPath } = require("../ir/access-path");

/** @type {WeakMap<CallArguments, WeakMap<BindingFunction, BindingResult>>} */
const cache = new WeakMap();
const MAX_ARGUMENTS = 128;
const MAX_BINDINGS = 512;

/** @param {BindingFunction} fn @param {CallArguments} event */
function implicitReceiverOffset(fn, event) {
  return fn.language === "python" && event.receiver && ["self", "cls"].includes(fn.parameters?.[0]) ? 1 : 0;
}

/** @param {BindingFunction} fn @param {CallArguments} event @returns {BindingResult} */
function bindCallArguments(fn, event) {
  let byFunction = cache.get(event);
  if (!byFunction) { byFunction = new WeakMap(); cache.set(event, byFunction); }
  const cached = byFunction.get(fn);
  if (cached) return cached;
  const result = buildBindings(fn, event);
  byFunction.set(fn, result);
  return result;
}

/** @param {BindingFunction} fn @param {CallArguments} event @returns {BindingResult} */
function buildBindings(fn, event) {
  const offset = implicitReceiverOffset(fn, event);
  const parameterNames = fn.parameters || [];
  const details = fn.parameterDetails || [];
  const namedLanguage = ["python", "php"].includes(fn.language);
  const strict = namedLanguage && details.length === parameterNames.length && details.every(parameter => parameter.callBinding);
  const args = event.arguments || [];
  /** @returns {BindingResult} */
  const limited = () => ({ status: "unresolved", valid: true, strict, special: true, bindings: [],
    reason: `Argument binding budget exceeded (${MAX_ARGUMENTS} arguments/parameters or ${MAX_BINDINGS} mappings); inspect this call manually.` });
  if (namedLanguage && (args.length > MAX_ARGUMENTS || parameterNames.length > MAX_ARGUMENTS)) return limited();
  if (!strict && namedLanguage && event.argumentKinds?.some(kind => kind !== "positional")) {
    if (args.length * (parameterNames.length - offset) > MAX_BINDINGS) return limited();
    return {
      status: "unresolved", valid: true, strict: false, special: true,
      reason: "Named or unpacked arguments require a syntax-proven callee signature; these possible mappings are unverified.",
      bindings: args.flatMap((_, argumentIndex) => parameterNames.slice(offset).map((name, index) => ({
        parameterIndex: index + offset, argumentIndex, parameterPath: [], kind: "explicit", uncertain: true,
      }))),
    };
  }
  if (!strict) return {
    status: "verified", valid: true, strict: false, special: false, reason: "Arguments use positional parameter order.",
    bindings: args.flatMap((_, argumentIndex) => parameterNames[argumentIndex + offset]
      ? [{ parameterIndex: argumentIndex + offset, argumentIndex, parameterPath: [], kind: "explicit" }] : []),
  };
  const parameters = fn.parameters.map((name, index) => ({ name: name.replace(/^\$/, ""), index,
    .../** @type {import('../ir/contracts').CallBinding} */ (details[index].callBinding) })).slice(offset);
  const byName = new Map(parameters.map(parameter => [parameter.name, parameter]));
  const positional = parameters.filter(parameter => ["positional-only", "positional-or-keyword"].includes(parameter.kind));
  const variadicPosition = parameters.find(parameter => ["variadic-positional", "variadic"].includes(parameter.kind));
  const variadicKeyword = parameters.find(parameter => ["variadic-keyword", "variadic"].includes(parameter.kind));
  /** @type {ArgumentBinding[]} */
  const bindings = [];
  const filled = new Set();
  const named = new Set();
  const issues = [];
  /** @type {{argumentIndex: number, kind: import('../ir/contracts').ArgumentKind}[]} */
  const unpacked = [];
  let positionalIndex = 0;
  let variadicIndex = 0;
  let sawNamed = false;
  let positionalUnknown = false;
  let special = parameters.some(parameter => parameter.kind !== "positional-or-keyword" || parameter.hasDefault);
  /** @param {string} reason @returns {BindingResult} */
  const invalid = reason => ({ status: "invalid", valid: false, strict: true, special: true, bindings: [], reason });
  /** @param {BoundParameter} parameter @param {number} argumentIndex @param {AccessPathSegment[]} [parameterPath] @param {boolean} [uncertain] */
  const add = (parameter, argumentIndex, parameterPath = [], uncertain = false) => bindings.push({
    parameterIndex: parameter.index, argumentIndex, parameterPath, kind: "explicit", uncertain,
  });
  for (let argumentIndex = 0; argumentIndex < args.length; argumentIndex++) {
    const kind = event.argumentKinds?.[argumentIndex] || "positional";
    if (kind.startsWith("unpack") || kind === "unknown") {
      special = true;
      unpacked.push({ argumentIndex, kind });
      if (kind !== "unpack-keyword") positionalUnknown = true;
      continue;
    }
    if (kind === "named") {
      special = true;
      sawNamed = true;
      const name = event.argumentNames?.[argumentIndex];
      if (!name) return invalid("A named argument has no syntax-proven parameter name.");
      if (named.has(name)) return invalid(`The call supplies named argument ${name} more than once.`);
      named.add(name);
      const parameter = byName.get(name);
      if (parameter && ["positional-or-keyword", "keyword-only"].includes(parameter.kind)) {
        if (filled.has(parameter.index)) return invalid(`Parameter ${name} receives both a positional and a named argument.`);
        filled.add(parameter.index);
        add(parameter, argumentIndex);
      } else if (variadicKeyword) add(variadicKeyword, argumentIndex, [name]);
      else return invalid(parameter?.kind === "positional-only"
        ? `Parameter ${name} is positional-only and cannot be supplied by name.`
        : `Named argument ${name} does not match a declared parameter.`);
      continue;
    }
    if (sawNamed) return invalid("A positional argument appears after a named argument.");
    if (positionalUnknown) { unpacked.push({ argumentIndex, kind: "unpack-positional" }); continue; }
    const parameter = positional[positionalIndex++];
    if (parameter) { filled.add(parameter.index); add(parameter, argumentIndex); }
    else if (variadicPosition) { special = true; add(variadicPosition, argumentIndex, [variadicIndex++]); }
    else if (fn.language === "php") issues.push("Extra PHP positional arguments require func_get_args/func_get_arg context.");
    else return invalid("The call supplies more positional arguments than the declared signature accepts.");
  }
  for (const parameter of parameters) {
    if (/^variadic/.test(parameter.kind) || filled.has(parameter.index)) continue;
    const mayBeUnpacked = unpacked.some(argument => unpackCanBind(argument.kind, parameter.kind, fn.language));
    if (mayBeUnpacked) continue;
    const requiredAfter = fn.language === "php" && parameters.some(later => later.index > parameter.index && !later.hasDefault && !/^variadic/.test(later.kind));
    if (parameter.hasDefault && !requiredAfter) bindings.push({ parameterIndex: parameter.index, parameterPath: [], kind: "default" });
    else return invalid(`Required parameter ${parameter.name} has no supplied argument.`);
  }
  for (const argument of unpacked) {
    for (const parameter of parameters) {
      if (filled.has(parameter.index) || !unpackCanBind(argument.kind, parameter.kind, fn.language)) continue;
      if (bindings.length >= MAX_BINDINGS) return limited();
      add(parameter, argument.argumentIndex, /^variadic/.test(parameter.kind) ? ["*"] : [], true);
    }
  }
  if (unpacked.length) issues.push("Unpacked argument contents are not statically resolved; possible parameter mappings remain review candidates.");
  const mapping = bindings.filter(binding => binding.kind === "explicit" && !binding.uncertain).map(binding => {
    const label = event.argumentNames?.[binding.argumentIndex] || `#${binding.argumentIndex + 1}`;
    return `${label} → ${fn.parameters[binding.parameterIndex]}${binding.parameterPath.length ? `[${binding.parameterPath.join(",")}]` : ""}`;
  });
  return {
    status: issues.length ? "unresolved" : "verified", valid: true, strict: true, special,
    bindings, reason: issues.length ? [...new Set(issues)].join(" ") : `Argument binding: ${mapping.join("; ") || "declared defaults or empty argument list"}.`,
  };
}

/** @param {import('../ir/contracts').ArgumentKind} argumentKind @param {import('../ir/contracts').ParameterKind} parameterKind @param {string} language */
function unpackCanBind(argumentKind, parameterKind, language) {
  if (argumentKind === "unknown" || language === "php" && argumentKind === "unpack") return true;
  if (argumentKind === "unpack-keyword") return !["positional-only", "variadic-positional"].includes(parameterKind);
  return !["keyword-only", "variadic-keyword"].includes(parameterKind);
}

/** @param {CallArguments} event @param {ArgumentBinding} binding @returns {{expression: string, variables: string[], constant?: boolean}} */
function argumentValue(event, binding) {
  if (binding.kind !== "explicit") return { variables: [], expression: "" };
  const index = binding.argumentIndex;
  return {
    expression: event.accessorArgumentPaths?.[index] || event.argumentValues?.[index] || event.arguments?.[index] || "",
    variables: event.argumentVariables?.[index] || [],
    constant: Boolean(event.argumentConstantFlags?.[index]),
  };
}

/** @param {BindingFunction} fn @param {ArgumentBinding} binding */
function parameterValue(fn, binding) { return appendAccessPath(fn.parameters[binding.parameterIndex], binding.parameterPath); }

/** @param {ArgumentBinding} binding @param {AccessPathSegment[]} [parameterPath] */
function bindingMatchesParameterPath(binding, parameterPath = []) {
  const bound = binding.parameterPath || [];
  const common = Math.min(bound.length, parameterPath.length);
  return bound.slice(0, common).every((segment, index) => segment === "*" || parameterPath[index] === "*" || segment === parameterPath[index]);
}

/** @param {CallArguments} event @param {ArgumentBinding} binding @param {AccessPathSegment[]} [parameterPath] @returns {string[]} */
function callerValuesForBinding(event, binding, parameterPath = []) {
  const bound = binding.parameterPath || [];
  if (!bindingMatchesParameterPath(binding, parameterPath)) return [];
  const suffix = parameterPath.slice(bound.length);
  const value = argumentValue(event, binding);
  if (value.constant) return [];
  const root = normalizeAccessPath(value.expression);
  if (binding.uncertain) return value.variables;
  if (suffix.length) return root ? [appendAccessPath(root, suffix)] : value.variables.map(variable => appendAccessPath(variable, suffix));
  return value.variables.length ? value.variables : root ? [root] : [];
}

/** @param {BindingFunction} fn @param {CallArguments} event @param {ArgumentBinding} binding @param {string} variable @returns {string[]} */
function calleeValuesForBinding(fn, event, binding, variable) {
  const value = argumentValue(event, binding);
  const target = parameterValue(fn, binding);
  if (binding.uncertain) return value.variables.some(input => pathFeeds(variable, input) || pathFeeds(input, variable)) ? [target] : [];
  if (value.variables.some(input => pathFeeds(variable, input))) return [target];
  const argument = normalizeAccessPath(value.expression);
  return argument && pathFeeds(argument, variable) ? [appendAccessPath(target, relativeAccessPath(variable, argument) || [])] : [];
}

module.exports = { argumentValue, bindCallArguments, bindingMatchesParameterPath, calleeValuesForBinding, callerValuesForBinding, implicitReceiverOffset, parameterValue };
