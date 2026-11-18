"use strict";

const { normalizeAccessPath, appendAccessPath } = require("../ir/access-path");
const { COLLECTION_SEMANTIC_MODELS } = require("./collection-models");

/**
 * Interpret collection propagator declarations without coupling AST frontends
 * to Java library names. Calls and argument inputs are already normalized by
 * the frontend; this module owns the small amount of state needed for precise
 * list-slot tracking.
 */
function interpretCollectionCall(call, output, language, states, context = {}) {
  if (language === "java" && isJavaMap(call)) {
    const slot = mapKeyPath(call.receiver, call.arguments?.[0]);
    if (call.function === "get" && call.arguments.length === 1) return { receiverInputs: [slot] };
    if (call.function === "put" && call.arguments.length === 2) return { writes: [{
      inputs: call.argumentInputs?.[1] || [], output: slot,
      reason: `Map.put() writes the selected key slot ${slot}.`,
    }] };
  }
  const models = COLLECTION_SEMANTIC_MODELS.filter(model => model.languages.includes(language));
  registerConstruction(models, call, output, states);

  const receiver = normalizeAccessPath(call?.receiver);
  if (!receiver) return {};

  const state = states.get(receiver);
  if (state) {
    const model = models.find(candidate => candidate.id === state.modelId);
    const declaration = model?.operations?.[String(call.function || "")];
    if (declaration) {
      const precise = applyStatefulOperation(declaration, call, receiver, state, states, context.controlScope);
      if (precise.handled) return precise.result;
    }
  }

  const generic = models.find(model =>
    !model.stateful &&
    receiverTypeMatches(model, call?.symbol?.receiverType) &&
    model.operations?.[String(call.function || "")]);
  if (!generic) return {};
  return applyStatelessOperation(generic.operations[String(call.function || "")], call, receiver);
}

function isJavaMap(call) {
  const type = String(call?.symbol?.receiverType || "").replace(/<.*>/g, "");
  return !call?.symbol?.shadowed && /^java\.util\.(?:(?:Map|HashMap|LinkedHashMap|TreeMap|SortedMap|NavigableMap)|concurrent\.(?:ConcurrentMap|ConcurrentHashMap|ConcurrentSkipListMap))$/.test(type);
}

function mapKeyPath(receiver, expression) {
  const raw = String(expression || "").trim();
  let key = "*";
  if (/^"[^"\\]*"$/.test(raw)) key = raw.slice(1, -1);
  else if (/^\d+$/.test(raw)) key = Number(raw);
  return appendAccessPath(normalizeAccessPath(receiver), [key]);
}

function registerConstruction(models, call, output, states) {
  const name = simpleTypeName(call?.function);
  const outputName = normalizeAccessPath(output?.name);
  if (!outputName || (call?.arguments || []).length) return;
  const model = models.find(candidate => candidate.stateful && candidate.constructors.includes(name));
  if (model) states.set(outputName, { modelId: model.id, slots: [], nextSlot: 0 });
}

function applyStatefulOperation(declaration, call, receiver, state, states, controlScope) {
  if (state.scope === undefined) state.scope = controlScope || "";
  else if (state.scope !== (controlScope || "")) state.imprecise = true;

  if (declaration.effect === "insert-slot") {
    const explicitIndex = (call.arguments || []).length >= declaration.indexedArityAtLeast
      ? numericArgument(call, declaration.indexArgument)
      : undefined;
    const valueIndex = argumentIndex(declaration.valueArgument, call);
    const slot = `${receiver}[${state.nextSlot++}]`;
    if (explicitIndex === undefined) state.slots.push(slot);
    else state.slots.splice(Math.min(explicitIndex, state.slots.length), 0, slot);
    return handled({ writes: [{
      inputs: call.argumentInputs?.[valueIndex] || [],
      output: slot,
      reason: `${call.function}() writes argument ${valueIndex} into tracked list slot ${slot}.`,
    }] });
  }

  if (declaration.effect === "remove-slot") {
    if (!state.imprecise) {
      const index = numericArgument(call, declaration.indexArgument);
      if (index !== undefined && index < state.slots.length) state.slots.splice(index, 1);
      else states.delete(receiver);
    }
    return handled({ writes: [] });
  }

  if (declaration.effect === "read-slot") {
    if (state.imprecise) {
      return handled({ receiverInputs: state.slots.length ? [...state.slots] : [`${receiver}[*]`], writes: [] });
    }
    const slot = state.slots[numericArgument(call, declaration.indexArgument)];
    return slot ? handled({ receiverInputs: [slot], writes: [] }) : unhandled();
  }

  if (declaration.effect === "replace-slot") {
    const valueIndex = argumentIndex(declaration.valueArgument, call);
    if (state.imprecise) {
      const slot = `${receiver}[${state.nextSlot++}]`;
      state.slots.push(slot);
      return handled({ writes: [{
        inputs: call.argumentInputs?.[valueIndex] || [],
        output: slot,
        reason: `${call.function}() may replace a list element across alternate control-flow paths; ${slot} preserves that candidate value.`,
      }] });
    }
    const slot = state.slots[numericArgument(call, declaration.indexArgument)];
    if (!slot) return unhandled();
    return handled({ writes: [{
      inputs: call.argumentInputs?.[valueIndex] || [],
      output: slot,
      reason: `${call.function}() replaces tracked list slot ${slot} with argument ${valueIndex}.`,
    }] });
  }

  return unhandled();
}

function applyStatelessOperation(declaration, call, receiver) {
  if (declaration.effect !== "write-elements") return {};
  const valueIndex = argumentIndex(declaration.valueArgument, call);
  const inputs = call.argumentInputs?.[valueIndex] || [];
  if (!inputs.length) return {};
  return { writes: [{
    inputs,
    output: `${receiver}[*]`,
    reason: `${call.function}() writes argument ${valueIndex} into ${receiver}.`,
  }] };
}

function receiverTypeMatches(model, receiverType) {
  const actual = simpleTypeName(receiverType);
  return Boolean(actual && model.receiverTypes.includes(actual));
}

function simpleTypeName(value) {
  const erased = String(value || "").replace(/\s+/g, "").replace(/<.*>$/, "");
  return erased.split(/[.$\\/]/).filter(Boolean).at(-1) || "";
}

function argumentIndex(value, call) {
  return value === "last" ? Math.max(0, (call.arguments || []).length - 1) : value;
}

function numericArgument(call, index) {
  const value = String(call.arguments?.[index] || "").trim();
  return /^\d+$/.test(value) ? Number(value) : undefined;
}

function handled(result) { return { handled: true, result }; }
function unhandled() { return { handled: false, result: {} }; }

module.exports = { interpretCollectionCall, isJavaMap, mapKeyPath, receiverTypeMatches, simpleTypeName };
