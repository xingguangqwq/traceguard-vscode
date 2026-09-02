"use strict";

// Collection APIs are dataflow propagators, not AST syntax. This declarative
// vocabulary is interpreted by collection-semantics.js.
const COLLECTION_SEMANTIC_MODELS = Object.freeze([
  Object.freeze({
    id: "java.list.slot-tracking",
    languages: ["java"],
    constructors: ["ArrayList", "LinkedList"],
    receiverTypes: ["List", "ArrayList", "LinkedList"],
    stateful: true,
    operations: Object.freeze({
      add: Object.freeze({ effect: "insert-slot", valueArgument: "last", indexArgument: 0, indexedArityAtLeast: 2 }),
      remove: Object.freeze({ effect: "remove-slot", indexArgument: 0 }),
      get: Object.freeze({ effect: "read-slot", indexArgument: 0 }),
      set: Object.freeze({ effect: "replace-slot", indexArgument: 0, valueArgument: 1 }),
    }),
  }),
  Object.freeze({
    id: "java.collection.element-writes",
    languages: ["java"],
    receiverTypes: [
      "Collection", "List", "Set", "Queue", "Deque", "Map", "ArrayList", "LinkedList",
      "HashSet", "TreeSet", "HashMap", "TreeMap", "ConcurrentHashMap",
    ],
    stateful: false,
    operations: Object.freeze({
      add: Object.freeze({ effect: "write-elements", valueArgument: "last" }),
      addAll: Object.freeze({ effect: "write-elements", valueArgument: "last" }),
      put: Object.freeze({ effect: "write-elements", valueArgument: 1 }),
      putIfAbsent: Object.freeze({ effect: "write-elements", valueArgument: 1 }),
      set: Object.freeze({ effect: "write-elements", valueArgument: 1 }),
      replace: Object.freeze({ effect: "write-elements", valueArgument: "last" }),
      putAll: Object.freeze({ effect: "write-elements", valueArgument: 0 }),
    }),
  }),
]);

module.exports = { COLLECTION_SEMANTIC_MODELS };
