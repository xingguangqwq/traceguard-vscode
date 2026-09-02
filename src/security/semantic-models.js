"use strict";

// Backward-compatible entry point. Built-in semantic declarations live only
// in catalog.js so every frontend consumes one source of security knowledge.
module.exports = require("./catalog");
