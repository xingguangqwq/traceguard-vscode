"use strict";

const { parentPort } = require("node:worker_threads");
const { runDataflowAnalysis } = require("./pipeline");

if (!parentPort) throw new Error("TraceGuard dataflow worker must run in a worker thread.");

parentPort.on("message", message => {
  try {
    parentPort.postMessage({ id: message.id, result: runDataflowAnalysis(message.analyses, message.options) });
  } catch (error) {
    parentPort.postMessage({
      id: message.id,
      error: { message: String(error?.message || error), stack: String(error?.stack || "") },
    });
  }
});
