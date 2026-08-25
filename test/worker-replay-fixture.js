"use strict";

const { parentPort } = require("node:worker_threads");

let initialized = false;

parentPort.on("message", message => {
  try {
    if (message.type === "initializeWorkspace") {
      if (message.options?.failReplay) throw new Error("simulated replay failure");
      const respond = () => {
        initialized = true;
        parentPort.postMessage({ id: message.id, result: { initialized } });
      };
      if (message.options?.delayMs) setTimeout(respond, message.options.delayMs);
      else respond();
      return;
    }
    if (message.type === "queryPaths") {
      const respond = () => parentPort.postMessage({ id: message.id, result: { initialized } });
      if (message.options?.delayMs) setTimeout(respond, message.options.delayMs);
      else respond();
      return;
    }
    throw new Error(`Unexpected fixture request: ${message.type}`);
  } catch (error) {
    parentPort.postMessage({
      id: message.id,
      error: { message: String(error.message || error), stack: String(error.stack || "") },
    });
  }
});
