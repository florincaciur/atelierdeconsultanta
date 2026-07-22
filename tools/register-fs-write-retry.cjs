"use strict";

const fs = require("fs");

const originalWriteFileSync = fs.writeFileSync.bind(fs);
const retryableCodes = new Set(["UNKNOWN", "EBUSY", "EPERM", "EACCES"]);
const waitBuffer = new Int32Array(new SharedArrayBuffer(4));

fs.writeFileSync = function writeFileSyncWithRetry(...args) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      return originalWriteFileSync(...args);
    } catch (error) {
      if (!retryableCodes.has(error?.code) || attempt === 7) throw error;
      Atomics.wait(waitBuffer, 0, 0, 50 * (attempt + 1));
    }
  }
};
