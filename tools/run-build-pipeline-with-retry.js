#!/usr/bin/env node
"use strict";

const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const preload = path.join(__dirname, "register-fs-write-retry.cjs");
const existingOptions = String(process.env.NODE_OPTIONS || "").trim();
const requireOption = `--require=${preload}`;
const command = process.platform === "win32" ? (process.env.ComSpec || "cmd.exe") : "npm";
const args = process.platform === "win32" ? ["/d", "/s", "/c", "npm run build:pipeline"] : ["run", "build:pipeline"];
const result = spawnSync(command, args, {
  cwd: ROOT,
  env: {
    ...process.env,
    NODE_OPTIONS: existingOptions ? `${requireOption} ${existingOptions}` : requireOption
  },
  stdio: "inherit"
});

if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
