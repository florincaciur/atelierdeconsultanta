#!/usr/bin/env node
"use strict";

const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "..");
const preload = path.join(__dirname, "fs-write-retry.js");
const npmCli = process.env.npm_execpath;

if (!npmCli) throw new Error("npm_execpath lipsește; rulează build-ul prin npm run build.");

const nodeOptions = [process.env.NODE_OPTIONS, `--require=${preload}`].filter(Boolean).join(" ");
const result = spawnSync(process.execPath, [npmCli, "run", "build:pipeline"], {
  cwd: root,
  env: { ...process.env, NODE_OPTIONS: nodeOptions },
  stdio: "inherit"
});

if (result.error) throw result.error;
process.exit(result.status ?? 1);
