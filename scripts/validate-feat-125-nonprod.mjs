#!/usr/bin/env node

import {
  loadFeat125NonprodConfig,
  validateFeat125NonprodConfig,
  verifyFeat125NonprodOnline,
} from "./feat-125-nonprod-config.mjs";

const { file, mode, online } = parseArgs(process.argv.slice(2));
const config = await loadFeat125NonprodConfig(file);
validateFeat125NonprodConfig(config, { mode });

if (online) {
  if (mode !== "ready") {
    throw new Error("--online is only valid with --mode ready");
  }
  await verifyFeat125NonprodOnline(config);
}

console.log(
  online
    ? "FEAT-125 nonproduction configuration and online preflight passed"
    : `FEAT-125 nonproduction ${mode} configuration passed`,
);

function parseArgs(args) {
  let mode = "template";
  let online = false;
  let file;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--mode") {
      mode = args[index + 1];
      index += 1;
    } else if (arg === "--online") {
      online = true;
    } else if (arg.startsWith("-")) {
      throw new Error(`unsupported option: ${arg}`);
    } else if (file === undefined) {
      file = arg;
    } else {
      throw new Error(`unexpected argument: ${arg}`);
    }
  }

  if (!file) {
    throw new Error("usage: validate-feat-125-nonprod.mjs [--mode template|ready] [--online] FILE");
  }
  return { file, mode, online };
}
