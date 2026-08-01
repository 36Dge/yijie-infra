#!/usr/bin/env node

import {
  loadFeat125LocalLabConfig,
  validateFeat125LocalLabConfig,
  verifyFeat125LocalLabOnline,
} from "./feat-125-local-config.mjs";

const options = parseArgs(process.argv.slice(2));
const config = await loadFeat125LocalLabConfig(options.file);

if (options.online) {
  await verifyFeat125LocalLabOnline(config, options);
} else {
  await validateFeat125LocalLabConfig(config, options);
}

console.log(
  options.online
    ? "FEAT-125 G3-NP-LOCAL online preflight passed"
    : `FEAT-125 G3-NP-LOCAL ${options.mode} validation passed`,
);

function parseArgs(args) {
  const options = { mode: "template", online: false };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--mode") {
      options.mode = requireValue(args, ++index, arg);
    } else if (arg === "--expected-api-commit") {
      options.expectedApiCommit = requireValue(args, ++index, arg);
    } else if (arg === "--expected-desktop-commit") {
      options.expectedDesktopCommit = requireValue(args, ++index, arg);
    } else if (arg === "--expected-api-reference") {
      options.expectedApiReference = requireValue(args, ++index, arg);
    } else if (arg === "--expected-desktop-reference") {
      options.expectedDesktopReference = requireValue(args, ++index, arg);
    } else if (arg === "--api-repository") {
      options.apiRepository = requireValue(args, ++index, arg);
    } else if (arg === "--desktop-repository") {
      options.desktopRepository = requireValue(args, ++index, arg);
    } else if (arg === "--online") {
      options.online = true;
    } else if (arg.startsWith("-")) {
      throw new Error(`unsupported option: ${arg}`);
    } else if (options.file === undefined) {
      options.file = arg;
    } else {
      throw new Error(`unexpected argument: ${arg}`);
    }
  }
  if (!options.file) {
    throw new Error(
      "usage: validate-feat-125-local.mjs [--mode template|local-lab] [--online] " +
        "[--expected-api-reference REF] [--expected-desktop-reference REF] " +
        "[--api-repository PATH] [--desktop-repository PATH] FILE",
    );
  }
  if (options.online && options.mode !== "local-lab") {
    throw new Error("--online is only valid with --mode local-lab");
  }
  return options;
}

function requireValue(args, index, option) {
  const value = args[index];
  if (!value || value.startsWith("-")) {
    throw new Error(`${option} requires a value`);
  }
  return value;
}
