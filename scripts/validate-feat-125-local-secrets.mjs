#!/usr/bin/env node

import { validateFeat125LocalSecrets } from "./feat-125-local-secrets.mjs";

const path = process.argv[2];
if (!path || process.argv.length !== 3) {
  throw new Error("usage: validate-feat-125-local-secrets.mjs FILE");
}
await validateFeat125LocalSecrets(path);
console.log("Validated ignored FEAT-125 local secrets file and permissions.");
