#!/usr/bin/env node

import { validateFeat126S10Secrets } from "./feat-126-s10-secrets.mjs";

const path = process.argv[2];
if (!path || process.argv.length !== 3) {
  throw new Error("usage: validate-feat-126-s10-secrets.mjs FILE");
}
await validateFeat126S10Secrets(path);
console.log("Validated ignored FEAT-126 S10 secrets file and permissions.");
