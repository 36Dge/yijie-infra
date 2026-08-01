#!/usr/bin/env node

import {
  loadFeat125LocalAssets,
  validateFeat125LocalAssets,
} from "./feat-125-local-assets.mjs";

validateFeat125LocalAssets(await loadFeat125LocalAssets());
console.log("Validated FEAT-125 local Keycloak realm and Caddy security boundaries.");
