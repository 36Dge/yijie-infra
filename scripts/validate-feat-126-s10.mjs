import { readFile } from "node:fs/promises";

import {
  FEAT_126_S10_IMAGES,
  FEAT_126_S10_PROFILE,
  FEAT_126_S10_SERVICES,
  loadCompose,
  validateCompose,
} from "./compose-model.mjs";
import {
  FEAT_126_S10_API_RUNTIME_AUTHORITY,
  validateApiRuntimeAuthority,
} from "./feat-126-s10-api-runtime-profile.mjs";

const compose = await loadCompose();
validateCompose(compose);
validateApiRuntimeAuthority(FEAT_126_S10_API_RUNTIME_AUTHORITY);

for (const name of FEAT_126_S10_SERVICES) {
  const service = compose.services[name];
  if (service.image !== FEAT_126_S10_IMAGES[name]) {
    throw new Error(`${name} image projection drifted`);
  }
  if (JSON.stringify(service.profiles) !== JSON.stringify([FEAT_126_S10_PROFILE])) {
    throw new Error(`${name} default-off profile drifted`);
  }
}

const caddyfile = await readFile("config/feat-126-s10/Caddyfile", "utf8");
for (const required of [
  "skip_install_trust",
  "reverse_proxy feat126-s10-keycloak:8080",
  "reverse_proxy host.docker.internal:18080",
  "respond @legacy_tasks 404",
]) {
  if (!caddyfile.includes(required)) {
    throw new Error(`FEAT-126 S10 Caddyfile is missing: ${required}`);
  }
}
if (/tls_insecure_skip_verify|0\.0\.0\.0|PRIVATE KEY/.test(caddyfile)) {
  throw new Error("FEAT-126 S10 Caddyfile contains a forbidden trust, bind, or key pattern");
}

console.log("Validated the default-off FEAT-126 S10E Compose and TLS projection.");
