import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  inspectCaCertificate,
  loadFeat125LocalLabConfig,
  resolveRepositoryPath,
} from "./feat-125-local-config.mjs";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const configPath = resolve(repositoryRoot, "environments/local/feat-125.local-lab.yaml");
const expectedRelativePath = "environments/local/generated/feat-125-caddy-root.crt";
const expectedCaPath = resolve(repositoryRoot, expectedRelativePath);

const config = await loadFeat125LocalLabConfig(configPath);
if (
  config.environment !== "local_lab" ||
  config.activation?.local !== true ||
  config.activation?.production !== false ||
  config.activation?.release !== false ||
  config.tls?.ca_certificate_path !== expectedRelativePath ||
  config.tls?.insecure_skip_verify !== false ||
  !/^[a-f0-9]{64}$/.test(config.tls?.ca_certificate_sha256 ?? "") ||
  resolveRepositoryPath(config.tls.ca_certificate_path) !== expectedCaPath
) {
  throw new Error("FEAT-125 local CA binding configuration is invalid");
}

const certificate = await inspectCaCertificate(expectedCaPath);
if (
  certificate.isCertificateAuthority !== true ||
  certificate.sha256 !== config.tls.ca_certificate_sha256
) {
  throw new Error("FEAT-125 local CA certificate does not match the rendered SHA-256 pin");
}

console.log("Validated owner-only single-certificate FEAT-125 CA and rendered SHA-256 pin.");
