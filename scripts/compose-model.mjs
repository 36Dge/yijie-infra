import { readFile } from "node:fs/promises";
import YAML from "yaml";

export async function loadCompose() {
  const compose = YAML.parse(await readFile("docker-compose.local.yml", "utf8"));
  if (!compose?.services || !compose?.volumes) throw new Error("Compose file must define services and volumes.");
  return compose;
}

export function validateCompose(compose) {
  const required = ["postgres", "redis", "pgvector"];
  const serviceNames = Object.keys(compose.services);
  for (const name of required) {
    const service = compose.services[name];
    if (!service) throw new Error(`Missing local service: ${name}`);
    if (!service.image || service.image.endsWith(":latest")) throw new Error(`${name} must use a tagged image.`);
    if (!service.healthcheck?.test) throw new Error(`${name} must define a healthcheck.`);
    if (!Array.isArray(service.volumes) || service.volumes.length === 0) {
      throw new Error(`${name} must use a persistent volume.`);
    }
  }
  if (serviceNames.length !== required.length) throw new Error("Unexpected services in local Compose file.");

  const hostPorts = serviceNames.flatMap((name) => compose.services[name].ports ?? []).map((port) => String(port).split(":")[0]);
  if (new Set(hostPorts).size !== hostPorts.length) throw new Error("Local service host ports must be unique.");
  if (!compose.services.pgvector.ports.includes("5433:5432")) throw new Error("pgvector must be exposed on host port 5433.");
}
