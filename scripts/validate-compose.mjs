import { loadCompose, validateCompose } from "./compose-model.mjs";

validateCompose(await loadCompose());
console.log("Validated local Compose services, images, ports, healthchecks, and volumes.");
