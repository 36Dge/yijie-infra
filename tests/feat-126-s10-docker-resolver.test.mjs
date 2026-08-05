import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { FEAT_126_S10_IMAGES } from "../scripts/compose-model.mjs";
import {
  DOCKER_FAILURE_CLASSES,
  DockerPreflightError,
  buildResolverProbeArgs,
  parseInspectOutput,
  parsePinnedImage,
  runResolverProbe,
  validateImageSnapshot,
  validateProbeContainer,
  verifyDockerExecutionCapability,
  verifyLocalImageAvailability,
} from "../scripts/verify-feat-126-s10-images.mjs";

const RUN_ID = "12600000-0000-4000-8000-000000000054";
const DIGEST = "sha256:" + "a".repeat(64);
const IMAGE_ID = "sha256:" + "1".repeat(64);
const CONTAINER_ID = "2".repeat(64);
const REFERENCE = "example.test/yijie/image:1.0.0@" + DIGEST;
const IMAGE = parsePinnedImage(REFERENCE);
const CAPABILITY = Object.freeze({ architecture: "arm64", os: "linux" });

function ok(stdout = "") {
  return { status: 0, stdout, stderr: "", error: undefined };
}

function failed(stderr = "command failed", error) {
  return { status: 1, stdout: "", stderr, error };
}

function asJson(value) {
  return ok(JSON.stringify(value));
}

function codeIs(code) {
  return (error) => error instanceof DockerPreflightError && error.code === code;
}

function imageSnapshot(overrides = {}) {
  return {
    Id: IMAGE_ID,
    RepoDigests: [IMAGE.digestReference],
    RepoTags: [IMAGE.tagReference],
    Descriptor: { digest: IMAGE.digest },
    Os: "linux",
    Architecture: "arm64",
    Config: { Volumes: { "/state": {} } },
    ...overrides,
  };
}

function createSuccessfulRunner({ snapshot = imageSnapshot() } = {}) {
  let active = false;
  let probe;
  const calls = [];
  const runDocker = (args) => {
    calls.push([...args]);
    if (args[0] === "version") {
      return asJson({ Arch: "arm64", Os: "linux" });
    }
    if (args[0] === "image" && args[1] === "inspect") {
      return asJson(snapshot);
    }
    if (args[0] === "container" && args[1] === "create") {
      const nameIndex = args.indexOf("--name");
      const name = args[nameIndex + 1];
      const labels = {};
      for (let index = 0; index < args.length; index += 1) {
        if (args[index] === "--label") {
          const [key, ...value] = args[index + 1].split("=");
          labels[key] = value.join("=");
        }
      }
      const tmpfs = {};
      for (let index = 0; index < args.length; index += 1) {
        if (args[index] === "--tmpfs") {
          const [path, ...options] = args[index + 1].split(":");
          tmpfs[path] = options.join(":");
        }
      }
      probe = {
        Id: CONTAINER_ID,
        Name: "/" + name,
        Config: { Image: args.at(-1), Labels: labels },
        State: { Running: false },
        HostConfig: { NetworkMode: "none", Tmpfs: tmpfs, PortBindings: {} },
        Mounts: Object.keys(tmpfs).map((path) => ({ Type: "tmpfs", Destination: path })),
        NetworkSettings: { Ports: {} },
      };
      active = true;
      return ok(CONTAINER_ID + "\n");
    }
    if (args[0] === "container" && args[1] === "inspect") {
      return active ? asJson(probe) : failed("No such container");
    }
    if (args[0] === "container" && args[1] === "rm") {
      active = false;
      return ok(CONTAINER_ID + "\n");
    }
    throw new Error("unexpected fake Docker command");
  };
  return { calls, isActive: () => active, runDocker };
}

test("S10BD1-001 classifies a missing Docker CLI before image or create calls", () => {
  const calls = [];
  assert.throws(
    () =>
      verifyDockerExecutionCapability({
        runDocker: (args) => {
          calls.push(args);
          return failed("", Object.assign(new Error("missing"), { code: "ENOENT" }));
        },
      }),
    codeIs("docker_cli_unavailable"),
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], "version");
});

test("S10BD1-002 separates permission denied and daemon unavailable", () => {
  assert.throws(
    () =>
      verifyDockerExecutionCapability({
        runDocker: () => failed("permission denied while opening endpoint"),
      }),
    codeIs("docker_permission_denied"),
  );
  assert.throws(
    () =>
      verifyDockerExecutionCapability({
        runDocker: () => failed("Cannot connect to the Docker daemon"),
      }),
    codeIs("docker_daemon_unavailable"),
  );
});

test("S10BD1-003 consumes only the original version-tag@digest authority", () => {
  const built = buildResolverProbeArgs({
    image: IMAGE,
    runId: RUN_ID,
    ordinal: 0,
    volumes: ["/state"],
  });
  assert.equal(built.args.at(-1), REFERENCE);
  assert.equal(built.args.includes(IMAGE.digestReference), false);
  assert.equal(built.args.includes("--pull=never"), true);
  assert.equal(built.args.includes("--network"), true);
  assert.equal(built.args.includes("none"), true);
});

test("S10BD1-004 validates exact Id, Descriptor, RepoDigests, repository, and platform", () => {
  const identity = validateImageSnapshot(imageSnapshot(), IMAGE, CAPABILITY);
  assert.equal(identity.id, IMAGE_ID);
  assert.equal(identity.descriptor, DIGEST);
  assert.deepEqual(identity.repoDigests, [IMAGE.digestReference]);
  assert.deepEqual(identity.volumes, ["/state"]);
  assert.throws(
    () => validateImageSnapshot(imageSnapshot({ Architecture: "amd64" }), IMAGE, CAPABILITY),
    codeIs("image_platform_mismatch"),
  );
});

test("S10BD1-005 distinguishes image missing from unresolved exact reference", () => {
  const missing = (args) => {
    if (args[0] === "version") {
      return asJson({ Arch: "arm64", Os: "linux" });
    }
    return failed("No such image");
  };
  assert.throws(
    () =>
      verifyLocalImageAvailability({
        imageMap: { one: REFERENCE },
        runDocker: missing,
        resolverProbe: false,
      }),
    codeIs("image_not_found"),
  );

  const unresolved = (args) => {
    if (args[0] === "version") {
      return asJson({ Arch: "arm64", Os: "linux" });
    }
    if (args[0] === "image" && args[2] === IMAGE.tagReference) {
      return asJson(imageSnapshot());
    }
    return failed("No such image");
  };
  assert.throws(
    () =>
      verifyLocalImageAvailability({
        imageMap: { one: REFERENCE },
        runDocker: unresolved,
        resolverProbe: false,
      }),
    codeIs("image_reference_unresolved"),
  );
});

test("S10BD1-006 rejects empty, multiline, oversized, and invalid JSON payloads", () => {
  for (const payload of ["", "{}\n{}", "x".repeat(1024 * 1024 + 1), "not-json"]) {
    assert.throws(() => parseInspectOutput(payload), codeIs("inspect_payload_invalid"));
  }
  assert.throws(
    () =>
      verifyDockerExecutionCapability({
        runDocker: () => failed("", Object.assign(new Error("oversized"), { code: "ENOBUFS" })),
      }),
    codeIs("inspect_payload_invalid"),
  );
});

test("S10BD1-007 fails closed on digest, repository, descriptor, and snapshot drift", () => {
  assert.throws(
    () =>
      validateImageSnapshot(
        imageSnapshot({ RepoDigests: ["other.example/image@" + DIGEST] }),
        IMAGE,
        CAPABILITY,
      ),
    codeIs("image_repository_mismatch"),
  );
  assert.throws(
    () =>
      validateImageSnapshot(
        imageSnapshot({ RepoDigests: [IMAGE.repository + "@sha256:" + "b".repeat(64)] }),
        IMAGE,
        CAPABILITY,
      ),
    codeIs("image_digest_mismatch"),
  );
  assert.throws(
    () =>
      validateImageSnapshot(
        imageSnapshot({ Descriptor: { digest: "sha256:" + "c".repeat(64) } }),
        IMAGE,
        CAPABILITY,
      ),
    codeIs("image_digest_mismatch"),
  );

  let snapshots = 0;
  assert.throws(
    () =>
      verifyLocalImageAvailability({
        imageMap: { one: REFERENCE },
        resolverProbe: false,
        runDocker: (args) => {
          if (args[0] === "version") {
            return asJson({ Arch: "arm64", Os: "linux" });
          }
          snapshots += 1;
          return asJson(
            imageSnapshot({
              Config: { Volumes: snapshots === 1 ? { "/state": {} } : { "/other": {} } },
            }),
          );
        },
      }),
    codeIs("image_identity_invalid"),
  );
});

test("S10BD1-008 creates, inspects, and removes a never-started no-pull probe", () => {
  const runner = createSuccessfulRunner();
  const result = verifyLocalImageAvailability({
    imageMap: { one: REFERENCE },
    runDocker: runner.runDocker,
    runId: RUN_ID,
  });
  assert.deepEqual(result, { imageCount: 1, probeCount: 1 });
  assert.equal(runner.isActive(), false);
  const create = runner.calls.find((args) => args[0] === "container" && args[1] === "create");
  assert.equal(create.includes("--pull=never"), true);
  assert.equal(runner.calls.some((args) => args[1] === "start"), false);
  assert.equal(runner.calls.some((args) => args[1] === "rm"), true);
});

test("S10BD1-009 enforces tmpfs volume coverage, no network, and no published ports", () => {
  const probe = buildResolverProbeArgs({
    image: IMAGE,
    runId: RUN_ID,
    ordinal: 0,
    volumes: ["/state"],
  });
  const container = {
    Id: CONTAINER_ID,
    Name: "/" + probe.name,
    Config: { Image: IMAGE.reference, Labels: probe.labels },
    State: { Running: false },
    HostConfig: {
      NetworkMode: "none",
      Tmpfs: { "/state": "rw,noexec,nosuid,nodev" },
      PortBindings: {},
    },
    Mounts: [{ Type: "tmpfs", Destination: "/state" }],
    NetworkSettings: { Ports: {} },
  };
  assert.doesNotThrow(() =>
    validateProbeContainer(container, {
      ...probe,
      containerId: CONTAINER_ID,
      image: IMAGE,
      volumes: ["/state"],
    }),
  );
  assert.throws(
    () =>
      validateProbeContainer(
        {
          ...container,
          Mounts: [{ Type: "volume", Destination: "/state" }],
        },
        {
          ...probe,
          containerId: CONTAINER_ID,
          image: IMAGE,
          volumes: ["/state"],
        },
      ),
    codeIs("resolver_probe_failed"),
  );
});

test("S10BD1-010 reconciles an unknown outcome and never removes a foreign identity", () => {
  const ownedRunner = createSuccessfulRunner();
  const base = ownedRunner.runDocker;
  let createFailed = false;
  const unknown = (args) => {
    if (args[0] === "container" && args[1] === "create" && !createFailed) {
      createFailed = true;
      base(args);
      return failed("transport closed");
    }
    return base(args);
  };
  assert.throws(
    () =>
      runResolverProbe({
        image: IMAGE,
        identity: { volumes: ["/state"] },
        runId: RUN_ID,
        ordinal: 0,
        runDocker: unknown,
      }),
    codeIs("resolver_probe_failed"),
  );
  assert.equal(ownedRunner.isActive(), false);
  assert.equal(ownedRunner.calls.some((args) => args[1] === "rm"), true);

  const probe = buildResolverProbeArgs({
    image: IMAGE,
    runId: RUN_ID,
    ordinal: 0,
    volumes: ["/state"],
  });
  let rmCalls = 0;
  let inspectCount = 0;
  const foreign = (args) => {
    if (args[0] === "container" && args[1] === "inspect") {
      inspectCount += 1;
      if (inspectCount === 1) {
        return failed("No such container");
      }
      return asJson({
        Id: CONTAINER_ID,
        Name: "/" + probe.name,
        Config: { Image: IMAGE.reference, Labels: { "ai.yijie.feature": "FOREIGN" } },
        State: { Running: false },
      });
    }
    if (args[0] === "container" && args[1] === "create") {
      return failed("transport closed");
    }
    if (args[0] === "container" && args[1] === "rm") {
      rmCalls += 1;
    }
    return ok();
  };
  assert.throws(
    () =>
      runResolverProbe({
        image: IMAGE,
        identity: { volumes: ["/state"] },
        runId: RUN_ID,
        ordinal: 0,
        runDocker: foreign,
      }),
    codeIs("resolver_probe_cleanup_incomplete"),
  );
  assert.equal(rmCalls, 0);

  const invalidOutputRunner = createSuccessfulRunner();
  const invalidBase = invalidOutputRunner.runDocker;
  const invalidOutput = (args) => {
    if (args[0] === "container" && args[1] === "create") {
      invalidBase(args);
      return ok("invalid-container-id\n");
    }
    return invalidBase(args);
  };
  assert.throws(
    () =>
      runResolverProbe({
        image: IMAGE,
        identity: { volumes: ["/state"] },
        runId: RUN_ID,
        ordinal: 0,
        runDocker: invalidOutput,
      }),
    codeIs("resolver_probe_failed"),
  );
  assert.equal(invalidOutputRunner.isActive(), false);
  assert.equal(invalidOutputRunner.calls.some((args) => args[1] === "rm"), true);
});

test("S10BD1-011 exposes only a closed failure class, never raw diagnostic text", () => {
  const secretCanary = "secret-canary-/private/docker.sock";
  assert.throws(
    () =>
      verifyDockerExecutionCapability({
        runDocker: () => failed(secretCanary),
      }),
    (error) => {
      assert.equal(error.code, "docker_daemon_unavailable");
      assert.equal(error.message.includes(secretCanary), false);
      assert.equal(error.message.includes("/private/docker.sock"), false);
      return true;
    },
  );
  assert.deepEqual(
    DOCKER_FAILURE_CLASSES,
    [...new Set(DOCKER_FAILURE_CLASSES)],
  );
});

test("S10BD1-012 preserves Compose pins, no-pull, and regression boundaries", async () => {
  const [composeScript, composeModel, documentation] = await Promise.all([
    readFile("scripts/feat-126-s10-compose.sh", "utf8"),
    readFile("scripts/compose-model.mjs", "utf8"),
    readFile("docs/feat-126-s10e.md", "utf8"),
  ]);
  assert.match(composeScript, /verify-feat-126-s10-images\.mjs" "\$run_id"/);
  assert.match(composeScript, /--pull never/);
  assert.doesNotMatch(composeScript, /docker (image )?pull|docker image tag|docker system prune/);
  for (const reference of Object.values(FEAT_126_S10_IMAGES)) {
    assert.equal(composeModel.includes(reference), true);
  }
  assert.match(documentation, /contract-impact = semantic/);
  assert.match(documentation, /does not authorize S10B-R4 or S11/);
});
