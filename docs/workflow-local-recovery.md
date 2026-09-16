# Explicit local recovery — FEAT-154

Owner authorization: the user explicitly approved the five-step recovery, activation and sample UI verification plan. `contract-impact=semantic` for the Infra-owned local deployment lifecycle; no public HTTP/bridge changes. This is an opt-in recovery of the recorded dataset, never automatic replay of engine work.

## Authority and phases

`workflow-recovery-plan` archives the original exited container identities, immutable image IDs, mounts, configuration fingerprints, credential-file fingerprints, old editor manifest/assets and private source state before any restart. It requires all owned containers stopped and no unresolved controller child/stop. `workflow-recover RECOVERY_ID=...` uses only that plan and records each phase. A plan never changes old exit codes; later observations are separate events.

The executable recovery phases are: stopped-data copies → original dependencies healthy → read-only private storage review → original primary applications healthy → canonical normal stop. Only six primary containers are eligible; migration/qualification one-off containers are excluded. No images are pulled, containers recreated, credentials rotated, migrations replayed or data rewritten by the recovery controller. PostgreSQL/MySQL perform their own normal startup recovery.

Data protection copies use Docker's normal copy-out from the stopped, recorded data mounts into a new private ignored recovery directory. Source volumes are not modified by this copy. A content inventory/hash is retained; this protects original bytes, not a claim of tested database restore. A failed/partial copy is not a completed backup and cannot authorize restart.

API and Coze own the checked-in read-only SQL reports under their workflow infrastructure/localadapter paths. Infra runs those exact bounded queries against the existing local databases. A nonzero last-run slot is harmless only when the referenced original execution is authoritatively terminal; it is never cleared. An unknown API storage-qualification receipt is accepted only when its per-operation declaration hash, audit evidence and absence from Coze dispatch facts match the original qualification implementation. All other unresolved intents, missing executions, nonterminal nodes/runs, scope mismatch or read failures block applications. No operation is retried or marked complete.

Normal stop/editor/up checks retain their original requirements. Recovery validates OLD image/config/asset bytes independently of the new sibling working tree; only after successful normal stop does the usual current-source build/register/up path apply. Old scripts must not be used while recovery is active. A failed phase retains evidence and any normally running dependencies; repeated execution observes completed stages rather than replaying starts. STOP_PENDING never escalates to a force stop.

## Failure boundary and evidence

All helpers hold the controller lock, verify exact primary IDs/epoch/images/mounts and record start intent before calling Docker. An already-attempted start that has exited again is reported for inspection, not retried automatically. A missing/changed original asset, image, private mount, backup, identity or source query rejects recovery. Public evidence contains no credential values or business graph/input/output content.

This scoped entry does not implement arbitrary database repair, in-flight engine recovery, data migration, volume restoration, dataset replacement or production recovery. Source and runtime verification are separate; completing a recovery does not qualify FEAT-154 UI or D4.

## Actual source review corrections

The first storage read used wire-style lowercase JSON keys; API private domain.Receipt uses Go field names Phase/ErrorCode. A later exact comparison correctly observed EnsurePrincipal appending its ordinary principal/success audit. Both source corrections were reviewed and recorded as immutable chained source revisions; original.json and data copies remain unchanged. The explicit workflow-recovery-revise entry accepts a reviewed source manifest SHA only at paused storage-review phases, validates original identities/copies, and never changes services/data. The startup check permits exactly the documented new principal audit and retains all previous audit rows, operations, workflows and executions. Unknown engine work remains blocking.
