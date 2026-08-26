# meidoya-yashiki

**Yashiki (屋敷) is the Infrastructure Plane of Meidoya.** It builds, updates and
inspects the Execution Nodes that Meidoya runs work on — Lima VMs and native
hosts — and it knows nothing about the work itself.

```text
meidoya-yashiki
  → create / provision a Lima VM
  → install meidoya-node
  → materialize credentials
  → register the service
  → verify receipt and health
```

## The boundary versus `meidoya`

Yashiki and the `meidoya` Control Plane are separate repositories with separate
release cycles, and neither reads the other's source
(`meidoya-design/03-repository-boundaries.md`).

| Yashiki owns | Yashiki never does |
| --- | --- |
| Lima VM lifecycle | create Tasks |
| native/Lima provider abstraction | choose Workers or Models |
| CPU / memory / disk / mount configuration | post to chat |
| `meidoya-node` install, upgrade, rollback | release a Human Gate |
| credential materialization | delegate between Workspaces |
| node bootstrap and service registration | generate agent prompts |
| doctor, preflight, receipts | |
| backup and recovery | |
| the Yashiki local registry | |

The **only** cross-repository contract is `@meidoya/node-protocol`,
`@meidoya/node-manifest`, and the `meidoya-node` release artifact. Until the
protocol package is published, `packages/node-protocol-client/` holds a
**type-only vendored mirror** of it, pinned at `NODE_PROTOCOL_VERSION = 1`; it
must be replaced by the published package once that exists. There is no git
dependency, submodule or path read into the `meidoya` repository, and
`tools/repository-boundary.test.ts` fails the build if one appears — or if any
Control Plane concept (Task, Human Gate, chat transport, model routing, agent
prompts) leaks into this repository.

Yashiki depends on a **Node Protocol version and an artifact checksum**, not on
a particular `meidoya` release.

## Safety rules enforced in code

- **Mounts** — mounting the whole host home, any ancestor of it, or a known
  sensitive directory (`~/.ssh`, `~/Library`, `~/.gnupg`, …) is rejected.
  Mounts come from node-local configuration only. Guest-full does not mean
  host-full.
- **Credentials** — values are read from the host Keychain or SOPS through an
  injected port, streamed to the guest over stdin, and never placed in argv,
  logs, receipts, error messages or doctor output. Owner, mode and
  symlink-safety are verified after every write. One file and one receipt per
  provider. `sync` and `revoke` are separate operations.
- **Secret guard** — a second, weaker line behind that structural rule. Every
  sink (receipt row, doctor line, backup archive, terminal, child argv and
  environment, quoted `limactl` stderr) hands the guard the exact bytes it is
  about to write; the guard decodes those bytes back towards plaintext
  (backslash/JSON escapes, HTML entities, percent-encoding and any composition
  of the three, hex, base64 at every alignment, all of those with whitespace
  and separators stripped so wrapped base64 and hexdumps are covered, UTF-16,
  gzip / deflate) and refuses the write if a value it was told about is
  recoverable. Textual and binary decoding are interleaved and repeated to a
  bounded fixpoint, so a stack of transports — `base64` of `base64`, hex of
  base64, base64 of gzip of base64 — is unwound rather than peeled once.
  Sinks that render a whole document — the terminal above all —
  hand it the whole buffer, because a multi-line credential has no single line
  that contains it. It is a tripwire, not a proof: it cannot see encryption, a
  value split across fields, or a transform it does not model, and it catches
  nothing at all unless the command populated it first.
  `packages/yashiki-core/src/secret-guard.ts` documents the exact limits, and
  every one of them is asserted as a known gap in its test.
- **The guard fails closed** — decoding is bounded (bytes per call, and per
  decompression, so a gzip bomb in guest output cannot turn 700 KB into
  gigabytes of host memory). Reaching either bound **refuses the write** rather
  than returning quietly: a guard that gives up silently under load is worse
  than no guard, because the operator believes it ran.
- **Short credential values** — there is no length floor on a guarded value,
  but a value shorter than eight characters is matched against payload bytes
  only, never against system-generated metadata (receipt chain links, sequence
  numbers, ISO timestamps). A four-character credential occurs inside every
  timestamp this system writes; matching it there would refuse every receipt
  *after* the credential had already reached the guest, which breaks
  provisioning irrecoverably.
- **Child processes** — a child inherits an explicit allowlist of host
  environment variables (`INHERITED_ENV_NAMES`), never the whole environment:
  `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK` and anything like them
  stop at the process boundary rather than riding `limactl shell` into the
  guest. A credential source adds the variables its own tool needs, per
  invocation (`CREDENTIAL_SOURCE_ENV_NAMES`): `sops` gets `SOPS_AGE_KEY_FILE`,
  `GNUPGHOME`, `AWS_PROFILE` and the other **locators**, and never a key value —
  `SOPS_AGE_KEY` and `AWS_SECRET_ACCESS_KEY` are excluded on purpose, so a key
  held only in this process's environment must be moved into a profile or a key
  file that sops opens itself. A key sops cannot reach is reported as
  `CONFIG_INVALID` naming the forwarded variables, never as `NOT_FOUND`.
- **Artifacts** — the release manifest is pinned by sha256, the artifact
  checksum is verified before anything is written to the guest, and a node whose
  installed artifact or protocol version does not match the pin is **refused a
  start**.
- **Fail-closed** — every mutation is followed by an exact read-back. An
  ambiguous result (unparsable `limactl` output, unknown VM state, unreadable
  service state, incomplete Control Plane view) is an error, never an optimistic
  success. Recovery halts with `RECOVERY_REQUIRED` rather than guessing.
- **Receipts** — content-hashed, chained, append-only in memory and in SQLite
  (`UPDATE`/`DELETE` triggers abort).
- **Node lock** — a node cannot be provisioned by two runs at once.

## CLI

```bash
meidoya-yashiki node create work-grammarxiv --provider lima --cpu 8 --memory 16GiB
meidoya-yashiki node start work-grammarxiv
meidoya-yashiki node stop work-grammarxiv
meidoya-yashiki node status work-grammarxiv
meidoya-yashiki node doctor work-grammarxiv
meidoya-yashiki node upgrade work-grammarxiv
meidoya-yashiki node reprovision work-grammarxiv
meidoya-yashiki node backup work-grammarxiv
```

Exit codes: `0` success, `1` failure, `2` usage error, `3` `RECOVERY_REQUIRED`.

### Local registry

```text
~/.config/meidoya-yashiki/config.yaml          desired node configuration
~/.local/share/meidoya-yashiki/yashiki.sqlite  registry: nodes, runs, receipts, health
~/.local/share/meidoya-yashiki/artifacts/      staged meidoya-node releases
```

See `config.example.yaml` for the configuration shape.

### Real Lima acceptance

On 2026-08-25 the CLI created and provisioned a disposable arm64 Lima VM, then
ran real read-only Meidoya tasks through Temporal with both Codex CLI 0.149.1
and Claude Code 2.1.234. `node doctor` passed artifact, systemd service,
registration, poller, runtime, mount and credential checks. The mounted Git
fixture stayed clean and a guest write probe was refused by the read-only mount.

The run reused existing Hermes Fleet authentication without modifying its VM:
Codex used `private-file:` and Claude used
`hermes-sops:/absolute/document.sops.yaml#claude.code_oauth_token`. The latter
retrieves the age key from the `hermes-sops-age` / `default` Keychain item and
gives it only to the exact `sops --extract` child invocation. Neither source
places credential values in argv, logs, receipts or the mounted repository.

The disposable VM and its temporary host state were removed after acceptance.
The detailed task evidence is recorded in the sibling Meidoya repository's
`docs/acceptance.md`.

### Provisioning lifecycle

`validate desired config → acquire node lock → create/inspect VM → apply
resource and mount config → install system dependencies → download pinned
artifact → verify checksum → materialize credentials → install
launchd/systemd service → start node → verify registration/heartbeat → write
receipt`, in that order, idempotently, with a read-back after every mutation.
`reprovision` re-runs the whole lifecycle against an existing node.

## Packages

```text
apps/meidoya-yashiki/            CLI (node:util parseArgs)
packages/yashiki-core/           desired config model, NodeProvider interface, mount policy, ports
packages/provider-lima/          limactl wrapper (MVP provider)
packages/provider-native/        node running directly on the host
packages/node-provisioner/       the provisioning lifecycle and node lock
packages/node-bundle/            release manifest pinning, checksum, start refusal
packages/credentials/            credential materialization, revoke, sync
packages/doctor/                 preflight and health checks
packages/receipts/               content hashing, immutable receipt chain
packages/backup/                 backup planning and execution
packages/recovery/               journal + CAS restore with fail-closed postconditions
packages/store-sqlite/           local registry schema and migrations
packages/node-protocol-client/   vendored type-only wire contract (protocol v1)
```

## Development

Node is pinned via [mise](https://mise.jdx.dev/); everything runs through pnpm
workspaces.

```bash
mise install
mise x -- pnpm install
mise x -- pnpm typecheck
mise x -- pnpm lint
mise x -- pnpm build
mise x -- pnpm test
```

Public release security checks and the one-commit publication procedure are in
[`docs/operations/public-release-ja.md`](docs/operations/public-release-ja.md).

The test suite is hermetic: it never requires `limactl`, a VM, the network, a
Keychain or a real filesystem target. Every host interaction goes through an
injectable port (`ProcessPort`, `SecretSourcePort`, `GuestCredentialPort`,
`ArtifactSourcePort`, `NodeServicePort`, `RegistrationVerifierPort`,
`ContentAddressedStorePort`, …) and tests drive fakes.

TypeScript is ESM-only and strict (`strict`, `noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes`, `NodeNext`); relative imports end in `.js`. CI runs
install → typecheck → lint → build → test on macOS and Ubuntu.

Version: `meidoya-yashiki 0.1.0`, independent of `meidoya`'s SemVer; node
protocol `1`.

## Status and remaining work

This repository has now also completed a real Lima acceptance run against the
sibling `meidoya` control plane. The hermetic suite remains the primary
development gate; the VM run proves the provider and service composition that
fakes cannot cover.

Not done, in rough priority order:

- **No mutation gate.** `meidoya` has one (`tools/mutation/`, `pnpm mutation`)
  that fails the build on any surviving mutant. Porting it is the single
  highest-value addition to this repository.
- **No `restore` command.** `recover()` has no production caller. The keying
  mismatch and the encryption gap are fixed and a round trip is proven in tests,
  but wiring the command means deciding what "restore" does to a live node.
- **`applyResourceConfig`** is a provisioner option wired at the composition root
  rather than a method on the `NodeProvider` interface.

Full handoff, including process notes that cost real time to learn:
[`meidoya/docs/HANDOFF.md`](https://github.com/ykawase1011/meidoya/blob/main/docs/HANDOFF.md).
