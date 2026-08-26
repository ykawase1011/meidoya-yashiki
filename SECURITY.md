# Security Policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability, credential, token, private key, personal data,
or a log that may contain any of them. Use GitHub's private vulnerability reporting for this
repository instead.

If a credential may have been exposed, revoke or rotate it before investigating or rewriting
Git history. Treat deletion from the current branch as insufficient because commits, forks,
pull-request refs, caches, artifacts, and existing clones may retain the value.

## Supported version

Security fixes target the current `main` branch. Older commits and local deployments are not
maintained as separate supported releases.

## Repository safeguards

- Runtime credentials belong outside the checkout. Yashiki reads them from configured Keychain,
  SOPS, or private-file sources and transfers values to the guest over stdin.
- Generated data, databases, token files, private keys, `.env` files, and local configuration are
  excluded from Git.
- Receipts, doctor output, terminal output, child argv, and child environments pass through the
  secret guard before reaching their sink.
- CI scans the complete reachable Git history with Gitleaks before other checks complete.
- CI fails when the lockfile contains a known dependency vulnerability of moderate severity or
  higher.
- Workflow permissions are read-only and third-party Actions are pinned to commit SHAs.
