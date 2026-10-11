# macOS prodqual loopback target

Role `macos_prodqual_loopback` is the fail-closed Ansible package for
`noesis-prodqual-macos-arm64-loopback-control-plane/v1`.

It is not wired into `site.yml` or `master-stack.yml`. It does not add a host
to `inventory/production/hosts.ini`.

This package does not claim unrestricted production approval.

Phases:

- offline_validation — default; templates and asserts only; tasks_from offline.yml
- install — identity + filesystem, requires prodqual_apply_authorized and root
- activation — idempotent launchd bootstrap, requires prodqual_activation_authorized
- bounded_canary — later external phase; in-role authorization is refused
- backup / staged restore / rollback — separately gated execute files

## Release composition (qualified adaptation v2)

| Slot | Identity |
|---|---|
| Noesis combined tree | `7f42dc7785507b41e61885e7d8000e703637e305` (branch `a6-checkpoint/2026-10-11`; 19-path digest `83ceef9bc1122413f2aaa83fa33aaee8019bb17033d5df5a575fbf77f33853a7`; Sentinel r4 `adfd713b…` PASS-WITH-COMMENTS; Skeptic r1 `91d0f0dc…` APPROVED-WITH-COMMENTS; combined-tree Sentinel `f9956b1d…` / Skeptic `fc565c25…`) |
| Hermes runtime payload | adaptation successor `d70372b6ce35c3a0f1243fda8d810c3e24c16940` (branch `prodqual/combined-runtime-2026-10-11`, parent `b2ad468e…`, grandparent qualified HARDENING `059c3b5b…`); recipe `hardening-1-trusted-manifest-runtime/v2`; candidate id `prodqual-hermes-adaptation-successor/v1`; 11 ordered paths, digest `3314ff8e88e1433bc0d9bf2ba6cd08efb7be99132ee79a8d6eaea6a9c398eb01`; Sentinel r2 `b76acf85…`; Skeptic r1 `2a30fd3b…` |
| Ansible baseline | `ffb1357d07ccdde0036c82acb47073b9d6770037` (source checkout, unchanged) |
| Lease pin | qualified `7f42dc7785507b41e61885e7d8000e703637e305` (status `approved_with_comments_lease_sentinel_r4_skeptic_r1`) |

Package `ba6911a54787861f748a526fce7ff18926c7740d` is SUPERSEDED by this
successor and is retained as historical evidence. Do not rewrite it.

The adaptation is NOT a silent drop-in. Its ancestry (child of `b2ad468e…`,
grandparent `059c3b5b…`) and its two-file delta beyond the qualified HARDENING
parent are the reviewed basis. A different Hermes tree must not be silently substituted for this v2 pin.

Publication plan dependency: `d70372b6…` currently exists only in the local
adaptation worktree; phase A (release publication) must publish it before any
apply, and offline validation must reconstruct the exact 11-file bytes from the
published source (hashes in role defaults are the check).

Consumed interface:

- schema noesis.approved_release_manifest/v1
- recipe hardening-1-trusted-manifest-runtime/v2
- aggregate digest 3314ff8e88e1433bc0d9bf2ba6cd08efb7be99132ee79a8d6eaea6a9c398eb01
- pin_status approved_with_comments_adaptation_sentinel_r2_skeptic_r1
  (scoped; not unrestricted production approval)
- launchd env HERMES_GOVERNED_PRODUCTION, HERMES_APPROVED_RELEASE_MANIFEST,
  HERMES_NOESIS_AUTHORITY_UID, HERMES_NOESIS_WORKER_UID

Policy, not the JSON schema, is the authority for the ordered eleven-path
runtime set.

Ansible repository baseline (not the package candidate):
ffb1357d07ccdde0036c82acb47073b9d6770037.

Trust is authority ownership/mode/path isolation. The environment variable
names the manifest path; it is not the trust source.

Hermes gateway ProgramArguments are `gateway run --external-supervisor`.
The frozen Hermes CLI has no unix-socket or bind-address flag; this unit
does not invent one and does not declare a CLI-configured listener.

Lease-candidate bytes are pinned to the qualified combined tree
`7f42dc77…` with scoped status
`approved_with_comments_lease_sentinel_r4_skeptic_r1`. Generic `approved`
remains fail-closed.
