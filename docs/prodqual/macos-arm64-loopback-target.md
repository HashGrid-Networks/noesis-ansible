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

HARDENING interface consumed (candidate 059c3b5bd80693205bd3e98dd916b650f98e82b8,
Sentinel/Skeptic HARDENING disposition PASS-WITH-COMMENTS, pin_status
pass_with_comments_scoped_hardening_r2):

- schema noesis.approved_release_manifest/v1
- recipe hardening-1-trusted-manifest-runtime/v1
- aggregate digest 9450ccf6b4f84538e3b15053d9a2618011bd89c4e9a9aa0d287b41d88bd37425
- launchd env HERMES_GOVERNED_PRODUCTION, HERMES_APPROVED_RELEASE_MANIFEST,
  HERMES_NOESIS_AUTHORITY_UID, HERMES_NOESIS_WORKER_UID

Policy, not the JSON schema, is the authority for the ordered eight-path
runtime set. A newer Hermes adaptation successor under review must not be silently substituted for this v1 HARDENING pin.

Ansible repository baseline (not the package candidate):
ffb1357d07ccdde0036c82acb47073b9d6770037.

Adopted package parent this successor remediates:
9059a277b753bd3d7bd83f0b4ab0dbd9b2b34c7e.

Trust is authority ownership/mode/path isolation. The environment variable
names the manifest path; it is not the trust source.

Hermes gateway ProgramArguments are `gateway run --external-supervisor`.
The frozen Hermes CLI has no unix-socket or bind-address flag; this unit
does not invent one and does not declare a CLI-configured listener.

Lease-candidate bytes are exposed as variables and are not pinned. Pinning
lease as approved while empty fails closed.
