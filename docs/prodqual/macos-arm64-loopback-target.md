# macOS prodqual loopback target

Role `macos_prodqual_loopback` is the fail-closed Ansible package for
`noesis-prodqual-macos-arm64-loopback-control-plane/v1`.

It is not wired into `site.yml` or `master-stack.yml`. It does not add a host
to `inventory/production/hosts.ini`.

Phases:

- offline_validation — default; templates and asserts only
- install — identity + filesystem, requires prodqual_apply_authorized
- activation — launchd bootstrap, requires prodqual_activation_authorized
- bounded_canary — requires prodqual_canary_authorized
- rollback — requires prodqual_apply_authorized and prodqual_restore_authorized

HARDENING interface consumed (candidate 059c3b5bd80693205bd3e98dd916b650f98e82b8,
unreviewed pending Sentinel):

- schema noesis.approved_release_manifest/v1
- recipe hardening-1-trusted-manifest-runtime/v1
- aggregate digest 9450ccf6b4f84538e3b15053d9a2618011bd89c4e9a9aa0d287b41d88bd37425
- launchd env HERMES_GOVERNED_PRODUCTION, HERMES_APPROVED_RELEASE_MANIFEST,
  HERMES_NOESIS_AUTHORITY_UID, HERMES_NOESIS_WORKER_UID

Trust is authority ownership/mode/path isolation. The environment variable
names the manifest path; it is not the trust source.

Lease-candidate bytes are exposed as variables and are not pinned.
