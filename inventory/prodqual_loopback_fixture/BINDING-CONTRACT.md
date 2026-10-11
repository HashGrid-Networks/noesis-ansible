# Approval-time host binding contract

Target: noesis-prodqual-macos-arm64-loopback-control-plane/v1

This fixture inventory is the reusable identity. It does not name a physical
host. `inventory/production/hosts.ini` must remain without this target until
an independent approval binds a host.

Approval-time extra-vars (not stored in this repository):

- prodqual_approval_inventory_alias
- prodqual_approval_ansible_host (loopback 127.0.0.1 or later-approved admin path)
- prodqual_apply_authorized=true
- prodqual_activation_authorized=true (separate later approval)
- prodqual_canary_authorized=true (separate later approval)
- prodqual_restore_authorized=true (separate later approval)

Forbidden at approval time:

- copying a laptop hostname into the reusable target name
- Tailscale bind for this target
- public 0.0.0.0 bind
- treating uid 501 same-UID prototype units as this target
- pinning unreviewed lease-candidate bytes

Discovered at apply time, never pinned in defaults:

- noesis-authority UniqueID
- noesis-worker UniqueID
- operator UniqueID (must stay distinct)

Offline validation command (does not reach activation):

    ansible-playbook -i inventory/prodqual_loopback_fixture/hosts.ini \
      playbooks/macos-prodqual-loopback-validate.yml --syntax-check

    ansible-playbook -i inventory/prodqual_loopback_fixture/hosts.ini \
      playbooks/macos-prodqual-loopback-validate.yml --check
