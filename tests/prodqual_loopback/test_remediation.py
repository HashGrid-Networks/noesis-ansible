#!/usr/bin/env python3
"""RED/GREEN remediation tests for macos_prodqual_loopback P1 closures.

Stdlib + PyYAML/jinja2 only. Never mutates system paths, launchd, or identities.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

REPO = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO / "roles" / "macos_prodqual_loopback" / "filter_plugins"
sys.path.insert(0, str(POLICY_DIR))
from prodqual_policy import (  # noqa: E402
    REQUIRED_RUNTIME_DIGEST,
    REQUIRED_RUNTIME_FILES,
    prodqual_policy_errors,
)
from test_offline import (  # noqa: E402
    ROLE,
    TEMPLATES,
    PLAYBOOKS,
    SCHEMA,
    load_yaml,
    render_jinja,
    valid_config,
)

try:
    from prodqual_policy import (  # noqa: E402
        prodqual_static_policy_errors,
        prodqual_identity_policy_errors,
        prodqual_live_service_errors,
        prodqual_parse_launchctl_list,
        prodqual_launchd_decision,
        prodqual_bootout_failed_when,
        prodqual_interpret_worker_probe,
        prodqual_hermes_gateway_argv,
        prodqual_backup_copy,
        prodqual_stage_restore,
        prodqual_live_restore,
        prodqual_rollback,
        HERMES_GATEWAY_BIND_CLASS,
    )
except ImportError:  # RED: names do not exist yet
    prodqual_static_policy_errors = None
    prodqual_identity_policy_errors = None
    prodqual_live_service_errors = None
    prodqual_parse_launchctl_list = None
    prodqual_launchd_decision = None
    prodqual_bootout_failed_when = None
    prodqual_interpret_worker_probe = None
    prodqual_hermes_gateway_argv = None
    prodqual_backup_copy = None
    prodqual_stage_restore = None
    prodqual_live_restore = None
    prodqual_rollback = None
    HERMES_GATEWAY_BIND_CLASS = None


def _require(fn, name):
    if fn is None:
        raise AssertionError("missing policy API: %s" % name)
    return fn


class HermesArgvBindTests(unittest.TestCase):
    def test_hermes_argv_is_gateway_run_external_supervisor(self):
        argv = _require(prodqual_hermes_gateway_argv, "prodqual_hermes_gateway_argv")
        self.assertEqual(list(argv()), ["gateway", "run", "--external-supervisor"])

    def test_hermes_plist_encodes_verified_argv_and_no_invented_socket(self):
        defaults = load_yaml(ROLE / "defaults" / "main.yml")
        defaults.update(
            {
                "prodqual_authority_uid": 901,
                "prodqual_worker_uid": 902,
                "prodqual_hardening_candidate_commit": "059c3b5bd80693205bd3e98dd916b650f98e82b8",
                "prodqual_runtime_payload_digest": REQUIRED_RUNTIME_DIGEST,
                "prodqual_ansible_baseline_commit": "ffb1357d07ccdde0036c82acb47073b9d6770037",
                "prodqual_agent_stack_commit": "60ff6377684b09bd2a12816e7ae1e1624fe602a1",
            }
        )
        rendered = render_jinja(
            (TEMPLATES / "ai.hermes.gateway.plist.j2").read_text(encoding="utf-8"),
            defaults,
        )
        self.assertIn("<string>gateway</string>", rendered)
        self.assertIn("<string>run</string>", rendered)
        self.assertIn("<string>--external-supervisor</string>", rendered)
        self.assertNotRegex(
            rendered,
            r"<string>gateway</string>\s*<string>--external-supervisor</string>",
        )
        self.assertNotIn("Sockets", rendered)
        self.assertNotIn("hermes-gateway.sock", rendered)
        self.assertNotIn("unix_socket", rendered)
        self.assertEqual(
            defaults.get("prodqual_hermes_gateway_bind_class"),
            "process_supervised_no_network_listener",
        )
        self.assertEqual(HERMES_GATEWAY_BIND_CLASS, "process_supervised_no_network_listener")

    def test_policy_rejects_unix_socket_claim_and_validates_consumed_bind_class(self):
        static = _require(prodqual_static_policy_errors, "prodqual_static_policy_errors")
        cfg = valid_config(hermes_gateway_bind_class="unix_socket")
        errors = static(cfg)
        self.assertTrue(any("hermes" in item and "unix_socket" in item for item in errors))
        cfg_ok = valid_config(
            hermes_gateway_bind_class="process_supervised_no_network_listener"
        )
        self.assertFalse(
            any("hermes_gateway_bind_class" in item for item in static(cfg_ok))
        )
        cfg_sock = valid_config(
            hermes_gateway_bind_class="process_supervised_no_network_listener",
            hermes_gateway_socket="/tmp/hermes-gateway.sock",
        )
        errors = static(cfg_sock)
        self.assertTrue(any("socket" in item for item in errors))


class FirstApplyUidDiscoveryTests(unittest.TestCase):
    def test_static_policy_passes_without_uids(self):
        static = _require(prodqual_static_policy_errors, "prodqual_static_policy_errors")
        cfg = valid_config()
        cfg["authority_uid"] = None
        cfg["worker_uid"] = None
        cfg["operator_uid"] = None
        cfg["policy_phase"] = "static"
        self.assertEqual(static(cfg), [])
        full = prodqual_policy_errors({**cfg, "policy_phase": "full"})
        self.assertTrue(any("uid" in item.lower() for item in full))

    def test_post_discovery_revalidation_is_full_policy(self):
        identity = _require(
            prodqual_identity_policy_errors, "prodqual_identity_policy_errors"
        )
        cfg = valid_config(authority_uid=902, worker_uid=902, operator_uid=501)
        errors = identity(cfg)
        self.assertTrue(any("distinct from worker" in item for item in errors))
        identity_src = (ROLE / "tasks" / "identity.yml").read_text(encoding="utf-8")
        self.assertIn("prodqual_policy_errors", identity_src)
        self.assertIn("prodqual_uids_discovered", identity_src)
        preflight = (ROLE / "tasks" / "preflight.yml").read_text(encoding="utf-8")
        self.assertIn("policy_phase", preflight)
        self.assertIn("static", preflight)

    def test_live_apply_does_not_require_dummy_uid_extra_vars_in_defaults(self):
        defaults = load_yaml(ROLE / "defaults" / "main.yml")
        self.assertIsNone(defaults["prodqual_authority_uid"])
        self.assertIsNone(defaults["prodqual_worker_uid"])
        self.assertFalse(defaults.get("prodqual_uids_discovered", False))


class DarwinIdentityPrivilegeTests(unittest.TestCase):
    def test_identity_does_not_set_linux_lock_password(self):
        identity = (ROLE / "tasks" / "identity.yml").read_text(encoding="utf-8")
        self.assertNotIn('password: "!"', identity)
        self.assertNotIn("password: '!'", identity)
        self.assertIn(";DisabledUser;", identity)
        self.assertIn("/usr/bin/dscl", identity)
        self.assertIn("become: true", identity)
        self.assertIn("ansible_effective_user_id", identity)

    def test_filesystem_probe_is_darwin_python_setuid_not_su_dash_s(self):
        filesystem = (ROLE / "tasks" / "filesystem.yml").read_text(encoding="utf-8")
        self.assertNotIn("/usr/bin/su", filesystem)
        self.assertNotIn("-s", filesystem)
        self.assertIn("/usr/bin/python3", filesystem)
        self.assertIn("os.setuid", filesystem)
        for path_token in (
            "prodqual_authority_log_root",
            "prodqual_rollback_staging_root",
            "prodqual_runtime_root",
            "prodqual_taskstore_root",
            "prodqual_approval_store",
            "prodqual_backup_root",
            "prodqual_authority_profile_root",
            "prodqual_authority_credential_ref_root",
            "prodqual_authority_launchd_dir",
        ):
            self.assertIn(path_token, filesystem)
        self.assertIn("become: true", filesystem)

    def test_probe_result_interpretation_fail_closed(self):
        interpret = _require(
            prodqual_interpret_worker_probe, "prodqual_interpret_worker_probe"
        )
        self.assertEqual(interpret(13, expect_denied=True), [])
        self.assertTrue(interpret(0, expect_denied=True))
        self.assertTrue(interpret(1, expect_denied=True))
        self.assertTrue(interpret(127, expect_denied=True))
        self.assertEqual(interpret(0, expect_denied=False), [])
        self.assertTrue(interpret(13, expect_denied=False))

    def test_apply_playbook_declares_privilege_contract(self):
        apply_pb = (PLAYBOOKS / "macos-prodqual-loopback.yml").read_text(encoding="utf-8")
        self.assertIn("prodqual_privilege_required", apply_pb)
        activate = (ROLE / "tasks" / "activate.yml").read_text(encoding="utf-8")
        self.assertIn("become: true", activate)
        self.assertIn("ansible_effective_user_id", activate)


class TagBypassTests(unittest.TestCase):
    def test_preflight_and_refuse_use_always_without_skippable_preflight_tag(self):
        main = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("tags: [always]", main)
        self.assertIn("apply:\n      tags: [always]", main)
        apply_pb = (PLAYBOOKS / "macos-prodqual-loopback.yml").read_text(encoding="utf-8")
        self.assertIn("tags: [always]", apply_pb)
        refuse_idx = apply_pb.find("Refuse default apply")
        self.assertGreaterEqual(refuse_idx, 0)
        window = apply_pb[refuse_idx : refuse_idx + 800]
        self.assertIn("always", window)
        preflight = (ROLE / "tasks" / "preflight.yml").read_text(encoding="utf-8")
        self.assertNotRegex(preflight, r"tags:\s*\[.*preflight")

    def test_validate_playbook_structurally_excludes_mutation_tasks(self):
        validate = (PLAYBOOKS / "macos-prodqual-loopback-validate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("tasks_from: offline.yml", validate)
        self.assertNotIn("identity.yml", validate)
        self.assertNotIn("filesystem.yml", validate)
        self.assertNotIn("activate.yml", validate)
        offline = (ROLE / "tasks" / "offline.yml").read_text(encoding="utf-8")
        self.assertNotIn("identity.yml", offline)
        self.assertNotIn("filesystem.yml", offline)
        self.assertNotIn("activate.yml", offline)
        self.assertNotIn("backup_execute.yml", offline)
        self.assertIn("check_mode: true", offline)

    def test_hostile_offline_override_cannot_enable_apply_writes_in_offline_file(self):
        offline = (ROLE / "tasks" / "offline.yml").read_text(encoding="utf-8")
        self.assertNotIn("prodqual_apply_authorized | bool", offline.split("check_mode")[0] if False else offline)
        configure = (ROLE / "tasks" / "configure.yml").read_text(encoding="utf-8")
        self.assertIn("resource-caps.yml.j2", configure)
        apply_caps = [
            line
            for line in configure.splitlines()
            if "resource-caps" in line or "path-policy" in line or "prodqual_apply_authorized" in line
        ]
        self.assertTrue(any("prodqual_apply_authorized" in line for line in configure.splitlines()))


class BackupRestoreRollbackTests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory(prefix="prodqual-iso-")
        self.root = Path(self._tmpdir.name)
        self.src = self.root / "src"
        self.dest = self.root / "dest"
        self.backup = self.root / "backup"
        self.staging = self.root / "staging"
        self.src.mkdir()
        self.dest.mkdir()
        self.backup.mkdir()
        self.staging.mkdir()
        self.file_a = self.src / "manifest.json"
        self.file_a.write_bytes(b"manifest-bytes-v1")
        self.runtime_file = self.src / "runtime" / "agent" / "agent_init.py"
        self.runtime_file.parent.mkdir(parents=True)
        self.runtime_file.write_bytes(b"runtime-bytes-v1")
        self.plist = self.src / "ai.noesis.broker.plist"
        self.plist.write_bytes(b"plist-bytes-v1")

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_backup_copies_file_bytes_and_content_hashes_not_aggregate_digest(self):
        backup_copy = _require(prodqual_backup_copy, "prodqual_backup_copy")
        entries = [
            {
                "class": "manifest",
                "source_path": str(self.file_a),
                "kind": "file",
                "live_path": str(self.dest / "approved-release-manifest.json"),
                "relpath": "payload/approved-release-manifest.json",
                "owner": "noesis-authority",
                "group": "noesis-authority",
                "mode": "0640",
                "flags": "",
            },
            {
                "class": "payload",
                "source_path": str(self.src / "runtime"),
                "kind": "directory",
                "live_path": str(self.dest / "runtime"),
                "relpath": "payload/runtime",
                "owner": "noesis-authority",
                "group": "noesis-authority",
                "mode": "0755",
                "flags": "",
                "files": [
                    {
                        "relpath": "agent/agent_init.py",
                        "source_path": str(self.runtime_file),
                    }
                ],
            },
            {
                "class": "plist",
                "source_path": str(self.plist),
                "kind": "file",
                "live_path": str(self.dest / "ai.noesis.broker.plist"),
                "relpath": "plists/ai.noesis.broker.plist",
                "owner": "root",
                "group": "wheel",
                "mode": "0644",
                "flags": "",
            },
        ]
        result = backup_copy(
            entries,
            backup_root=str(self.backup),
            recognized_checksums=[],
            service_state=[{"label": "ai.noesis.broker", "loaded": False, "pid": None}],
        )
        self.assertEqual(result["errors"], [])
        manifest_hash = hashlib.sha256(b"manifest-bytes-v1").hexdigest()
        runtime_hash = hashlib.sha256(b"runtime-bytes-v1").hexdigest()
        self.assertNotEqual(manifest_hash, REQUIRED_RUNTIME_DIGEST)
        recorded = {item["class"]: item for item in result["entries"] if item["class"] != "payload_file"}
        self.assertEqual(recorded["manifest"]["source_sha256"], manifest_hash)
        payload_files = [item for item in result["entries"] if item.get("class") == "payload_file"]
        self.assertEqual(payload_files[0]["source_sha256"], runtime_hash)
        obj = self.backup / "objects" / manifest_hash
        self.assertTrue(obj.is_file())
        self.assertEqual(obj.read_bytes(), b"manifest-bytes-v1")

    def test_backup_halts_on_unrecognized_file_and_directory_without_manifest(self):
        backup_copy = _require(prodqual_backup_copy, "prodqual_backup_copy")
        live = self.dest / "approved-release-manifest.json"
        live.write_bytes(b"unexpected-live")
        entries = [
            {
                "class": "manifest",
                "source_path": str(self.file_a),
                "kind": "file",
                "live_path": str(live),
                "relpath": "payload/approved-release-manifest.json",
                "owner": "noesis-authority",
                "group": "noesis-authority",
                "mode": "0640",
                "flags": "",
            }
        ]
        result = backup_copy(entries, backup_root=str(self.backup), recognized_checksums=[])
        self.assertTrue(any("unrecognized" in item for item in result["errors"]))
        dir_live = self.dest / "runtime"
        dir_live.mkdir()
        (dir_live / "stray").write_bytes(b"x")
        dir_entries = [
            {
                "class": "payload",
                "source_path": str(self.src / "runtime"),
                "kind": "directory",
                "live_path": str(dir_live),
                "relpath": "payload/runtime",
                "owner": "noesis-authority",
                "group": "noesis-authority",
                "mode": "0755",
                "flags": "",
            }
        ]
        result = backup_copy(dir_entries, backup_root=str(self.backup), recognized_checksums=[])
        self.assertTrue(any("directory" in item and "manifest" in item for item in result["errors"]))

    def test_staged_restore_verifies_hashes_before_live(self):
        backup_copy = _require(prodqual_backup_copy, "prodqual_backup_copy")
        stage = _require(prodqual_stage_restore, "prodqual_stage_restore")
        live = _require(prodqual_live_restore, "prodqual_live_restore")
        entries = [
            {
                "class": "manifest",
                "source_path": str(self.file_a),
                "kind": "file",
                "live_path": str(self.dest / "approved-release-manifest.json"),
                "relpath": "payload/approved-release-manifest.json",
                "owner": "noesis-authority",
                "group": "noesis-authority",
                "mode": "0640",
                "flags": "",
            }
        ]
        backup = backup_copy(entries, backup_root=str(self.backup), recognized_checksums=[])
        staged = stage(backup, staging_root=str(self.staging))
        self.assertEqual(staged["errors"], [])
        staged_path = self.staging / "payload" / "approved-release-manifest.json"
        self.assertEqual(staged_path.read_bytes(), b"manifest-bytes-v1")
        refused = live(
            backup,
            staging_root=str(self.staging),
            restore_authorized=True,
            restore_live_authorized=False,
        )
        self.assertTrue(any("live" in item for item in refused["errors"]))
        self.assertFalse((self.dest / "approved-release-manifest.json").exists())
        applied = live(
            backup,
            staging_root=str(self.staging),
            restore_authorized=True,
            restore_live_authorized=True,
        )
        self.assertEqual(applied["errors"], [])
        self.assertEqual(
            (self.dest / "approved-release-manifest.json").read_bytes(),
            b"manifest-bytes-v1",
        )

    def test_rollback_refuses_unknown_destination_and_restores_known(self):
        backup_copy = _require(prodqual_backup_copy, "prodqual_backup_copy")
        stage = _require(prodqual_stage_restore, "prodqual_stage_restore")
        rollback = _require(prodqual_rollback, "prodqual_rollback")
        live_path = self.dest / "approved-release-manifest.json"
        entries = [
            {
                "class": "manifest",
                "source_path": str(self.file_a),
                "kind": "file",
                "live_path": str(live_path),
                "relpath": "payload/approved-release-manifest.json",
                "owner": "noesis-authority",
                "group": "noesis-authority",
                "mode": "0640",
                "flags": "",
            }
        ]
        backup = backup_copy(entries, backup_root=str(self.backup), recognized_checksums=[])
        stage(backup, staging_root=str(self.staging))
        live_path.write_bytes(b"drift-after-backup")
        unknown = self.dest / "unknown-extra.json"
        unknown.write_bytes(b"do-not-delete")
        refused = rollback(
            backup,
            staging_root=str(self.staging),
            rollback_authorized=True,
            extra_live_paths=[str(unknown)],
        )
        self.assertTrue(any("unknown" in item for item in refused["errors"]))
        self.assertEqual(unknown.read_bytes(), b"do-not-delete")
        ok = rollback(
            backup,
            staging_root=str(self.staging),
            rollback_authorized=True,
            extra_live_paths=[],
        )
        self.assertEqual(ok["errors"], [])
        self.assertEqual(live_path.read_bytes(), b"manifest-bytes-v1")
        self.assertTrue(unknown.exists())

    def test_ansible_backup_tasks_are_not_plan_only(self):
        backup = (ROLE / "tasks" / "backup_execute.yml").read_text(encoding="utf-8")
        self.assertIn("prodqual_backup_copy", backup)
        restore = (ROLE / "tasks" / "restore_execute.yml").read_text(encoding="utf-8")
        self.assertIn("prodqual_stage_restore", restore)
        self.assertIn("prodqual_restore_live_authorized", restore)
        rollback = (ROLE / "tasks" / "rollback_execute.yml").read_text(encoding="utf-8")
        self.assertIn("prodqual_rollback", rollback)
        template = (TEMPLATES / "backup-manifest.json.j2").read_text(encoding="utf-8")
        self.assertNotIn(
            '"source_sha256": "{{ prodqual_runtime_payload_digest }}"', template
        )


class ApplyConfigActivationTests(unittest.TestCase):
    def test_apply_path_renders_resource_caps_and_path_policy(self):
        configure = (ROLE / "tasks" / "configure.yml").read_text(encoding="utf-8")
        self.assertGreaterEqual(configure.count("src: resource-caps.yml.j2"), 2)
        self.assertGreaterEqual(configure.count("src: path-policy.yml.j2"), 2)
        self.assertIn("prodqual_apply_authorized | bool", configure)
        path_policy = (TEMPLATES / "path-policy.yml.j2").read_text(encoding="utf-8")
        self.assertIn("prodqual_authority_log_root", path_policy)
        self.assertIn("prodqual_rollback_staging_root", path_policy)

    def test_launchd_decision_is_idempotent_and_absent_bootout_safe(self):
        decision = _require(prodqual_launchd_decision, "prodqual_launchd_decision")
        self.assertEqual(
            decision(loaded_labels=["ai.noesis.broker"], label="ai.noesis.broker"),
            "skip",
        )
        self.assertEqual(
            decision(loaded_labels=[], label="ai.noesis.broker"),
            "bootstrap",
        )
        bootout = _require(prodqual_bootout_failed_when, "prodqual_bootout_failed_when")
        self.assertFalse(bootout(0, ""))
        self.assertFalse(bootout(113, "Could not find specified service"))
        self.assertTrue(bootout(1, "permission denied"))
        activate = (ROLE / "tasks" / "activate.yml").read_text(encoding="utf-8")
        self.assertIn("prodqual_launchd_decision", activate)
        self.assertNotIn("prodqual_canary_authorized | bool)\n    fail_msg", activate)
        self.assertIn("later external phase", activate)
        handlers = (ROLE / "handlers" / "main.yml").read_text(encoding="utf-8")
        self.assertNotIn("listen: prodqual_load_authority_launchd", handlers)


class LiveStaleLabelTests(unittest.TestCase):
    def test_parse_and_refuse_stale_same_uid_and_unrecognized(self):
        parse = _require(prodqual_parse_launchctl_list, "prodqual_parse_launchctl_list")
        live = _require(prodqual_live_service_errors, "prodqual_live_service_errors")
        stdout = "\n".join(
            [
                "PID\tStatus\tLabel",
                "12\t0\tcom.apple.something",
                "88\t0\tcom.noesis.hermesdev",
                "99\t0\tai.noesis.broker",
                "-\t0\tai.openclaw.gateway",
                "5010\t0\tai.noesis.prototype",
            ]
        )
        loaded = parse(stdout)
        labels = [item["label"] for item in loaded]
        self.assertIn("com.noesis.hermesdev", labels)
        errors = live(
            loaded,
            expected_labels=[
                "ai.noesis.broker",
                "ai.noesis.orchestrator",
                "ai.hermes.gateway",
                "ai.openclaw.gateway",
            ],
            operator_uid=501,
            process_uids={"ai.noesis.prototype": 501, "ai.noesis.broker": 901},
        )
        self.assertTrue(any("com.noesis.hermesdev" in item for item in errors))
        self.assertTrue(any("prototype" in item or "same-UID" in item or "501" in item for item in errors))
        self.assertTrue(any("unrecognized" in item or "conflicting" in item for item in errors))
        preflight = (ROLE / "tasks" / "preflight.yml").read_text(encoding="utf-8")
        self.assertIn("prodqual_live_service_errors", preflight)
        self.assertIn("prodqual_offline_mode", preflight)
        self.assertIn("launchctl", preflight)

    def test_offline_preflight_does_not_invoke_launchctl_unconditionally(self):
        preflight = (ROLE / "tasks" / "preflight.yml").read_text(encoding="utf-8")
        self.assertIn("not (prodqual_offline_mode | bool)", preflight)


class ReleaseMetadataTests(unittest.TestCase):
    def test_hardening_pin_status_is_scoped_not_unreviewed(self):
        defaults = load_yaml(ROLE / "defaults" / "main.yml")
        fixture = load_yaml(
            REPO / "inventory" / "prodqual_loopback_fixture" / "group_vars" / "all.yml"
        )
        self.assertEqual(
            defaults["prodqual_hardening_pin_status"],
            "pass_with_comments_scoped_hardening_r2",
        )
        self.assertEqual(
            fixture["prodqual_hardening_pin_status"],
            "pass_with_comments_scoped_hardening_r2",
        )
        self.assertNotEqual(
            defaults["prodqual_hardening_pin_status"], "unreviewed_pending_sentinel"
        )
        docs = (REPO / "docs" / "prodqual" / "macos-arm64-loopback-target.md").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("unreviewed pending Sentinel", docs)
        self.assertIn("PASS-WITH-COMMENTS", docs)
        self.assertIn("must not be silently substituted", docs)

    def test_baseline_parent_is_not_presented_as_package_candidate(self):
        fixture = load_yaml(
            REPO / "inventory" / "prodqual_loopback_fixture" / "group_vars" / "all.yml"
        )
        self.assertEqual(
            fixture["prodqual_ansible_baseline_commit"],
            "ffb1357d07ccdde0036c82acb47073b9d6770037",
        )
        self.assertEqual(
            fixture.get("prodqual_package_parent_commit"),
            "9059a277b753bd3d7bd83f0b4ab0dbd9b2b34c7e",
        )
        docs = (REPO / "docs" / "prodqual" / "macos-arm64-loopback-target.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Ansible repository baseline", docs)
        self.assertIn("not the package candidate", docs)
        self.assertEqual(fixture["prodqual_lease_candidate_commit"], "")
        self.assertEqual(
            fixture["prodqual_lease_candidate_status"], "pending_successor_review"
        )

    def test_policy_not_schema_is_runtime_path_authority(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertNotIn("const", schema["properties"]["files"].get("items", {}).get("properties", {}).get("path", {}))
        self.assertEqual(list(REQUIRED_RUNTIME_FILES)[0], "agent/agent_init.py")
        self.assertEqual(len(REQUIRED_RUNTIME_FILES), 8)
        cfg = valid_config(lease_candidate_commit="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", lease_candidate_status="approved")
        errors = prodqual_policy_errors(cfg)
        self.assertTrue(any("approved" in item or "pending" in item for item in errors))


if __name__ == "__main__":
    unittest.main(verbosity=2)
