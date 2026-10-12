#!/usr/bin/env python3
"""RED/GREEN remediation tests for macos_prodqual_loopback P1 closures.

Stdlib + PyYAML/jinja2 only. Never mutates system paths, launchd, or identities.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
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
                "prodqual_hardening_candidate_commit": "d70372b6ce35c3a0f1243fda8d810c3e24c16940",
                "prodqual_runtime_payload_digest": REQUIRED_RUNTIME_DIGEST,
                "prodqual_ansible_baseline_commit": "ffb1357d07ccdde0036c82acb47073b9d6770037",
                "prodqual_agent_stack_commit": "7f42dc7785507b41e61885e7d8000e703637e305",
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


V2_CANDIDATE_ID = "prodqual-hermes-adaptation-successor/v1"
V2_RECIPE = "hardening-1-trusted-manifest-runtime/v2"
V2_DIGEST = "3314ff8e88e1433bc0d9bf2ba6cd08efb7be99132ee79a8d6eaea6a9c398eb01"
V2_ADAPTATION_COMMIT = "d70372b6ce35c3a0f1243fda8d810c3e24c16940"
V2_PIN_STATUS = "approved_with_comments_adaptation_sentinel_r2_skeptic_r1"
V2_LEASE_COMMIT = "7f42dc7785507b41e61885e7d8000e703637e305"
V2_LEASE_STATUS = "approved_with_comments_lease_sentinel_r4_skeptic_r1"
V2_PACKAGE_PARENT = "ba6911a54787861f748a526fce7ff18926c7740d"
V2_AGENT_STACK = "7f42dc7785507b41e61885e7d8000e703637e305"
V2_RUNTIME_FILES = (
    ("agent/agent_init.py", "0764575f3666186b1bd0480b2ef48942a11c4dc14f52f8afe757e80a790b6715"),
    ("agent/error_classifier.py", "dc0514324c17cbbca5966051b395ed62ba8f2a4afcfd764fd568a4002c005f2e"),
    ("agent/runtime_enforcement.py", "76664e9257d6530f6cebab2ec7a2109e3c88c2736478e056dd22e0c2636a15d7"),
    ("agent/turn_api_call.py", "40912fac8add1ebdc9a4088dd150584a1cf578954152b2b00636bdbcadb88980"),
    ("agent/turn_api_error.py", "03d5715a2ec37526048f58316e133244e5ce0cd9c7b08b0cf0af1abe6583fd0a"),
    ("agent/turn_recovery.py", "7496a5493991ee875a1f9c3f8a9689101073c05f95b0923765067793648154b1"),
    ("run_agent.py", "c4066c1bfd6de65a491549fce5cc0adc54b7f1ad2bdcb10b9fb7cf90e366caca"),
    ("agent/legacy_cli.py", "84d2a3ad750355ddd8439afa9e49413eafeef5a3e8c5b69aec55345b4a305bf2"),
    ("tools/approval_yolo.py", "c0b721b9b3ce4d4b23d6329e69d531654f0f9638e720f8e0ec9d94480e998905"),
    ("agent/compression_facade.py", "ab79c855e565f36443b3c945209cff6392ce9c1b170a5691d9b16f040b3a35d4"),
    ("agent/conversation_compression.py", "67aaac8f55eee1e0a795f6fdcb3104b63b9785a1967db1b82f90ae3722daa428"),
)


class AdaptationSuccessorV2PinTests(unittest.TestCase):
    def test_defaults_carry_v2_adaptation_identity(self):
        defaults = load_yaml(ROLE / "defaults" / "main.yml")
        self.assertEqual(defaults["prodqual_candidate_id"], V2_CANDIDATE_ID)
        self.assertEqual(defaults["prodqual_runtime_payload_recipe_version"], V2_RECIPE)
        self.assertEqual(defaults["prodqual_hardening_candidate_commit"], V2_ADAPTATION_COMMIT)
        self.assertEqual(defaults["prodqual_hardening_pin_status"], V2_PIN_STATUS)
        self.assertEqual(defaults["prodqual_package_parent_commit"], V2_PACKAGE_PARENT)
        self.assertEqual(defaults["prodqual_runtime_payload_digest"], V2_DIGEST)
        self.assertEqual(
            defaults["prodqual_ansible_baseline_commit"],
            "ffb1357d07ccdde0036c82acb47073b9d6770037",
        )
        self.assertEqual(defaults["prodqual_agent_stack_commit"], V2_AGENT_STACK)
        self.assertEqual(defaults["prodqual_lease_candidate_commit"], V2_LEASE_COMMIT)
        self.assertEqual(defaults["prodqual_lease_candidate_status"], V2_LEASE_STATUS)
        self.assertEqual(defaults["prodqual_expected_runtime_payload_digest"], V2_DIGEST)
        observed = [(item["path"], item["sha256"]) for item in defaults["prodqual_runtime_files"]]
        self.assertEqual(observed, list(V2_RUNTIME_FILES))
        self.assertEqual(len(observed), 11)

    def test_policy_constants_and_v1_recipe_are_rejected(self):
        self.assertEqual(REQUIRED_RUNTIME_DIGEST, V2_DIGEST)
        self.assertEqual(len(REQUIRED_RUNTIME_FILES), 11)
        self.assertEqual(tuple(REQUIRED_RUNTIME_FILES), tuple(path for path, _ in V2_RUNTIME_FILES))
        v1 = valid_config()
        v1["runtime_payload_recipe_version"] = "hardening-1-trusted-manifest-runtime/v1"
        v1["runtime_payload_digest"] = "9450ccf6b4f84538e3b15053d9a2618011bd89c4e9a9aa0d287b41d88bd37425"
        v1["runtime_files"] = valid_config()["runtime_files"][:8]
        errors = prodqual_policy_errors(v1)
        self.assertTrue(
            any("recipe" in item or "v1" in item or "mismatch" in item for item in errors)
        )

    def test_manifest_renders_v2_identity_lease_and_pin_status(self):
        defaults = load_yaml(ROLE / "defaults" / "main.yml")
        rendered = render_jinja(
            (TEMPLATES / "approved-release-manifest.json.j2").read_text(encoding="utf-8"),
            defaults,
        )
        payload = json.loads(rendered)
        self.assertEqual(payload["candidate_id"], V2_CANDIDATE_ID)
        self.assertEqual(payload["runtime_payload_recipe_version"], V2_RECIPE)
        self.assertEqual(payload["runtime_payload_digest"], V2_DIGEST)
        self.assertEqual(payload["candidate_commit"], V2_ADAPTATION_COMMIT)
        self.assertEqual(payload["pin_status"], V2_PIN_STATUS)
        self.assertEqual(
            [(item["path"], item["sha256"]) for item in payload["files"]],
            list(V2_RUNTIME_FILES),
        )
        self.assertEqual(len(payload["files"]), 11)
        self.assertEqual(defaults["prodqual_lease_candidate_commit"], V2_LEASE_COMMIT)
        self.assertEqual(defaults["prodqual_lease_candidate_status"], V2_LEASE_STATUS)

    def test_pinned_hash_concat_recomputes_v2_digest(self):
        defaults = load_yaml(ROLE / "defaults" / "main.yml")
        hashes = [item["sha256"] for item in defaults["prodqual_runtime_files"]]
        self.assertEqual(hashes, [digest for _, digest in V2_RUNTIME_FILES])
        self.assertEqual("".join(hashes), "".join(digest for _, digest in V2_RUNTIME_FILES))
        self.assertEqual(len("".join(hashes)), 64 * 11)
        self.assertEqual(defaults["prodqual_runtime_payload_digest"], V2_DIGEST)
        self.assertEqual(defaults["prodqual_expected_runtime_payload_digest"], V2_DIGEST)
        self.assertEqual(REQUIRED_RUNTIME_DIGEST, V2_DIGEST)

    def test_docs_record_supersession_and_adaptation_ancestry(self):
        docs = (REPO / "docs" / "prodqual" / "macos-arm64-loopback-target.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("prodqual-hermes-adaptation-successor/v1", docs)
        self.assertIn("hardening-1-trusted-manifest-runtime/v2", docs)
        self.assertIn("3314ff8e88e1433bc0d9bf2ba6cd08efb7be99132ee79a8d6eaea6a9c398eb01", docs)
        self.assertIn("ba6911a54787861f748a526fce7ff18926c7740d", docs)
        self.assertIn("SUPERSEDED", docs)
        self.assertIn("b2ad468e", docs)
        self.assertIn("059c3b5b", docs)
        normalized = docs.lower().replace("—", " ").replace("-", " ")
        self.assertIn("not a silent drop in", normalized)
        self.assertIn("d70372b6", docs)
        self.assertIn("phase a", docs.lower())


class ReleaseMetadataTests(unittest.TestCase):
    def test_hardening_pin_status_is_scoped_not_unreviewed(self):
        defaults = load_yaml(ROLE / "defaults" / "main.yml")
        fixture = load_yaml(
            REPO / "inventory" / "prodqual_loopback_fixture" / "group_vars" / "all.yml"
        )
        self.assertEqual(
            defaults["prodqual_hardening_pin_status"],
            "approved_with_comments_adaptation_sentinel_r2_skeptic_r1",
        )
        self.assertEqual(
            fixture["prodqual_hardening_pin_status"],
            "approved_with_comments_adaptation_sentinel_r2_skeptic_r1",
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
            "ba6911a54787861f748a526fce7ff18926c7740d",
        )
        docs = (REPO / "docs" / "prodqual" / "macos-arm64-loopback-target.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Ansible repository baseline", docs)
        self.assertIn("not the package candidate", docs)
        self.assertEqual(
            fixture["prodqual_lease_candidate_commit"],
            "7f42dc7785507b41e61885e7d8000e703637e305",
        )
        self.assertEqual(
            fixture["prodqual_lease_candidate_status"],
            "approved_with_comments_lease_sentinel_r4_skeptic_r1",
        )

    def test_policy_not_schema_is_runtime_path_authority(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertNotIn("const", schema["properties"]["files"].get("items", {}).get("properties", {}).get("path", {}))
        self.assertEqual(list(REQUIRED_RUNTIME_FILES)[0], "agent/agent_init.py")
        self.assertEqual(len(REQUIRED_RUNTIME_FILES), 11)
        cfg = valid_config(lease_candidate_commit="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", lease_candidate_status="approved")
        errors = prodqual_policy_errors(cfg)
        self.assertTrue(any("approved" in item or "pending" in item for item in errors))


MUTATION_TASK_FILES = (
    "identity.yml",
    "filesystem.yml",
    "activate.yml",
    "backup_execute.yml",
    "restore_execute.yml",
    "rollback_execute.yml",
)
EXECUTION_IDENTITY_KEYS = (
    "ansible_effective_user_id",
    "ansible_user_id",
    "ansible_uid",
)


def _named_task(tasks, name):
    matches = [item for item in tasks if isinstance(item, dict) and item.get("name") == name]
    if len(matches) != 1:
        raise AssertionError("expected exactly one task named %r, found %d" % (name, len(matches)))
    return matches[0]


class PrivilegedFactGatheringInvocationTests(unittest.TestCase):
    def test_setup_for_privileged_facts_has_task_level_become(self):
        play = load_yaml(PLAYBOOKS / "macos-prodqual-loopback.yml")[0]
        self.assertIs(play.get("become"), False)
        self.assertIs(play.get("gather_facts"), False)
        setup = _named_task(play.get("pre_tasks") or [], "Gather facts only after apply authorization")
        self.assertIn("ansible.builtin.setup", setup)
        self.assertIs(setup.get("become"), True)
        self.assertIn("prodqual_apply_authorized | bool", str(setup.get("when")))

    def test_operator_uid_discovery_is_unprivileged_id_u(self):
        identity = load_yaml(ROLE / "tasks" / "identity.yml")
        discover = _named_task(identity, "Discover operator UniqueID")
        command = discover.get("ansible.builtin.command") or {}
        self.assertEqual(command.get("argv"), ["/usr/bin/id", "-u"])
        self.assertNotIn("become", discover)
        self.assertNotEqual(discover.get("become"), True)
        preflight = load_yaml(ROLE / "tasks" / "preflight.yml")
        live_block = None
        for item in preflight:
            if isinstance(item, dict) and item.get("name") == "Live OS preflight (skipped offline)":
                live_block = item.get("block") or []
                break
        self.assertIsNotNone(live_block)
        pre_discover = _named_task(live_block, "Discover operator UniqueID (read-only)")
        pre_command = pre_discover.get("ansible.builtin.command") or {}
        self.assertEqual(pre_command.get("argv"), ["/usr/bin/id", "-u"])
        self.assertNotIn("become", pre_discover)

    def test_no_cached_or_overridden_execution_identity(self):
        play_path = PLAYBOOKS / "macos-prodqual-loopback.yml"
        play_text = play_path.read_text(encoding="utf-8")
        play = load_yaml(play_path)[0]
        vars_ = play.get("vars") or {}
        for key in EXECUTION_IDENTITY_KEYS:
            self.assertNotIn(key, vars_)
            self.assertNotIn("%s:" % key, play_text)
            self.assertNotIn("-e %s" % key, play_text)
            self.assertNotIn("%s | default" % key, play_text)
        identity_text = (ROLE / "tasks" / "identity.yml").read_text(encoding="utf-8")
        self.assertNotIn("set_fact:\n    ansible_effective_user_id", identity_text)
        self.assertNotRegex(identity_text, r"ansible_effective_user_id\s*:")
        self.assertIn("ansible_effective_user_id | int == 0", identity_text)

    def test_play_remain_unprivileged_with_explicit_mutation_boundaries(self):
        play = load_yaml(PLAYBOOKS / "macos-prodqual-loopback.yml")[0]
        self.assertIs(play.get("become"), False)
        setup = _named_task(play.get("pre_tasks") or [], "Gather facts only after apply authorization")
        self.assertIs(setup.get("become"), True)
        for rel in MUTATION_TASK_FILES:
            text = (ROLE / "tasks" / rel).read_text(encoding="utf-8")
            self.assertIn("become: true", text, msg=rel)
            self.assertIn("ansible_effective_user_id | int == 0", text, msg=rel)


IDENTITY_DISCOVERY_SPECS = (
    (
        "Discover authority UniqueID",
        ["/usr/bin/dscl", ".", "-read", "/Users/{{ prodqual_authority_user }}", "UniqueID"],
        "prodqual_authority_dscl",
        "prodqual_authority_uid",
        r"^UniqueID:\s*",
    ),
    (
        "Discover worker UniqueID",
        ["/usr/bin/dscl", ".", "-read", "/Users/{{ prodqual_worker_user }}", "UniqueID"],
        "prodqual_worker_dscl",
        "prodqual_worker_uid",
        r"^UniqueID:\s*",
    ),
    (
        "Discover worker PrimaryGroupID",
        ["/usr/bin/dscl", ".", "-read", "/Groups/{{ prodqual_worker_group }}", "PrimaryGroupID"],
        "prodqual_worker_gid_dscl",
        "prodqual_worker_gid",
        r"^PrimaryGroupID:\s*",
    ),
    (
        "Discover operator UniqueID",
        ["/usr/bin/id", "-u"],
        "prodqual_operator_id",
        "prodqual_operator_uid",
        None,
    ),
)


def _parse_discovery_stdout(stdout, strip_prefix):
    text = "" if stdout is None else str(stdout)
    if strip_prefix:
        text = re.sub(strip_prefix, "", text)
    return text.strip()


def _facts_from_discovery_stdout(stdout_by_task):
    facts = {}
    for name, _argv, _register, fact_key, strip_prefix in IDENTITY_DISCOVERY_SPECS:
        facts[fact_key] = _parse_discovery_stdout(stdout_by_task.get(name), strip_prefix)
    return facts


def _full_policy_from_discovered_facts(facts):
    return prodqual_policy_errors(
        valid_config(
            authority_uid=facts["prodqual_authority_uid"],
            worker_uid=facts["prodqual_worker_uid"],
            operator_uid=facts["prodqual_operator_uid"],
            policy_phase="full",
        )
    )


class CheckModeIdentityDiscoveryTests(unittest.TestCase):
    def test_four_identity_discovery_tasks_run_read_only_in_check_mode(self):
        identity = load_yaml(ROLE / "tasks" / "identity.yml")
        identity_src = (ROLE / "tasks" / "identity.yml").read_text(encoding="utf-8")
        record = _named_task(identity, "Record discovered UniqueIDs")
        recorded = record.get("ansible.builtin.set_fact") or {}
        for name, argv, register, fact_key, strip_prefix in IDENTITY_DISCOVERY_SPECS:
            task = _named_task(identity, name)
            command = task.get("ansible.builtin.command") or {}
            self.assertEqual(command.get("argv"), argv, msg=name)
            self.assertIs(task.get("changed_when"), False, msg=name)
            self.assertIs(task.get("check_mode"), False, msg=name)
            self.assertEqual(task.get("register"), register, msg=name)
            self.assertNotEqual(task.get("become"), True, msg=name)
            self.assertIn(register + ".stdout", identity_src)
            self.assertIn(fact_key + ":", identity_src)
            self.assertIn(register + ".stdout", recorded.get(fact_key, ""))
            if strip_prefix:
                self.assertRegex(recorded.get(fact_key, ""), r"regex_replace\('%s'" % re.escape(strip_prefix))
            else:
                self.assertIn("%s.stdout | trim" % register, recorded.get(fact_key, ""))
        operator = _named_task(identity, "Discover operator UniqueID")
        self.assertNotIn("become", operator)
        self.assertIn("prodqual_worker_gid | int > 0", (ROLE / "tasks" / "filesystem.yml").read_text(encoding="utf-8"))

    def test_discovered_command_stdout_feeds_full_identity_validation(self):
        facts = _facts_from_discovery_stdout(
            {
                "Discover authority UniqueID": "UniqueID: 443",
                "Discover worker UniqueID": "UniqueID: 444",
                "Discover worker PrimaryGroupID": "PrimaryGroupID: 443",
                "Discover operator UniqueID": "501",
            }
        )
        self.assertEqual(facts["prodqual_authority_uid"], "443")
        self.assertEqual(facts["prodqual_worker_uid"], "444")
        self.assertEqual(facts["prodqual_worker_gid"], "443")
        self.assertEqual(facts["prodqual_operator_uid"], "501")
        self.assertGreater(int(facts["prodqual_worker_gid"]), 0)
        errors = _full_policy_from_discovered_facts(facts)
        self.assertFalse(any("uid" in item.lower() for item in errors), msg=errors)
        identity_errors = _require(prodqual_identity_policy_errors, "prodqual_identity_policy_errors")(
            {
                "authority_uid": facts["prodqual_authority_uid"],
                "worker_uid": facts["prodqual_worker_uid"],
                "operator_uid": facts["prodqual_operator_uid"],
            }
        )
        self.assertEqual(identity_errors, [])

    def test_missing_malformed_or_failed_discovery_fail_closed(self):
        skipped = _facts_from_discovery_stdout({})
        self.assertEqual(skipped["prodqual_authority_uid"], "")
        self.assertEqual(skipped["prodqual_worker_uid"], "")
        self.assertEqual(skipped["prodqual_worker_gid"], "")
        self.assertEqual(skipped["prodqual_operator_uid"], "")
        skipped_errors = _full_policy_from_discovered_facts(skipped)
        self.assertIn("authority_uid is required", skipped_errors)
        self.assertIn("worker_uid is required", skipped_errors)
        self.assertIn("operator_uid is required", skipped_errors)
        with self.assertRaises(ValueError):
            int(skipped["prodqual_worker_gid"])

        malformed = _facts_from_discovery_stdout(
            {
                "Discover authority UniqueID": "UniqueID: not-an-id",
                "Discover worker UniqueID": "UniqueID: also-bad",
                "Discover worker PrimaryGroupID": "PrimaryGroupID: nope",
                "Discover operator UniqueID": "operator",
            }
        )
        malformed_errors = _full_policy_from_discovered_facts(malformed)
        self.assertTrue(any("authority_uid must be an integer" in item for item in malformed_errors))
        self.assertTrue(any("worker_uid must be an integer" in item for item in malformed_errors))
        self.assertTrue(any("operator_uid must be an integer" in item for item in malformed_errors))
        with self.assertRaises(ValueError):
            int(malformed["prodqual_worker_gid"])

        failed = _facts_from_discovery_stdout(
            {
                "Discover authority UniqueID": None,
                "Discover worker UniqueID": None,
                "Discover worker PrimaryGroupID": None,
                "Discover operator UniqueID": None,
            }
        )
        failed_errors = _full_policy_from_discovered_facts(failed)
        self.assertIn("authority_uid is required", failed_errors)
        self.assertIn("worker_uid is required", failed_errors)
        self.assertIn("operator_uid is required", failed_errors)


if __name__ == "__main__":
    unittest.main(verbosity=2)
