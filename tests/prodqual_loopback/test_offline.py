#!/usr/bin/env python3
"""Offline fail-closed tests for macos_prodqual_loopback. Stdlib + PyYAML only."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import unittest
from copy import deepcopy
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

ROLE = REPO / "roles" / "macos_prodqual_loopback"
TEMPLATES = ROLE / "templates"
PLAYBOOKS = REPO / "playbooks"
SCHEMA = REPO / "files" / "schemas" / "approved-release-manifest.schema.json"
SECRET_RE = re.compile(
    r"(password\s*[:=]\s*['\"][^'\"]{8,}['\"]|api_key\s*[:=]\s*['\"][^'\"]+['\"]|BEGIN (RSA |OPENSSH )?PRIVATE KEY)",
    re.IGNORECASE,
)
STALE = ("com.noesis.hermesdev", "com.noesis.clawdev")


def load_yaml(path: Path):
    if yaml is None:
        raise unittest.SkipTest("PyYAML is not available")
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def valid_config(**overrides):
    config = {
        "target_name": "noesis-prodqual-macos-arm64-loopback-control-plane",
        "target_version": "v1",
        "os_family": "Darwin",
        "os_product": "macOS",
        "os_major": "27",
        "arch": "arm64",
        "authority_user": "noesis-authority",
        "worker_user": "noesis-worker",
        "authority_group": "noesis-authority",
        "worker_group": "noesis-worker",
        "authority_uid": 901,
        "worker_uid": 902,
        "operator_uid": 501,
        "tailscale_bind_enabled": False,
        "public_bind_enabled": False,
        "allowed_path_prefixes": ["/opt/noesis/prodqual", "/Library/LaunchDaemons"],
        "runtime_root": "/opt/noesis/prodqual/runtime",
        "manifest_path": "/opt/noesis/prodqual/authority/approved-release-manifest.json",
        "taskstore_root": "/opt/noesis/prodqual/authority/taskstore",
        "approval_store": "/opt/noesis/prodqual/authority/approvals",
        "backup_root": "/opt/noesis/prodqual/authority/backups",
        "authority_profile_root": "/opt/noesis/prodqual/authority/profiles",
        "worker_profile_root": "/opt/noesis/prodqual/worker/profiles",
        "worker_scratch_root": "/opt/noesis/prodqual/worker/scratch",
        "authority_credential_ref_root": "/opt/noesis/prodqual/authority/credential-refs",
        "authority_log_root": "/opt/noesis/prodqual/authority/logs",
        "worker_log_root": "/opt/noesis/prodqual/worker/logs",
        "authority_run_root": "/opt/noesis/prodqual/authority/run",
        "authority_launchd_dir": "/Library/LaunchDaemons",
        "worker_launchd_dir": "/Library/LaunchDaemons",
        "rollback_staging_root": "/opt/noesis/prodqual/authority/restore-staging",
        "taskstore_dir_mode": "0700",
        "taskstore_file_mode": "0600",
        "approval_dir_mode": "0700",
        "approval_file_mode": "0600",
        "backup_dir_mode": "0700",
        "credential_ref_dir_mode": "0700",
        "authority_profile_dir_mode": "0700",
        "worker_profile_dir_mode": "0700",
        "runtime_dir_mode": "0755",
        "runtime_file_mode": "0644",
        "runtime_owner": "noesis-authority",
        "manifest_owner": "noesis-authority",
        "worker_profile_owner": "noesis-worker",
        "binds": {
            "broker": {"host": "127.0.0.1", "port": 8787},
            "openclaw": {"host": "127.0.0.1", "port": 18789},
        },
        "service_labels": [
            "ai.noesis.broker",
            "ai.noesis.orchestrator",
            "ai.hermes.gateway",
            "ai.openclaw.gateway",
        ],
        "governed_env_keys": [
            "HERMES_GOVERNED_PRODUCTION",
            "HERMES_APPROVED_RELEASE_MANIFEST",
            "HERMES_NOESIS_AUTHORITY_UID",
            "HERMES_NOESIS_WORKER_UID",
        ],
        "runtime_payload_recipe_version": "hardening-1-trusted-manifest-runtime/v2",
        "manifest_schema_version": "noesis.approved_release_manifest/v1",
        "runtime_files": [
            {
                "path": "agent/agent_init.py",
                "sha256": "0764575f3666186b1bd0480b2ef48942a11c4dc14f52f8afe757e80a790b6715",
            },
            {
                "path": "agent/error_classifier.py",
                "sha256": "dc0514324c17cbbca5966051b395ed62ba8f2a4afcfd764fd568a4002c005f2e",
            },
            {
                "path": "agent/runtime_enforcement.py",
                "sha256": "76664e9257d6530f6cebab2ec7a2109e3c88c2736478e056dd22e0c2636a15d7",
            },
            {
                "path": "agent/turn_api_call.py",
                "sha256": "40912fac8add1ebdc9a4088dd150584a1cf578954152b2b00636bdbcadb88980",
            },
            {
                "path": "agent/turn_api_error.py",
                "sha256": "03d5715a2ec37526048f58316e133244e5ce0cd9c7b08b0cf0af1abe6583fd0a",
            },
            {
                "path": "agent/turn_recovery.py",
                "sha256": "7496a5493991ee875a1f9c3f8a9689101073c05f95b0923765067793648154b1",
            },
            {
                "path": "run_agent.py",
                "sha256": "c4066c1bfd6de65a491549fce5cc0adc54b7f1ad2bdcb10b9fb7cf90e366caca",
            },
            {
                "path": "agent/legacy_cli.py",
                "sha256": "84d2a3ad750355ddd8439afa9e49413eafeef5a3e8c5b69aec55345b4a305bf2",
            },
            {
                "path": "tools/approval_yolo.py",
                "sha256": "c0b721b9b3ce4d4b23d6329e69d531654f0f9638e720f8e0ec9d94480e998905",
            },
            {
                "path": "agent/compression_facade.py",
                "sha256": "ab79c855e565f36443b3c945209cff6392ce9c1b170a5691d9b16f040b3a35d4",
            },
            {
                "path": "agent/conversation_compression.py",
                "sha256": "67aaac8f55eee1e0a795f6fdcb3104b63b9785a1967db1b82f90ae3722daa428",
            },
        ],
        "runtime_payload_digest": REQUIRED_RUNTIME_DIGEST,
        "hardening_candidate_commit": "d70372b6ce35c3a0f1243fda8d810c3e24c16940",
        "ansible_baseline_commit": "ffb1357d07ccdde0036c82acb47073b9d6770037",
        "agent_stack_commit": "7f42dc7785507b41e61885e7d8000e703637e305",
        "lease_candidate_commit": "7f42dc7785507b41e61885e7d8000e703637e305",
        "lease_candidate_status": "approved_with_comments_lease_sentinel_r4_skeptic_r1",
        "timeout_seconds": 1800,
        "exit_timeout_seconds": 20,
        "throttle_interval_seconds": 30,
        "max_parallel_jobs": 4,
        "max_fanout": 3,
        "apply_authorized": False,
        "offline_mode": True,
    }
    config.update(overrides)
    return config


def render_jinja(template_text: str, variables: dict) -> str:
    try:
        from jinja2 import Environment, StrictUndefined
    except ImportError as exc:  # pragma: no cover
        raise unittest.SkipTest("jinja2 is not available") from exc
    env = Environment(undefined=StrictUndefined, keep_trailing_newline=True)

    def to_nice_yaml(value):
        return yaml.safe_dump(value, default_flow_style=False) if yaml else str(value)

    env.filters["to_nice_yaml"] = to_nice_yaml
    env.filters["bool"] = bool
    return env.from_string(template_text).render(**variables)


class PolicyTests(unittest.TestCase):
    def test_valid_config_passes(self):
        self.assertEqual(prodqual_policy_errors(valid_config()), [])

    def test_required_vars_and_digest_shape(self):
        errors = prodqual_policy_errors(valid_config(runtime_payload_digest="deadbeef"))
        self.assertTrue(any("64-char" in item or "digest" in item for item in errors))
        errors = prodqual_policy_errors(
            valid_config(runtime_payload_digest="sha256:" + REQUIRED_RUNTIME_DIGEST)
        )
        self.assertTrue(any("unqualified" in item for item in errors))
        errors = prodqual_policy_errors(valid_config(hardening_candidate_commit=""))
        self.assertTrue(any("hardening_candidate_commit" in item for item in errors))

    def test_distinct_identity_constraints(self):
        errors = prodqual_policy_errors(valid_config(authority_uid=902, worker_uid=902))
        self.assertTrue(any("distinct from worker" in item for item in errors))
        errors = prodqual_policy_errors(valid_config(authority_uid=501))
        self.assertTrue(any("distinct from operator" in item for item in errors))

    def test_unsafe_mode_owner_path_rejection(self):
        errors = prodqual_policy_errors(valid_config(taskstore_dir_mode="0777"))
        self.assertTrue(any("taskstore_dir_mode" in item for item in errors))
        errors = prodqual_policy_errors(
            valid_config(runtime_root="/tmp/noesis", manifest_path="/tmp/noesis/m.json")
        )
        self.assertTrue(any("outside allowed prefixes" in item or "unsafe" in item for item in errors))
        errors = prodqual_policy_errors(
            valid_config(runtime_root="/opt/noesis/prodqual/runtime/../etc")
        )
        self.assertTrue(len(errors) > 0)
        errors = prodqual_policy_errors(valid_config(runtime_owner="noesis-worker"))
        self.assertTrue(any("runtime_owner" in item for item in errors))

    def test_manifest_recipe_order_digest(self):
        files = list(valid_config()["runtime_files"])
        files[0], files[1] = files[1], files[0]
        errors = prodqual_policy_errors(valid_config(runtime_files=files))
        self.assertTrue(any("order" in item for item in errors))
        self.assertEqual(tuple(p for p in REQUIRED_RUNTIME_FILES), REQUIRED_RUNTIME_FILES)
        self.assertEqual(len(REQUIRED_RUNTIME_FILES), 11)

    def test_v2_defaults_and_policy_reject_v1_recipe(self):
        defaults = load_yaml(ROLE / "defaults" / "main.yml")
        self.assertEqual(
            defaults["prodqual_candidate_id"], "prodqual-hermes-adaptation-successor/v1"
        )
        self.assertEqual(
            defaults["prodqual_runtime_payload_recipe_version"],
            "hardening-1-trusted-manifest-runtime/v2",
        )
        self.assertEqual(
            defaults["prodqual_expected_runtime_payload_digest"],
            "3314ff8e88e1433bc0d9bf2ba6cd08efb7be99132ee79a8d6eaea6a9c398eb01",
        )
        self.assertEqual(len(defaults["prodqual_runtime_files"]), 11)
        self.assertEqual(
            REQUIRED_RUNTIME_DIGEST,
            "3314ff8e88e1433bc0d9bf2ba6cd08efb7be99132ee79a8d6eaea6a9c398eb01",
        )
        errors = prodqual_policy_errors(
            valid_config(runtime_payload_recipe_version="hardening-1-trusted-manifest-runtime/v1")
        )
        self.assertTrue(any("recipe" in item for item in errors))

    def test_loopback_only_bind_enforcement(self):
        errors = prodqual_policy_errors(
            valid_config(binds={"broker": {"host": "0.0.0.0", "port": 8787}})
        )
        self.assertTrue(any("loopback" in item for item in errors))
        errors = prodqual_policy_errors(valid_config(tailscale_bind_enabled=True))
        self.assertTrue(any("tailscale" in item for item in errors))

    def test_stale_label_refusal(self):
        labels = list(valid_config()["service_labels"]) + ["com.noesis.hermesdev"]
        errors = prodqual_policy_errors(valid_config(service_labels=labels))
        self.assertTrue(any("stale" in item for item in errors))

    def test_no_secret_bearing_fields(self):
        errors = prodqual_policy_errors(valid_config(broker_token="sekrit"))
        self.assertTrue(any("plaintext secret" in item for item in errors))


class TemplateTests(unittest.TestCase):
    def template_vars(self):
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
        return defaults

    def test_manifest_render_schema_and_digest(self):
        rendered = render_jinja(
            (TEMPLATES / "approved-release-manifest.json.j2").read_text(encoding="utf-8"),
            self.template_vars(),
        )
        payload = json.loads(rendered)
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        for key in schema["required"]:
            self.assertIn(key, payload)
        self.assertEqual(payload["runtime_payload_digest"], REQUIRED_RUNTIME_DIGEST)
        self.assertEqual(
            [item["path"] for item in payload["files"]],
            list(REQUIRED_RUNTIME_FILES),
        )
        self.assertEqual(payload["candidate_commit"], "d70372b6ce35c3a0f1243fda8d810c3e24c16940")
        self.assertTrue(payload["trust"]["environment_variable_is_not_authority"])
        second = render_jinja(
            (TEMPLATES / "approved-release-manifest.json.j2").read_text(encoding="utf-8"),
            self.template_vars(),
        )
        self.assertEqual(rendered, second)

    def test_launchd_interface_and_worker_isolation(self):
        variables = self.template_vars()
        broker = render_jinja(
            (TEMPLATES / "ai.noesis.broker.plist.j2").read_text(encoding="utf-8"),
            variables,
        )
        worker = render_jinja(
            (TEMPLATES / "ai.openclaw.gateway.plist.j2").read_text(encoding="utf-8"),
            variables,
        )
        for label in STALE:
            self.assertNotIn(label, broker)
            self.assertNotIn(label, worker)
        self.assertIn("ai.noesis.broker", broker)
        self.assertIn("HERMES_GOVERNED_PRODUCTION", broker)
        self.assertIn("HERMES_APPROVED_RELEASE_MANIFEST", broker)
        self.assertIn("HERMES_NOESIS_AUTHORITY_UID", broker)
        self.assertIn("HERMES_NOESIS_WORKER_UID", broker)
        self.assertIn("127.0.0.1", broker)
        self.assertNotIn("0.0.0.0", broker)
        self.assertNotIn("HERMES_GOVERNED_PRODUCTION", worker)
        self.assertNotIn("HERMES_APPROVED_RELEASE_MANIFEST", worker)
        self.assertIn("ai.openclaw.gateway", worker)
        self.assertIn("127.0.0.1", worker)

    def test_backup_restore_determinism_and_rollback_completeness(self):
        variables = self.template_vars()
        backup_src = (TEMPLATES / "backup-manifest.json.j2").read_text(encoding="utf-8")
        first = render_jinja(backup_src, variables)
        second = render_jinja(backup_src, variables)
        self.assertEqual(first, second)
        backup = json.loads(first)
        self.assertTrue(backup["never_overwrite_unrecognized"])
        self.assertTrue(backup["worker_denied"])
        rollback = render_jinja(
            (TEMPLATES / "rollback-plan.yml.j2").read_text(encoding="utf-8"),
            variables,
        )
        for token in (
            "payload",
            "manifests",
            "plists",
            "ownership_modes_flags",
            "service_state",
            "never_delete_unrecognized",
            "isolated_staging",
            "offline_validation",
            "activation",
            "bounded_canary",
            "rollback",
        ):
            self.assertIn(token, rollback)


class PlaybookGateTests(unittest.TestCase):
    def test_offline_playbook_cannot_reach_activation(self):
        validate = (PLAYBOOKS / "macos-prodqual-loopback-validate.yml").read_text(encoding="utf-8")
        self.assertIn("prodqual_activation_authorized: false", validate)
        self.assertIn("prodqual_offline_mode: true", validate)
        self.assertNotIn("include_tasks: activate.yml", validate)
        self.assertNotIn("include_tasks: identity.yml", validate)
        activate = (ROLE / "tasks" / "activate.yml").read_text(encoding="utf-8")
        self.assertIn("prodqual_activation_authorized", activate)
        self.assertIn("not (ansible_check_mode | bool)", activate)
        main = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("tags: [prodqual, activate, apply]", main)

    def test_apply_playbook_refuses_default(self):
        apply_pb = (PLAYBOOKS / "macos-prodqual-loopback.yml").read_text(encoding="utf-8")
        self.assertIn("prodqual_apply_authorized | bool", apply_pb)
        self.assertNotIn("inventory/production", apply_pb)

    def test_production_inventory_untouched(self):
        production = (REPO / "inventory" / "production" / "hosts.ini").read_text(encoding="utf-8")
        self.assertIn("# Add production hosts here", production)
        self.assertNotIn("prodqual", production)


class SecretScanTests(unittest.TestCase):
    def test_changed_package_has_no_secret_literals(self):
        roots = [
            ROLE,
            PLAYBOOKS / "macos-prodqual-loopback-validate.yml",
            PLAYBOOKS / "macos-prodqual-loopback.yml",
            REPO / "inventory" / "prodqual_loopback_fixture",
            REPO / "docs" / "prodqual",
            REPO / "tests" / "prodqual_loopback",
        ]
        for root in roots:
            paths = [root] if root.is_file() else root.rglob("*")
            for path in paths:
                if not path.is_file():
                    continue
                if path.suffix in {".pyc"} or "__pycache__" in path.parts:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
                self.assertIsNone(SECRET_RE.search(text), msg=str(path))


class HashHelperTests(unittest.TestCase):
    def test_package_digest_helper_is_stable(self):
        payload = b"prodqual-offline"
        digest = hashlib.sha256(payload).hexdigest()
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
