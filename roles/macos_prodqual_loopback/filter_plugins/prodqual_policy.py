# Fail-closed policy for noesis-prodqual-macos-arm64-loopback-control-plane/v1.
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import re

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
LOOPBACK_BINDS = frozenset(["127.0.0.1", "::1"])
PROHIBITED_BINDS = frozenset(
    ["0.0.0.0", "*", "::", "0:0:0:0:0:0:0:0", "[::]", "localhost"]
)
STALE_LABELS = frozenset(
    [
        "com.noesis.hermesdev",
        "com.noesis.clawdev",
        "com.noesispraxis.clawdev",
        "com.noesispraxis.hermesdev",
    ]
)
REQUIRED_LABELS = (
    "ai.noesis.broker",
    "ai.noesis.orchestrator",
    "ai.hermes.gateway",
    "ai.openclaw.gateway",
)
REQUIRED_RUNTIME_FILES = (
    "agent/agent_init.py",
    "agent/error_classifier.py",
    "agent/runtime_enforcement.py",
    "agent/turn_api_call.py",
    "agent/turn_api_error.py",
    "agent/turn_recovery.py",
    "run_agent.py",
    "agent/legacy_cli.py",
)
REQUIRED_RUNTIME_DIGEST = (
    "9450ccf6b4f84538e3b15053d9a2618011bd89c4e9a9aa0d287b41d88bd37425"
)
REQUIRED_RECIPE = "hardening-1-trusted-manifest-runtime/v1"
REQUIRED_MANIFEST_SCHEMA = "noesis.approved_release_manifest/v1"
REQUIRED_ENV = (
    "HERMES_GOVERNED_PRODUCTION",
    "HERMES_APPROVED_RELEASE_MANIFEST",
    "HERMES_NOESIS_AUTHORITY_UID",
    "HERMES_NOESIS_WORKER_UID",
)
SECRET_KEY_RE = re.compile(
    r"(password|secret|token|api[_-]?key|credential|private[_-]?key|bws_access)",
    re.IGNORECASE,
)
DEFAULT_ALLOWED_PREFIXES = ("/opt/noesis/prodqual",)


def _truthy(value):
    if isinstance(value, bool):
        return value
    if value in (None, "", 0, "False", "false", "no", "0", "False"):
        return False
    if str(value).lower() in ("true", "yes", "1"):
        return True
    return bool(value)


def _as_int(value, field, errors):
    if value is None or value == "":
        errors.append("%s is required" % field)
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        errors.append("%s must be an integer, got %r" % (field, value))
        return None


def _mode_int(mode, field, errors):
    if mode is None or mode == "":
        errors.append("%s is required" % field)
        return None
    try:
        if isinstance(mode, int):
            return mode
        text = str(mode).strip()
        if text.startswith("0o"):
            return int(text, 8)
        return int(text, 8)
    except (TypeError, ValueError):
        errors.append("%s is not an octal mode: %r" % (field, mode))
        return None


def _path_errors(path, field, allowed_prefixes):
    found = []
    if path is None or str(path).strip() == "":
        return ["%s is required" % field]
    text = str(path)
    if not text.startswith("/"):
        found.append("%s must be an absolute path" % field)
        return found
    if "~" in text or "$" in text:
        found.append("%s must not contain ~ or $ expansion" % field)
    normalized = os.path.normpath(text)
    if normalized != text:
        found.append("%s is not canonical (got %s, norm %s)" % (field, text, normalized))
    if ".." in text.split("/"):
        found.append("%s must not contain .." % field)
    if text in ("/", "/tmp", "/Users", "/var/tmp"):
        found.append("%s is an unsafe root path" % field)
    if allowed_prefixes:
        if not any(text == pfx or text.startswith(pfx + "/") for pfx in allowed_prefixes):
            found.append("%s is outside allowed prefixes %s" % (field, list(allowed_prefixes)))
    return found


def _digest_errors(value, field):
    if value is None or str(value).strip() == "":
        return ["%s is required" % field]
    text = str(value).strip().lower()
    if text.startswith("sha256:"):
        return ["%s must be unqualified 64-char hex, not algorithm-prefixed" % field]
    if not SHA256_RE.match(text):
        return ["%s is not a 64-char lowercase hex digest" % field]
    return []


def _commit_errors(value, field):
    if value is None or str(value).strip() == "":
        return ["%s is required" % field]
    text = str(value).strip().lower()
    if not COMMIT_RE.match(text):
        return ["%s is not a 40-char lowercase hex commit" % field]
    return []


def _secret_field_errors(mapping, prefix=""):
    found = []
    if not isinstance(mapping, dict):
        return found
    safe_suffixes = (
        "_root",
        "_path",
        "_dir",
        "_mode",
        "_owner",
        "_user",
        "_group",
        "_env",
        "_var",
        "_ref",
        "_refs",
    )
    for key, value in mapping.items():
        path = "%s.%s" % (prefix, key) if prefix else str(key)
        key_text = str(key)
        if SECRET_KEY_RE.search(key_text) and not any(key_text.endswith(sfx) for sfx in safe_suffixes):
            if value not in (None, "", False):
                found.append("plaintext secret field forbidden: %s" % path)
        if isinstance(value, dict):
            found.extend(_secret_field_errors(value, path))
        elif isinstance(value, list):
            for idx, item in enumerate(value):
                if isinstance(item, dict):
                    found.extend(_secret_field_errors(item, "%s[%s]" % (path, idx)))
    return found


def prodqual_policy_errors(config):
    """Return a list of fail-closed violations for a target config dict."""
    errors = []
    if not isinstance(config, dict):
        return ["prodqual config must be a mapping"]

    if config.get("target_name") != "noesis-prodqual-macos-arm64-loopback-control-plane":
        errors.append("target_name must be noesis-prodqual-macos-arm64-loopback-control-plane")
    if str(config.get("target_version")) != "v1":
        errors.append("target_version must be v1")
    if config.get("os_family") != "Darwin":
        errors.append("os_family must be Darwin")
    if config.get("os_product") != "macOS":
        errors.append("os_product must be macOS")
    if str(config.get("os_major")) != "27":
        errors.append("os_major must be 27")
    if config.get("arch") != "arm64":
        errors.append("arch must be arm64")

    if config.get("authority_user") != "noesis-authority":
        errors.append("authority_user must be noesis-authority")
    if config.get("worker_user") != "noesis-worker":
        errors.append("worker_user must be noesis-worker")
    if config.get("authority_group") != "noesis-authority":
        errors.append("authority_group must be noesis-authority")
    if config.get("worker_group") != "noesis-worker":
        errors.append("worker_group must be noesis-worker")

    authority_uid = _as_int(config.get("authority_uid"), "authority_uid", errors)
    worker_uid = _as_int(config.get("worker_uid"), "worker_uid", errors)
    operator_uid = _as_int(config.get("operator_uid"), "operator_uid", errors)
    if None not in (authority_uid, worker_uid, operator_uid):
        if authority_uid == worker_uid:
            errors.append("authority_uid must be distinct from worker_uid")
        if authority_uid == operator_uid:
            errors.append("authority_uid must be distinct from operator_uid")
        if worker_uid == operator_uid:
            errors.append("worker_uid must be distinct from operator_uid")
        for name, uid in (
            ("authority_uid", authority_uid),
            ("worker_uid", worker_uid),
            ("operator_uid", operator_uid),
        ):
            if uid is not None and uid < 1:
                errors.append("%s must be a positive UniqueID" % name)

    if _truthy(config.get("tailscale_bind_enabled")):
        errors.append("tailscale bind is prohibited for this target")
    if _truthy(config.get("public_bind_enabled")):
        errors.append("public bind is prohibited for this target")

    allowed = tuple(config.get("allowed_path_prefixes") or DEFAULT_ALLOWED_PREFIXES)
    path_fields = (
        "runtime_root",
        "manifest_path",
        "taskstore_root",
        "approval_store",
        "backup_root",
        "authority_profile_root",
        "worker_profile_root",
        "worker_scratch_root",
        "authority_credential_ref_root",
        "authority_log_root",
        "worker_log_root",
        "authority_run_root",
        "authority_launchd_dir",
        "worker_launchd_dir",
        "rollback_staging_root",
    )
    for field in path_fields:
        errors.extend(_path_errors(config.get(field), field, allowed))

    runtime_root = config.get("runtime_root")
    manifest_path = config.get("manifest_path")
    if runtime_root and manifest_path:
        man_dir = os.path.dirname(str(manifest_path))
        if str(manifest_path).startswith(str(runtime_root) + "/"):
            errors.append("manifest_path must not live inside runtime payload root")
        if man_dir == runtime_root:
            errors.append("manifest parent must be isolated from runtime payload root")

    private_modes = (
        ("taskstore_dir_mode", True),
        ("taskstore_file_mode", True),
        ("approval_dir_mode", True),
        ("approval_file_mode", True),
        ("backup_dir_mode", True),
        ("credential_ref_dir_mode", True),
        ("authority_profile_dir_mode", True),
        ("worker_profile_dir_mode", True),
    )
    for field, private in private_modes:
        mode = _mode_int(config.get(field), field, errors)
        if mode is None:
            continue
        if mode & 0o002:
            errors.append("%s must not be other-writable" % field)
        if private and (mode & 0o020):
            errors.append("%s must not be group-writable" % field)
        if private and (mode & 0o007):
            errors.append("%s must deny other access" % field)

    payload_dir_mode = _mode_int(
        config.get("runtime_dir_mode"), "runtime_dir_mode", errors
    )
    payload_file_mode = _mode_int(
        config.get("runtime_file_mode"), "runtime_file_mode", errors
    )
    for field, mode in (
        ("runtime_dir_mode", payload_dir_mode),
        ("runtime_file_mode", payload_file_mode),
    ):
        if mode is not None and (mode & 0o002):
            errors.append("%s must not be other-writable" % field)

    if config.get("runtime_owner") not in (None, "noesis-authority"):
        errors.append("runtime_owner must be noesis-authority")
    if config.get("manifest_owner") not in (None, "noesis-authority"):
        errors.append("manifest_owner must be noesis-authority")
    if config.get("worker_profile_owner") not in (None, "noesis-worker"):
        errors.append("worker_profile_owner must be noesis-worker")

    binds = config.get("binds") or {}
    if not isinstance(binds, dict):
        errors.append("binds must be a mapping")
        binds = {}
    for name, spec in binds.items():
        if not isinstance(spec, dict):
            errors.append("bind %s must be a mapping" % name)
            continue
        host = spec.get("host")
        if host in PROHIBITED_BINDS or host not in LOOPBACK_BINDS:
            errors.append("bind %s host %r is not loopback-only" % (name, host))
        port = spec.get("port")
        if port is None or port == "":
            errors.append("bind %s port is required" % name)
        else:
            try:
                port_i = int(port)
                if port_i < 1 or port_i > 65535:
                    errors.append("bind %s port out of range" % name)
            except (TypeError, ValueError):
                errors.append("bind %s port must be an integer" % name)

    labels = list(config.get("service_labels") or [])
    for stale in STALE_LABELS:
        if stale in labels:
            errors.append("stale launchd label refused: %s" % stale)
    for label in labels:
        if str(label).startswith("com.noesis."):
            errors.append("stale com.noesis.* label refused: %s" % label)
    for required in REQUIRED_LABELS:
        if required not in labels:
            errors.append("missing required service label %s" % required)

    env_keys = list(config.get("governed_env_keys") or [])
    if tuple(env_keys) != REQUIRED_ENV:
        errors.append("governed env keys must be exactly %s" % (REQUIRED_ENV,))

    recipe = config.get("runtime_payload_recipe_version")
    if recipe != REQUIRED_RECIPE:
        errors.append("runtime recipe must be %s" % REQUIRED_RECIPE)
    schema = config.get("manifest_schema_version")
    if schema != REQUIRED_MANIFEST_SCHEMA:
        errors.append("manifest schema must be %s" % REQUIRED_MANIFEST_SCHEMA)

    files = list(config.get("runtime_files") or [])
    if len(files) != 8:
        errors.append("runtime file set must contain exactly 8 paths")
    observed_paths = []
    for item in files:
        if not isinstance(item, dict):
            errors.append("runtime file entries must be mappings")
            continue
        observed_paths.append(item.get("path"))
        errors.extend(_digest_errors(item.get("sha256"), "runtime file %s sha256" % item.get("path")))
    if tuple(observed_paths) != REQUIRED_RUNTIME_FILES:
        errors.append("runtime file order/path set does not match frozen recipe")

    errors.extend(
        _digest_errors(config.get("runtime_payload_digest"), "runtime_payload_digest")
    )
    digest = str(config.get("runtime_payload_digest") or "").strip().lower()
    if digest and digest != REQUIRED_RUNTIME_DIGEST:
        errors.append("runtime_payload_digest does not match frozen HARDENING interface")

    errors.extend(_commit_errors(config.get("hardening_candidate_commit"), "hardening_candidate_commit"))
    errors.extend(_commit_errors(config.get("ansible_baseline_commit"), "ansible_baseline_commit"))
    errors.extend(_commit_errors(config.get("agent_stack_commit"), "agent_stack_commit"))

    if config.get("lease_candidate_commit"):
        errors.extend(
            _commit_errors(config.get("lease_candidate_commit"), "lease_candidate_commit")
        )
        if config.get("lease_candidate_status") not in (
            "pending_successor_review",
            "unreviewed",
        ):
            errors.append("lease candidate must remain pending review; do not pin as approved")

    for cap in (
        "timeout_seconds",
        "exit_timeout_seconds",
        "throttle_interval_seconds",
        "max_parallel_jobs",
        "max_fanout",
    ):
        number = _as_int(config.get(cap), cap, errors)
        if number is not None and number < 1:
            errors.append("%s must be >= 1" % cap)

    if _truthy(config.get("apply_authorized")) and _truthy(config.get("offline_mode")):
        errors.append("apply_authorized cannot be true in offline_mode")

    errors.extend(_secret_field_errors(config))
    return errors


class FilterModule(object):
    def filters(self):
        return {
            "prodqual_policy_errors": prodqual_policy_errors,
        }
