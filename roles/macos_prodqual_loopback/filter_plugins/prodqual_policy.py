# Fail-closed policy for noesis-prodqual-macos-arm64-loopback-control-plane/v1.
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import hashlib
import os
import re
import shutil

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
HERMES_GATEWAY_BIND_CLASS = "process_supervised_no_network_listener"
HERMES_GATEWAY_ARGV = ("gateway", "run", "--external-supervisor")


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
        "_socket",
        "_class",
        "_note",
        "_interface",
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


def prodqual_identity_policy_errors(config):
    """UID/GID distinctness. Live apply runs this only after discovery."""
    errors = []
    if not isinstance(config, dict):
        return ["prodqual config must be a mapping"]
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
    return errors


def prodqual_static_policy_errors(config):
    """Static target/policy inputs that do not require discovered UIDs."""
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

    bind_class = config.get("hermes_gateway_bind_class")
    if bind_class not in (None, ""):
        if bind_class == "unix_socket":
            errors.append(
                "hermes_gateway_bind_class unix_socket is not a supported Hermes CLI listener"
            )
        elif bind_class != HERMES_GATEWAY_BIND_CLASS:
            errors.append(
                "hermes_gateway_bind_class must be %s" % HERMES_GATEWAY_BIND_CLASS
            )
    socket = config.get("hermes_gateway_socket")
    if socket not in (None, ""):
        errors.append(
            "hermes_gateway_socket is not a supported/consumed Hermes CLI bind; remove unused socket claim"
        )

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


def prodqual_policy_errors(config):
    """Return a list of fail-closed violations for a target config dict."""
    if not isinstance(config, dict):
        return ["prodqual config must be a mapping"]
    errors = prodqual_static_policy_errors(config)
    phase = config.get("policy_phase") or "full"
    if phase != "static":
        errors.extend(prodqual_identity_policy_errors(config))
    return errors


def prodqual_hermes_gateway_argv(*_args, **_kwargs):
    return list(HERMES_GATEWAY_ARGV)


def prodqual_interpret_worker_probe(rc, expect_denied=True, stderr=""):
    """Fail-closed interpretation of Darwin setuid write probes."""
    try:
        code = int(rc)
    except (TypeError, ValueError):
        return ["worker probe rc is not an integer: %r" % rc]
    if expect_denied:
        if code == 13:
            return []
        return [
            "worker denial probe failed rc=%s (need EACCES=13; 0=write succeeded; other=parser/command failure)"
            % code
        ]
    if code == 0:
        return []
    return ["worker allow probe failed rc=%s" % code]


def prodqual_parse_launchctl_list(stdout):
    loaded = []
    for line in str(stdout or "").splitlines():
        text = line.strip()
        if not text or text.lower().startswith("pid"):
            continue
        parts = text.split()
        if len(parts) < 3:
            continue
        pid_text, status, label = parts[0], parts[1], parts[2]
        pid = None if pid_text == "-" else (int(pid_text) if pid_text.isdigit() else pid_text)
        loaded.append({"pid": pid, "status": status, "label": label})
    return loaded


def prodqual_live_service_errors(loaded, expected_labels=None, operator_uid=None, process_uids=None):
    errors = []
    expected = set(expected_labels or REQUIRED_LABELS)
    process_uids = process_uids or {}
    for item in loaded or []:
        label = str(item.get("label") or "")
        if label.startswith("com.apple.") or label.startswith("com.openssh."):
            continue
        if label.startswith("com.noesis."):
            errors.append("stale launchd label refused: %s" % label)
        uid = process_uids.get(label)
        if (
            uid is not None
            and operator_uid not in (None, "")
            and int(uid) == int(operator_uid)
            and (
                label.startswith("ai.noesis.")
                or label.startswith("ai.hermes.")
                or label.startswith("ai.openclaw.")
                or "prototype" in label
            )
        ):
            errors.append("same-UID prototype unit refused: %s uid=%s" % (label, uid))
        if (
            label.startswith("ai.noesis.")
            or label.startswith("ai.hermes.")
            or label.startswith("ai.openclaw.")
        ) and label not in expected:
            errors.append("conflicting or unrecognized service label: %s" % label)
    return errors


def prodqual_process_uids_from_ps(loaded, ps_stdout):
    pid_to_uid = {}
    for line in str(ps_stdout or "").splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        if str(parts[0]).isdigit() and str(parts[1]).isdigit():
            pid_to_uid[int(parts[1])] = int(parts[0])
    mapping = {}
    for item in loaded or []:
        pid = item.get("pid")
        if pid in (None, "-", ""):
            continue
        try:
            pid_i = int(pid)
        except (TypeError, ValueError):
            continue
        if pid_i in pid_to_uid:
            mapping[item["label"]] = pid_to_uid[pid_i]
    return mapping


def prodqual_launchd_decision(loaded_labels, label):
    if label in (loaded_labels or []):
        return "skip"
    return "bootstrap"


def prodqual_bootout_failed_when(rc, stderr=""):
    try:
        code = int(rc)
    except (TypeError, ValueError):
        return True
    if code == 0:
        return False
    text = stderr or ""
    if code in (3, 113) or "Could not find specified service" in text or "No such process" in text:
        return False
    return True


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_into(src, dest):
    parent = os.path.dirname(dest)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(src, "rb") as inf, open(dest, "wb") as out:
        shutil.copyfileobj(inf, out)


def prodqual_backup_copy(entries, backup_root, recognized_checksums=None, service_state=None):
    """Copy exact file payloads into a content-addressed backup root."""
    errors = []
    recorded = []
    recognized_checksums = list(recognized_checksums or [])
    os.makedirs(backup_root, exist_ok=True)
    objects = os.path.join(backup_root, "objects")
    os.makedirs(objects, exist_ok=True)

    def remember_file(entry, source, relpath, live_path, class_name):
        sha = _file_sha256(source)
        object_path = os.path.join(objects, sha)
        if not os.path.isfile(object_path):
            _copy_into(source, object_path)
        dest_path = os.path.join(backup_root, relpath)
        _copy_into(source, dest_path)
        rec = dict(entry)
        rec["class"] = class_name
        rec["kind"] = "file"
        rec["source_path"] = source
        rec["source_sha256"] = sha
        rec["backup_path"] = dest_path
        rec["object_path"] = object_path
        rec["relpath"] = relpath
        rec["live_path"] = live_path
        recorded.append(rec)

    for entry in entries or []:
        kind = entry.get("kind")
        live = entry.get("live_path")
        source = entry.get("source_path")
        if kind == "directory":
            files = entry.get("files")
            if not files:
                errors.append(
                    "directory destination requires explicit file manifest: %s" % live
                )
                continue
            if live and os.path.isdir(live):
                manifest_rel = set(item.get("relpath") for item in files)
                for root, _dirs, names in os.walk(live):
                    for name in names:
                        full = os.path.join(root, name)
                        rel = os.path.relpath(full, live)
                        if rel not in manifest_rel:
                            live_hash = _file_sha256(full)
                            if live_hash not in recognized_checksums:
                                errors.append("unrecognized destination drift: %s" % full)
            dir_rec = dict(entry)
            dir_rec["source_sha256"] = None
            recorded.append(dir_rec)
            for item in files:
                src = item["source_path"]
                if not os.path.isfile(src):
                    errors.append("source file missing: %s" % src)
                    continue
                relpath = os.path.join(entry.get("relpath") or "payload/runtime", item["relpath"])
                live_path = os.path.join(live, item["relpath"]) if live else None
                if live_path and os.path.isfile(live_path):
                    live_hash = _file_sha256(live_path)
                    src_hash = _file_sha256(src)
                    if live_hash != src_hash and live_hash not in recognized_checksums:
                        errors.append("unrecognized destination drift: %s" % live_path)
                        continue
                remember_file(entry, src, relpath, live_path, "payload_file")
            continue
        if not os.path.isfile(source):
            errors.append("source file missing: %s" % source)
            continue
        if live and os.path.exists(live):
            if os.path.isdir(live):
                errors.append(
                    "unrecognized destination drift, directory where file expected: %s" % live
                )
                continue
            live_hash = _file_sha256(live)
            src_hash = _file_sha256(source)
            if live_hash != src_hash and live_hash not in recognized_checksums:
                errors.append("unrecognized destination drift: %s" % live)
                continue
        remember_file(entry, source, entry.get("relpath"), live, entry.get("class") or "file")

    if errors:
        return {
            "errors": errors,
            "entries": [],
            "service_state": list(service_state or []),
            "backup_root": backup_root,
            "worker_denied": True,
        }
    return {
        "errors": [],
        "entries": recorded,
        "service_state": list(service_state or []),
        "backup_root": backup_root,
        "worker_denied": True,
        "never_overwrite_unrecognized": True,
    }


def prodqual_stage_restore(backup, staging_root):
    errors = []
    os.makedirs(staging_root, exist_ok=True)
    staged = []
    for entry in backup.get("entries") or []:
        if entry.get("kind") == "directory" and entry.get("class") != "payload_file":
            continue
        backup_path = entry.get("backup_path")
        relpath = entry.get("relpath")
        expected = entry.get("source_sha256")
        if not relpath or not expected:
            continue
        if not backup_path or not os.path.isfile(backup_path):
            errors.append("backup object missing for %s" % relpath)
            continue
        actual = _file_sha256(backup_path)
        if actual != expected:
            errors.append("backup object hash mismatch for %s" % relpath)
            continue
        dest = os.path.join(staging_root, relpath)
        _copy_into(backup_path, dest)
        staged_hash = _file_sha256(dest)
        if staged_hash != expected:
            errors.append("staged hash mismatch for %s" % relpath)
            continue
        staged.append(
            {
                "relpath": relpath,
                "path": dest,
                "sha256": expected,
                "live_path": entry.get("live_path"),
                "owner": entry.get("owner"),
                "group": entry.get("group"),
                "mode": entry.get("mode"),
                "flags": entry.get("flags") or "",
                "class": entry.get("class"),
            }
        )
    return {"errors": errors, "staged": staged, "staging_root": staging_root}


def prodqual_live_restore(backup, staging_root, restore_authorized=False, restore_live_authorized=False):
    errors = []
    if not restore_authorized:
        return {"errors": ["restore is not authorized"]}
    staged = prodqual_stage_restore(backup, staging_root)
    if staged["errors"]:
        return staged
    if not restore_live_authorized:
        return {
            "errors": ["live restore writes require separate restore live authorization"],
            "staged": staged["staged"],
        }
    for item in staged["staged"]:
        live = item.get("live_path")
        if not live:
            errors.append("missing live_path")
            continue
        _copy_into(item["path"], live)
        if _file_sha256(live) != item["sha256"]:
            errors.append("live hash mismatch for %s" % live)
    return {"errors": errors, "staged": staged["staged"]}


def prodqual_rollback(backup, staging_root, rollback_authorized=False, extra_live_paths=None):
    if not rollback_authorized:
        return {"errors": ["rollback is not authorized"]}
    extra = list(extra_live_paths or [])
    known = set()
    for entry in backup.get("entries") or []:
        live = entry.get("live_path")
        if live:
            known.add(os.path.abspath(live))
    errors = []
    for path in extra:
        if os.path.abspath(path) not in known:
            errors.append("unknown destination refused: %s" % path)
    if errors:
        return {"errors": errors}
    return prodqual_live_restore(
        backup,
        staging_root,
        restore_authorized=True,
        restore_live_authorized=True,
    )


def prodqual_build_backup_entries(config):
    runtime_root = config.get("runtime_root")
    launchd = config.get("authority_launchd_dir")
    worker_launchd = config.get("worker_launchd_dir") or launchd
    payload_files = []
    for item in config.get("runtime_files") or []:
        relpath = item.get("path")
        payload_files.append(
            {
                "relpath": relpath,
                "source_path": os.path.join(runtime_root, relpath),
            }
        )
    owner = config.get("runtime_owner") or "noesis-authority"
    group = config.get("authority_group") or "noesis-authority"
    return [
        {
            "class": "manifest",
            "kind": "file",
            "source_path": config.get("manifest_path"),
            "live_path": config.get("manifest_path"),
            "relpath": "payload/approved-release-manifest.json",
            "owner": owner,
            "group": group,
            "mode": config.get("manifest_mode") or "0640",
            "flags": "",
        },
        {
            "class": "payload",
            "kind": "directory",
            "source_path": runtime_root,
            "live_path": runtime_root,
            "relpath": "payload/runtime",
            "owner": owner,
            "group": group,
            "mode": config.get("runtime_dir_mode") or "0755",
            "flags": "",
            "files": payload_files,
        },
        {
            "class": "plist",
            "kind": "file",
            "source_path": os.path.join(launchd, "ai.noesis.broker.plist"),
            "live_path": os.path.join(launchd, "ai.noesis.broker.plist"),
            "relpath": "plists/ai.noesis.broker.plist",
            "owner": "root",
            "group": "wheel",
            "mode": "0644",
            "flags": "",
        },
        {
            "class": "plist",
            "kind": "file",
            "source_path": os.path.join(launchd, "ai.noesis.orchestrator.plist"),
            "live_path": os.path.join(launchd, "ai.noesis.orchestrator.plist"),
            "relpath": "plists/ai.noesis.orchestrator.plist",
            "owner": "root",
            "group": "wheel",
            "mode": "0644",
            "flags": "",
        },
        {
            "class": "plist",
            "kind": "file",
            "source_path": os.path.join(launchd, "ai.hermes.gateway.plist"),
            "live_path": os.path.join(launchd, "ai.hermes.gateway.plist"),
            "relpath": "plists/ai.hermes.gateway.plist",
            "owner": "root",
            "group": "wheel",
            "mode": "0644",
            "flags": "",
        },
        {
            "class": "plist",
            "kind": "file",
            "source_path": os.path.join(worker_launchd, "ai.openclaw.gateway.plist"),
            "live_path": os.path.join(worker_launchd, "ai.openclaw.gateway.plist"),
            "relpath": "plists/ai.openclaw.gateway.plist",
            "owner": "root",
            "group": "wheel",
            "mode": "0644",
            "flags": "",
        },
    ]


class FilterModule(object):
    def filters(self):
        return {
            "prodqual_policy_errors": prodqual_policy_errors,
            "prodqual_static_policy_errors": prodqual_static_policy_errors,
            "prodqual_identity_policy_errors": prodqual_identity_policy_errors,
            "prodqual_live_service_errors": prodqual_live_service_errors,
            "prodqual_parse_launchctl_list": prodqual_parse_launchctl_list,
            "prodqual_launchd_decision": prodqual_launchd_decision,
            "prodqual_bootout_failed_when": prodqual_bootout_failed_when,
            "prodqual_interpret_worker_probe": prodqual_interpret_worker_probe,
            "prodqual_hermes_gateway_argv": prodqual_hermes_gateway_argv,
            "prodqual_backup_copy": prodqual_backup_copy,
            "prodqual_stage_restore": prodqual_stage_restore,
            "prodqual_live_restore": prodqual_live_restore,
            "prodqual_rollback": prodqual_rollback,
            "prodqual_build_backup_entries": prodqual_build_backup_entries,
            "prodqual_process_uids_from_ps": prodqual_process_uids_from_ps,
        }
