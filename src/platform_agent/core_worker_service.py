"""Supervised entrypoint for the configured, single-host artifact worker.

Operational identities, package admission, signer keys and parent budgets must
already exist. This process creates none of those authorities on startup.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import signal
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from threading import Event
from typing import Any

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from foundry_runner.execution_provider import ExecutionWorker, HttpExecutionProvider, LocalExecutionProvider
from foundry_runner.network_egress import EgressPolicy

from .artifact_worker_runtime import build_core_artifact_worker
from .core_execution_authorizer import ArtifactWorkerBinding
from .core_work_authority_issuer import ArtifactWorkPolicy, CoreWorkAuthoritySigner
from .skill_admission import SQLiteSkillAdmissionStore
from .skill_admission_service import GovernedSkillAdmissionService
from .tenant_control import SQLiteTenantControlStore


class WorkerConfigurationError(ValueError):
    pass


def private_file(path: object, *, maximum: int) -> bytes:
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise WorkerConfigurationError("absolute private operational file required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        parent = Path(path).parent.stat()
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1
                or parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077):
            raise WorkerConfigurationError("operational file must be private to its owner")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if not data or len(data) > maximum:
            raise WorkerConfigurationError("operational file is empty or oversized")
        return bytes(data)
    finally:
        os.close(fd)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WorkerConfigurationError("duplicate configuration key")
        result[key] = value
    return result


def _secret(path: object) -> Callable[[], str]:
    def read() -> str:
        value = private_file(path, maximum=16384).decode("utf-8").rstrip("\n")
        if not value or value.strip() != value or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise WorkerConfigurationError("invalid operational credential")
        return value
    read()
    return read


def load_worker(profile_path: Path) -> ExecutionWorker:
    data = json.loads(private_file(str(profile_path), maximum=65536), object_pairs_hook=_unique_object)
    keys = {
        "schemaVersion", "tenantId", "projectId", "workspaceId", "coreAgentId", "professionalRole",
        "canonicalAgentId", "roleId", "roleManifestRef", "maxInputTokens", "maxOutputTokens",
        "policyId", "policySha256", "jurisdiction", "licenseId", "coreOrigin", "providerOrigin",
        "providerMode", "coreTokenFile", "providerTokenFile", "postgresDsnFile", "tenantStoreFile",
        "admissionStoreFile", "executionStateFile", "packageFile", "artifactFile", "signers", "uploadHosts",
    }
    if not isinstance(data, dict) or set(data) != keys or data["schemaVersion"] != "foundry.artifact-worker-profile.v1":
        raise WorkerConfigurationError("exact artifact worker profile required")
    for key in keys - {"maxInputTokens", "maxOutputTokens", "signers", "uploadHosts"}:
        if not isinstance(data[key], str) or not data[key] or data[key].strip() != data[key]:
            raise WorkerConfigurationError("invalid artifact worker profile field")
    signers: list[CoreWorkAuthoritySigner] = []
    if not isinstance(data["signers"], list) or not 1 <= len(data["signers"]) <= 16:
        raise WorkerConfigurationError("configured operational signing keys required")
    for entry in data["signers"]:
        if not isinstance(entry, dict) or set(entry) != {"kid", "privateKeyFile"}:
            raise WorkerConfigurationError("exact operational signer profile required")
        raw = base64.b64decode(private_file(entry["privateKeyFile"], maximum=128).strip(), validate=True)
        signing_key = Ed25519PrivateKey.from_private_bytes(raw)
        signers.append(CoreWorkAuthoritySigner(entry["kid"], signing_key.public_key().public_bytes_raw(), signing_key.sign))
    if (not isinstance(data["uploadHosts"], list) or not data["uploadHosts"]
            or any(not isinstance(host, str) for host in data["uploadHosts"])):
        raise WorkerConfigurationError("explicit trusted upload hosts required")
    provider_token = _secret(data["providerTokenFile"])
    if data["providerMode"] == "https":
        from urllib.parse import urlsplit
        host = urlsplit(data["providerOrigin"]).hostname
        if host is None:
            raise WorkerConfigurationError("provider origin has no host")
        provider: HttpExecutionProvider = HttpExecutionProvider(
            endpoint=data["providerOrigin"], token_supplier=provider_token,
            egress_policy=EgressPolicy(frozenset({host})), timeout_seconds=120,
        )
    elif data["providerMode"] == "loopback":
        provider = LocalExecutionProvider(endpoint=data["providerOrigin"], token_supplier=provider_token, timeout_seconds=120)
    else:
        raise WorkerConfigurationError("provider mode must be explicitly https or loopback")
    for field in ("tenantStoreFile", "admissionStoreFile"):
        private_file(data[field], maximum=64 * 1024 * 1024)
    package = json.loads(private_file(data["packageFile"], maximum=512 * 1024), object_pairs_hook=_unique_object)
    artifact = private_file(data["artifactFile"], maximum=64 * 1024 * 1024)
    dsn = _secret(data["postgresDsnFile"])
    def connect() -> psycopg.Connection[tuple[Any, ...]]:
        from psycopg.conninfo import conninfo_to_dict
        value = dsn()
        configured = conninfo_to_dict(value).get("options", "")
        if not isinstance(configured, str):
            raise WorkerConfigurationError("PostgreSQL options must be text")
        return psycopg.connect(value, connect_timeout=5,
            options=configured + " -c statement_timeout=10000 -c lock_timeout=5000")
    admissions = GovernedSkillAdmissionService(
        tenant_store=SQLiteTenantControlStore(Path(data["tenantStoreFile"])),
        admission_store=SQLiteSkillAdmissionStore(Path(data["admissionStoreFile"])),
    )
    return build_core_artifact_worker(
        binding=ArtifactWorkerBinding(data["tenantId"], data["projectId"], data["workspaceId"], data["coreAgentId"],
            data["professionalRole"], data["canonicalAgentId"], data["roleId"], data["roleManifestRef"],
            data["maxInputTokens"], data["maxOutputTokens"]),
        core_origin=data["coreOrigin"], core_token_supplier=_secret(data["coreTokenFile"]),
        admissions=admissions, package=package, artifact_bytes=artifact,
        policy=ArtifactWorkPolicy(data["policyId"], data["policySha256"], data["jurisdiction"]),
        signers=signers, state_path=Path(data["executionStateFile"]), connection_factory=connect,
        license_id=data["licenseId"], provider=provider,
        upload_egress_policy=EgressPolicy(frozenset(data["uploadHosts"])),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the configured Core artifact worker")
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    stop = Event()
    previous = {}
    for name in (signal.SIGINT, signal.SIGTERM):
        previous[name] = signal.getsignal(name)
        signal.signal(name, lambda *_: stop.set())
    try:
        worker = load_worker(args.profile)
        while not stop.is_set():
            handled = worker.run_once()
            if args.once:
                print(json.dumps({"status": "handled" if handled else "idle"}))
                return 0
            if not handled:
                stop.wait(2)
        return 0
    except Exception:
        # No traceback, DSN, token, key path or provider material is logged.
        print("Artifact worker stopped; operational state requires review.", file=sys.stderr)
        return 1
    finally:
        for name, handler in previous.items():
            signal.signal(name, handler)


if __name__ == "__main__":
    raise SystemExit(main())
