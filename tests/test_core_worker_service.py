from __future__ import annotations

import base64
import json
import os

import pytest

from platform_agent.core_worker_service import WorkerConfigurationError, load_worker, main, private_file
from test_core_execution_authorizer import Harness


def write(path, content):
    path.write_bytes(content)
    path.chmod(0o600)
    return str(path)


@pytest.mark.parametrize("kind", ["public", "symlink", "oversized", "empty", "hardlink"])
def test_operational_files_must_be_private_regular_bounded_files(tmp_path, kind):
    target = tmp_path / "private"
    write(target, b"private-fixture")
    path = target
    maximum = 100
    if kind == "public":
        path.chmod(0o644)
    elif kind == "symlink":
        path = tmp_path / "link"
        path.symlink_to(target)
    elif kind == "oversized":
        maximum = 2
    elif kind == "empty":
        path.write_bytes(b"")
    else:
        os.link(target, tmp_path / "hardlink")
    with pytest.raises((WorkerConfigurationError, OSError)):
        private_file(str(path), maximum=maximum)


def test_exact_private_profile_loads_existing_operational_state_without_creating_authority(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    for file in (tmp_path / "tenants.db", tmp_path / "admissions.db"):
        file.chmod(0o600)
    profile = {
        "schemaVersion": "foundry.artifact-worker-profile.v1", "tenantId": h.config.tenant_id,
        "projectId": h.config.project_id, "workspaceId": h.config.workspace_id, "coreAgentId": h.config.core_agent_id,
        "professionalRole": h.config.professional_role, "canonicalAgentId": h.config.canonical_agent_id,
        "roleId": h.config.role_id, "roleManifestRef": h.config.role_manifest_ref,
        "maxInputTokens": h.config.max_input_tokens, "maxOutputTokens": h.config.max_output_tokens,
        "policyId": "pol_worker-acceptance.v1", "policySha256": "a" * 64, "jurisdiction": "AT",
        "licenseId": "license_worker-acceptance", "coreOrigin": "https://core.example.test",
        "providerOrigin": "http://127.0.0.1:8010", "providerMode": "loopback",
        "coreTokenFile": write(tmp_path / "core-token", b"service-fixture-secret"),
        "providerTokenFile": write(tmp_path / "provider-token", b"provider-fixture-secret"),
        "postgresDsnFile": write(tmp_path / "postgres", b"postgres://isolated:fixture@localhost/worker_test"),
        "tenantStoreFile": str(tmp_path / "tenants.db"), "admissionStoreFile": str(tmp_path / "admissions.db"),
        "executionStateFile": str(tmp_path / "service-execution.db"),
        "packageFile": write(tmp_path / "package.json", json.dumps(h.package).encode()),
        "artifactFile": write(tmp_path / "package.bin", h.bytes),
        "signers": [{"kid": h.kid, "privateKeyFile": write(tmp_path / "signer", base64.b64encode(h.key.private_bytes_raw()))}],
        "uploadHosts": ["storage.example.test"],
    }
    path = tmp_path / "profile.json"
    write(path, json.dumps(profile).encode())
    received = []
    monkeypatch.setattr("platform_agent.core_worker_service.build_core_artifact_worker", lambda **args: received.append(args) or "configured")
    assert load_worker(path) == "configured"
    assert received[0]["binding"] == h.config
    assert received[0]["signers"][0].public_key == h.public
    assert received[0]["package"] == h.package and received[0]["artifact_bytes"] == h.bytes
    assert not h.calls


def test_duplicate_configuration_keys_are_rejected(tmp_path):
    path = tmp_path / "profile.json"
    write(path, b'{"schemaVersion":"a","schemaVersion":"b"}')
    with pytest.raises(WorkerConfigurationError, match="duplicate"):
        load_worker(path)


def test_service_failure_never_logs_credential_or_exception_material(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["foundry-artifact-worker", "--profile", "/private/fixture.json", "--once"])
    def fail(_):
        raise RuntimeError("password-do-not-log")
    monkeypatch.setattr("platform_agent.core_worker_service.load_worker", fail)
    assert main() == 1
    output = capsys.readouterr()
    assert not output.out and "requires review" in output.err
    assert "password-do-not-log" not in output.err


@pytest.mark.parametrize("handled,status", [(True, "handled"), (False, "idle")])
def test_service_once_exits_without_automatic_retry(monkeypatch, capsys, handled, status):
    class Worker:
        calls = 0
        def run_once(self):
            self.calls += 1
            return handled
    worker = Worker()
    monkeypatch.setattr("sys.argv", ["foundry-artifact-worker", "--profile", "/private/fixture.json", "--once"])
    monkeypatch.setattr("platform_agent.core_worker_service.load_worker", lambda _: worker)
    assert main() == 0
    assert json.loads(capsys.readouterr().out) == {"status": status}
    assert worker.calls == 1
