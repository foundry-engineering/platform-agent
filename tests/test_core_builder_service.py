"""Actual private-profile parsing and code authority; no API calls at startup."""
import base64
import json
from dataclasses import asdict


from platform_agent.core_builder_runtime import CoreBuilderWorker
from platform_agent.core_builder_service import _admission, load_builder, main
from test_core_execution_authorizer import Harness
from test_core_worker_service import write
from builder_runtime_fixture import IMAGE, link_core_code_authority


def test_real_private_profile_builds_actual_core_builder_without_model_or_signing(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch)
    root = tmp_path / 'code'
    root.mkdir(mode=0o700)
    code = link_core_code_authority(h, root)
    for file in (tmp_path / 'tenants.db', tmp_path / 'admissions.db'):
        file.chmod(0o600)
    runtime = {
        'schemaVersion': 'foundry.artifact-worker-profile.v1',
        'tenantId': h.config.tenant_id, 'projectId': h.config.project_id, 'workspaceId': h.config.workspace_id,
        'coreAgentId': h.config.core_agent_id, 'professionalRole': h.config.professional_role,
        'canonicalAgentId': h.config.canonical_agent_id, 'roleId': h.config.role_id,
        'roleManifestRef': h.config.role_manifest_ref, 'maxInputTokens': h.config.max_input_tokens,
        'maxOutputTokens': h.config.max_output_tokens, 'policyId': 'pol_worker-acceptance.v1',
        'policySha256': 'a' * 64, 'jurisdiction': 'AT', 'licenseId': 'license_worker-acceptance',
        'coreOrigin': 'https://core.example.test', 'providerOrigin': 'http://127.0.0.1:8010',
        'providerMode': 'loopback', 'coreTokenFile': write(tmp_path / 'core-token', b'fixture-secret'),
        'providerTokenFile': write(tmp_path / 'provider-token', b'provider-fixture-secret'),
        'postgresDsnFile': write(tmp_path / 'postgres', b'postgres://fixture:fixture@localhost/builder_test'),
        'tenantStoreFile': str(tmp_path / 'tenants.db'), 'admissionStoreFile': str(tmp_path / 'admissions.db'),
        'executionStateFile': str(tmp_path / 'execution.db'),
        'packageFile': write(tmp_path / 'package.json', json.dumps(h.package).encode()),
        'artifactFile': write(tmp_path / 'package.bin', h.bytes),
        'signers': [{'kid': h.kid, 'privateKeyFile': write(tmp_path / 'signer', base64.b64encode(h.key.private_bytes_raw()))}],
        'uploadHosts': ['storage.example.test'],
    }
    evidence = tmp_path / 'evidence'
    evidence.mkdir(mode=0o700)
    profile = {
        'schemaVersion': 'foundry.core-builder-profile.v1',
        'artifactWorkerProfileFile': write(tmp_path / 'runtime.json', json.dumps(runtime).encode()),
        'builderTaskFile': write(tmp_path / 'task.json', json.dumps(asdict(code.task)).encode()),
        'tenantAdmissionFile': write(tmp_path / 'admission.json', json.dumps(code.admission.as_dict()).encode()),
        'grantTrustedKeysFile': write(tmp_path / 'grant-keys.json', json.dumps({'kid_builder-grant.v1':
            base64.b64encode(code.grant_key.public_key().public_bytes_raw()).decode()}).encode()),
        'workspaceSigners': [{'kid': 'kid_builder-workspace.v1', 'privateKeyFile':
            write(tmp_path / 'workspace-signer', base64.b64encode(code.workspace_key.private_bytes_raw()))}],
        'witnessSigners': [{'kid': 'kid_builder-witness.v1', 'privateKeyFile':
            write(tmp_path / 'witness-signer', base64.b64encode(code.witness_key.private_bytes_raw()))}],
        'coreWorkNodeId': h.job.work_node_id, 'workspace': str(code.workspace), 'sourcePaths': ['src/app.py'],
        'stateDirectory': str(code.state), 'artifactStoreRoot': str(code.artifacts.root),
        'verificationEvidenceDirectory': str(evidence), 'maximumSeconds': 600,
        'sandbox': {'image': IMAGE, 'checks': [{'check_id': 'python-unittest',
            'argv': ['/usr/local/bin/python', '-B', '-m', 'unittest', 'discover', '-s', '/workspace/tests']}]},
    }
    path = tmp_path / 'builder.json'
    write(path, json.dumps(profile).encode())
    assert isinstance(load_builder(path), CoreBuilderWorker)
    assert h.calls == [] and h.transport.requests == []
    assert _admission(code.admission.as_dict()) == code.admission


def test_cli_configuration_failure_never_logs_secrets_or_tracebacks(monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', ['foundry-engineering-agent', '--profile', '/private/config.json'])
    def failed(_):
        raise ValueError('model-secret-must-not-leak')
    monkeypatch.setattr('platform_agent.core_builder_service.load_builder', failed)
    assert main() == 1
    output = capsys.readouterr()
    assert not output.out and 'stopped' in output.err
    assert 'model-secret' not in output.err and 'Traceback' not in output.err
