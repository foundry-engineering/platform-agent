"""Explicit multi-unit inference fixtures; actual signatures, files and checks."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace

from agent_protocol.execution_grant import derive_execution_grant_id
from engineering_agent.builder import Verification
from engineering_agent.builder_runner import RunnerModelArtifact
from engineering_agent.sandbox_verifier import DockerSandboxVerifier, TrustedCheck, TrustedSandboxProfile
from engineering_agent.selfhosted_model import _files_to_dop

from platform_agent.builder_work_units import BuilderWorkUnit
from platform_agent.grant_signing import ExecutionGrantSigner, sign_execution_grant
from builder_runtime_fixture import IMAGE


PARTS = {
    "foundation": {
        "pyproject.toml": '[project]\nname = "unit-store"\nversion = "0.1.0"\n',
        "lib/types.py": "TenantId = str\n",
        "lib/validation.py": "def valid(tenant):\n    return isinstance(tenant, str) and bool(tenant)\n",
        "lib/constants.py": "VERSION = '0.1.0'\n",
        "migrations/001.sql": "CREATE TABLE records(tenant TEXT NOT NULL, value TEXT NOT NULL);\n",
        "public/index.html": "<!doctype html><title>Unit store</title>\n",
        "public/site.css": "body { color: black; }\n",
        "README.md": "# Unit store\nTenant-isolated records.\n",
    },
    "service": {
        "app/store.py": "def values(db, tenant):\n    return [r[0] for r in db.execute('SELECT value FROM records WHERE tenant=?', (tenant,))]\n",
        "app/pricing.py": "def total(lines):\n    return sum(price * quantity for price, quantity in lines)\n",
        "app/accounts.py": "def scope(tenant, account):\n    return (tenant, account)\n",
        "app/projects.py": "def scope(tenant, project):\n    return (tenant, project)\n",
        "app/billing.py": "CURRENCY = 'EUR'\n",
        "app/health.py": "def status():\n    return 'ready'\n",
        "app/__init__.py": "# Application package\n",
        "lib/__init__.py": "# Shared package\n",
    },
    "application": {
        "src/main.py": "from app.store import values\ndef list_values(db, tenant):\n    return values(db, tenant)\n",
        "src/config.py": "DATABASE_SCHEMA = 1\n",
        "src/schema.py": "FIELDS = ('tenant', 'value')\n",
        "src/client.py": "def scope(tenant):\n    return {'tenant': tenant}\n",
        "src/routes.py": "ROUTES = ('/records', '/health')\n",
        "src/version.py": "VERSION = '0.1.0'\n",
        "src/security.py": "def authenticated(subject):\n    return bool(subject)\n",
        "src/__init__.py": "# Entry package\n",
    },
}
FILES = {path: content for files in PARTS.values() for path, content in files.items()}
PATHS = tuple(sorted(FILES))
UNITS = (
    BuilderWorkUnit("application", "Connect the entry point to the tenant store",
        (*PARTS["application"], "app/store.py", "migrations/001.sql"), tuple(PARTS["application"]),
        ("service",), 1, ("application-check",)),
    BuilderWorkUnit("foundation", "Create the project manifest and database schema",
        tuple(PARTS["foundation"]), tuple(PARTS["foundation"]), (), 1, ("foundation-check",)),
    BuilderWorkUnit("service", "Build the tenant-isolated application service",
        (*PARTS["service"], "migrations/001.sql", "lib/validation.py"), tuple(PARTS["service"]),
        ("foundation",), 1, ("service-check",)),
)


def assigned_unit(feedback):
    prefix = "Approved work-unit data: "
    return json.loads(feedback[0].removeprefix(prefix))["unitId"]


def admit_units(h):
    grant = {key: value for key, value in h.grant.items() if key != "signatures"}
    grant["read_paths"], grant["write_paths"] = list(PATHS), list(PATHS)
    grant["grant_id"] = derive_execution_grant_id(grant)
    h.grant = sign_execution_grant(grant, signers=(ExecutionGrantSigner(
        "kid_builder-grant.v1", h.grant_key.public_key().public_bytes_raw(), h.grant_key.sign),))
    h.admission = replace(h.admission, signed_grants=(h.grant,))


class UnitModelFixture:
    def __init__(self, *, fail_first=False):
        self.requests = []
        self.fail_first = fail_first

    def produce(self, request):
        self.requests.append(request)
        files = dict(PARTS[assigned_unit(request.verification_feedback)])
        if self.fail_first and len(self.requests) == 1:
            files["pyproject.toml"] = files["pyproject.toml"].replace("unit-store", "wrong-name")
        current = {item.path: item.sha256 for item in request.source_context}
        entries = [{"path": path, "content": content,
                    **({"expectedSha256": current[path]} if current.get(path) is not None else {})}
                   for path, content in files.items()]
        plan = _files_to_dop({"files": entries}, task_id=request.task_id,
            policy_sha256="f" * 64, source_context=request.source_context)
        body = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
        return RunnerModelArtifact(request.task_id, request.tenant_id, request.workspace_id,
            request.project_id, request.cell_id, request.repository_id, request.base_commit_sha,
            body, hashlib.sha256(body).hexdigest(), 1, "fixture:usage", "fixture:admission",
            "fixture:reservation", "fixture:settlement", "fixture:scan")


class UnitBytesVerifier:
    """Nonexecuting ordinary check; Docker below executes integration behavior."""
    def __init__(self, workspace, files):
        self.workspace, self.files, self.calls = workspace, files, []

    def verify(self, task, *, round_number):
        self.calls.append(round_number)
        values = [(self.workspace / path).read_bytes() for path in self.files]
        passed = values == [content.encode() for content in self.files.values()]
        return Verification(passed, ("unit-bytes",),
            tuple("sha256:" + hashlib.sha256(value).hexdigest() for value in values),
            "" if passed else "Independent project bytes differ")


def unit_checks():
    return (
        TrustedCheck("foundation-check", ("/usr/local/bin/python", "-B", "-c",
            "from pathlib import Path;import tomllib;p=Path('/workspace');"
            "assert tomllib.loads((p/'pyproject.toml').read_text())['project']['name']=='unit-store';"
            "assert (p/'public/index.html').read_text().startswith('<!doctype html>')")),
        TrustedCheck("service-check", ("/usr/local/bin/python", "-B", "-c",
            "import sqlite3;from pathlib import Path;from app.store import values;"
            "db=sqlite3.connect(':memory:');db.executescript(Path('/workspace/migrations/001.sql').read_text());"
            "db.executemany('INSERT INTO records VALUES(?,?)',[('a','private-a'),('b','private-b')]);"
            "assert values(db,'a')==['private-a'];assert values(db,'b')==['private-b'];"
            "assert values(db,\"a' OR 1=1 --\")==[]")),
        TrustedCheck("application-check", ("/usr/local/bin/python", "-B", "-c",
            "import sqlite3;from pathlib import Path;from src.main import list_values;"
            "db=sqlite3.connect(':memory:');db.executescript(Path('/workspace/migrations/001.sql').read_text());"
            "db.execute('INSERT INTO records VALUES(?,?)',('a','value'));"
            "assert list_values(db,'a')==['value'];assert list_values(db,'b')==[]")),
    )


def verifiers(workspace, evidence, *, docker):
    checks = unit_checks()  # Validate trusted argument bounds on every host.
    if not docker:
        return UnitBytesVerifier(workspace, FILES), {
            unit.unit_id: UnitBytesVerifier(workspace, PARTS[unit.unit_id]) for unit in UNITS}
    full = DockerSandboxVerifier(workspace=workspace, evidence_dir=evidence,
        profile=TrustedSandboxProfile(image=IMAGE, checks=checks))
    return full, {unit.unit_id: DockerSandboxVerifier(workspace=workspace, evidence_dir=evidence,
        profile=TrustedSandboxProfile(image=IMAGE,
            checks=tuple(check for check in checks if check.check_id in unit.check_ids))) for unit in UNITS}
