"""Isolated Core/provider/storage counterparties; no model or customer delivery."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import timedelta

from foundry_runner.http_transport import HttpResponse


class Response:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def read(self, size=-1):
        data = json.dumps(self.value).encode()
        return data if size < 0 else data[:size]


class Counterparties:
    def __init__(self, h):
        self.h = h
        self.content = b"Isolated provider output: actual worker orchestration acceptance.\n"
        self.sha256 = hashlib.sha256(self.content).hexdigest()
        self.provider_calls, self.uploads, self.events = [], [], []
        job = h.job
        self.job = {"id": job.id, "workspaceId": job.workspace_id, "projectId": job.project_id,
            "workNodeId": job.work_node_id, "assignmentId": job.assignment_id, "authorityId": job.authority_id,
            "authorityEpoch": job.authority_epoch, "agentId": job.agent_id, "artifactId": job.artifact_id,
            "objective": job.objective, "professionalRole": job.professional_role,
            "allowedActions": list(job.allowed_actions), "budgetMinor": job.budget_minor,
            "providerBudgetMicrousd": job.provider_budget_microusd, "currency": job.currency}

    def core(self, request, *, timeout):
        assert timeout > 0
        url, method = request.full_url, request.get_method()
        body = json.loads(request.data) if request.data else None
        if url.endswith("/claim"):
            return Response(self.job)
        if "/authority/" in url:
            return Response({**self.job, "allowed": self.h.transport.document["allowed"], "status": "active", "revokedAt": None})
        if url.endswith("/heartbeat"):
            return Response({"id": self.h.job.id, "status": "running",
                             "leaseExpiresAt": (self.h.now + timedelta(seconds=60)).isoformat()})
        if url.endswith("/economics"):
            self.events.append(body)
            return Response({**body, "replayed": False})
        if url.endswith("/outputs"):
            return Response({"objectId": "output_worker_fixture", "objectKey": "private/worker/output",
                "uploadUrl": "https://storage.example.test/private/worker/output", "headers": {"content-type": "text/plain"}})
        if "/outputs/" in url:
            return Response({"objectId": "output_worker_fixture", "contentRef": "object:private/worker/output",
                "sha256": self.sha256, "status": "available", "scanStatus": "clean", "scanRef": "scan:isolated-acceptance"}
                if method == "GET" else {"status": "quarantined"})
        if url.endswith("/runtime-events"):
            self.events.append(body)
            if body["type"] == "completion" and body["outcome"] == "completed":
                self.h.transport.document["allowed"] = False
            return Response({"state": "completed", "verificationState": "unverified"})
        raise AssertionError("unexpected isolated control-plane request")

    def request(self, request, *, timeout_seconds, max_response_bytes, checkpoint):
        checkpoint()
        assert timeout_seconds > 0
        if request.get_method() == "PUT":
            assert request.data == self.content
            self.uploads.append(request)
            return HttpResponse(200, b"")
        self.provider_calls.append(request)
        body = json.loads(request.data)
        assert body["artifactId"] == self.h.job.artifact_id
        output = {"artifactId": self.h.job.artifact_id, "fileName": "acceptance.txt", "mimeType": "text/plain",
            "contentBase64": base64.b64encode(self.content).decode(), "contentSha256": self.sha256,
            "costMicrousd": 100000, "providerRef": "provider:isolated-acceptance",
            "evidenceRefs": ["sha256:" + self.sha256], "usage": {"providerId": "fixture-provider",
                "modelOrToolId": "fixture-artifact", "pricingVersion": "fixture.v1", "actualModelMicrousd": 100000,
                "actualExternalToolMicrousd": 0, "inputTokens": 100, "outputTokens": 20, "cachedInputTokens": 0}}
        data = json.dumps(output).encode()
        assert len(data) <= max_response_bytes
        checkpoint()
        return HttpResponse(200, data)
