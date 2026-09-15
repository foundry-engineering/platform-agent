from __future__ import annotations

import pytest

from platform_agent.capability_router import (
    CapabilityRegistry,
    CapabilityRegistryError,
    CapabilityRoutingError,
)


def _payload(*capability_ids: str) -> dict[str, object]:
    return {
        "type": "capability.advertise",
        "capabilities": [
            {
                "capability_id": capability_id,
                "version": "1.0.0",
                "input_schema": f"schema://{capability_id}/input",
                "output_schema": f"schema://{capability_id}/output",
            }
            for capability_id in capability_ids
        ],
    }


def test_unique_capability_route_is_deterministic() -> None:
    registry = CapabilityRegistry.from_apv1_payloads(
        {
            "backend-agent": _payload("cap_backend.service"),
            "frontend-agent": _payload("cap_frontend.web"),
        }
    )

    decision = registry.route(("cap_frontend.web",))

    assert decision.agent_id == "frontend-agent"
    assert decision.required_capabilities == ("cap_frontend.web",)


def test_route_requires_all_capabilities() -> None:
    registry = CapabilityRegistry.from_apv1_payloads(
        {
            "fullstack-agent": _payload("cap_backend.service", "cap_frontend.web"),
            "frontend-agent": _payload("cap_frontend.web"),
        }
    )

    decision = registry.route(("cap_frontend.web", "cap_backend.service"))

    assert decision.agent_id == "fullstack-agent"


def test_ambiguous_route_fails_closed_without_owner() -> None:
    registry = CapabilityRegistry.from_apv1_payloads(
        {
            "frontend-a": _payload("cap_frontend.web"),
            "frontend-b": _payload("cap_frontend.web"),
        }
    )

    with pytest.raises(CapabilityRoutingError, match="ambiguous route"):
        registry.route(("cap_frontend.web",))


def test_preferred_owner_must_be_registered_and_capable() -> None:
    registry = CapabilityRegistry.from_apv1_payloads(
        {
            "backend-agent": _payload("cap_backend.service"),
            "frontend-agent": _payload("cap_frontend.web"),
        }
    )

    with pytest.raises(CapabilityRoutingError, match="lacks capabilities"):
        registry.route(
            ("cap_frontend.web",),
            preferred_owner="backend-agent",
        )

    with pytest.raises(CapabilityRoutingError, match="not registered"):
        registry.route(
            ("cap_frontend.web",),
            preferred_owner="unknown-agent",
        )


def test_missing_capability_fails_closed() -> None:
    registry = CapabilityRegistry.from_apv1_payloads(
        {
            "frontend-agent": _payload("cap_frontend.web"),
        }
    )

    with pytest.raises(CapabilityRoutingError, match="no agent satisfies"):
        registry.route(("cap_security.scan",))


def test_malformed_advertisement_is_rejected() -> None:
    with pytest.raises(CapabilityRegistryError, match="invalid type"):
        CapabilityRegistry.from_apv1_payloads(
            {
                "frontend-agent": {
                    "type": "wrong",
                    "capabilities": [],
                }
            }
        )
