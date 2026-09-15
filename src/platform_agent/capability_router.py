from __future__ import annotations

from dataclasses import dataclass


class CapabilityRegistryError(ValueError):
    """Raised when capability advertisements cannot form a safe registry."""


class CapabilityRoutingError(ValueError):
    """Raised when deterministic routing cannot select exactly one agent."""


@dataclass(frozen=True, slots=True)
class CapabilityRecord:
    agent_id: str
    capability_id: str
    version: str
    input_schema: str
    output_schema: str

    def as_dict(self) -> dict[str, str]:
        return {
            "agent_id": self.agent_id,
            "capability_id": self.capability_id,
            "version": self.version,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
        }


@dataclass(frozen=True, slots=True)
class RouteDecision:
    agent_id: str
    required_capabilities: tuple[str, ...]
    matched_capabilities: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "required_capabilities": list(self.required_capabilities),
            "matched_capabilities": list(self.matched_capabilities),
        }


class CapabilityRegistry:
    """Deterministic, fail-closed in-memory capability registry.

    Advertisements are expected to have passed APv1 schema validation at the
    protocol boundary. The registry still validates the fields it relies on so
    routing never silently continues with malformed or conflicting data.
    """

    def __init__(self, records: tuple[CapabilityRecord, ...]) -> None:
        by_agent: dict[str, dict[str, CapabilityRecord]] = {}

        for record in records:
            if not record.agent_id:
                raise CapabilityRegistryError("agent_id must not be empty")
            if not record.capability_id.startswith("cap_"):
                raise CapabilityRegistryError(
                    f"invalid capability_id: {record.capability_id}"
                )
            if not record.version:
                raise CapabilityRegistryError(
                    f"capability {record.capability_id} has empty version"
                )
            if not record.input_schema or not record.output_schema:
                raise CapabilityRegistryError(
                    f"capability {record.capability_id} must declare I/O schemas"
                )

            agent_capabilities = by_agent.setdefault(record.agent_id, {})
            existing = agent_capabilities.get(record.capability_id)
            if existing is not None and existing != record:
                raise CapabilityRegistryError(
                    "conflicting capability advertisement for "
                    f"{record.agent_id}:{record.capability_id}"
                )
            agent_capabilities[record.capability_id] = record

        self._by_agent = {
            agent_id: dict(sorted(capabilities.items()))
            for agent_id, capabilities in sorted(by_agent.items())
        }

    @classmethod
    def from_apv1_payloads(
        cls,
        advertisements: dict[str, object],
    ) -> "CapabilityRegistry":
        records: list[CapabilityRecord] = []

        for agent_id in sorted(advertisements):
            payload = advertisements[agent_id]
            if not isinstance(payload, dict):
                raise CapabilityRegistryError(
                    f"advertisement for {agent_id} must be an object"
                )
            if payload.get("type") != "capability.advertise":
                raise CapabilityRegistryError(
                    f"advertisement for {agent_id} has invalid type"
                )

            capabilities = payload.get("capabilities")
            if not isinstance(capabilities, list) or not capabilities:
                raise CapabilityRegistryError(
                    f"advertisement for {agent_id} has no capabilities"
                )

            for capability in capabilities:
                if not isinstance(capability, dict):
                    raise CapabilityRegistryError(
                        f"advertisement for {agent_id} contains invalid capability"
                    )

                capability_id = capability.get("capability_id")
                version = capability.get("version")
                input_schema = capability.get("input_schema")
                output_schema = capability.get("output_schema")
                if not all(
                    isinstance(value, str)
                    for value in (
                        capability_id,
                        version,
                        input_schema,
                        output_schema,
                    )
                ):
                    raise CapabilityRegistryError(
                        f"advertisement for {agent_id} has malformed capability fields"
                    )

                records.append(
                    CapabilityRecord(
                        agent_id=agent_id,
                        capability_id=capability_id,
                        version=version,
                        input_schema=input_schema,
                        output_schema=output_schema,
                    )
                )

        return cls(tuple(records))

    @property
    def agent_ids(self) -> tuple[str, ...]:
        return tuple(self._by_agent)

    def capabilities_for(self, agent_id: str) -> tuple[str, ...]:
        try:
            capabilities = self._by_agent[agent_id]
        except KeyError as exc:
            raise CapabilityRoutingError(f"unknown agent: {agent_id}") from exc
        return tuple(capabilities)

    def candidates(
        self,
        required_capabilities: tuple[str, ...],
    ) -> tuple[str, ...]:
        required = tuple(sorted(set(required_capabilities)))
        if not required:
            raise CapabilityRoutingError(
                "routing requires at least one required capability"
            )

        candidates: list[str] = []
        for agent_id, capabilities in self._by_agent.items():
            if all(capability in capabilities for capability in required):
                candidates.append(agent_id)
        return tuple(candidates)

    def route(
        self,
        required_capabilities: tuple[str, ...],
        *,
        preferred_owner: str | None = None,
    ) -> RouteDecision:
        required = tuple(sorted(set(required_capabilities)))
        candidates = self.candidates(required)

        if preferred_owner is not None:
            if preferred_owner not in self._by_agent:
                raise CapabilityRoutingError(
                    f"preferred owner is not registered: {preferred_owner}"
                )
            if preferred_owner not in candidates:
                missing = sorted(
                    set(required) - set(self._by_agent[preferred_owner])
                )
                raise CapabilityRoutingError(
                    f"preferred owner {preferred_owner} lacks capabilities: "
                    + ", ".join(missing)
                )
            selected = preferred_owner
        else:
            if not candidates:
                raise CapabilityRoutingError(
                    "no agent satisfies required capabilities: "
                    + ", ".join(required)
                )
            if len(candidates) > 1:
                raise CapabilityRoutingError(
                    "ambiguous route; multiple agents satisfy requirements: "
                    + ", ".join(candidates)
                )
            selected = candidates[0]

        return RouteDecision(
            agent_id=selected,
            required_capabilities=required,
            matched_capabilities=required,
        )
