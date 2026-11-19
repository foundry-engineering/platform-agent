"""Bounded agent repair observations remain separate from first-attempt scores."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from .quality_evaluation import _digest


@dataclass(frozen=True, slots=True)
class RepairReceipt:
    case_id: str
    language: str
    model_id: str
    profile_sha256: str
    runtime_sha256: str
    initial_source_sha256: str
    final_source_sha256: str
    oracle_sha256: str
    outcome: Literal["verified", "needs_revision"]
    input_tokens: int
    output_tokens: int
    actual_microusd: int
    invocations: int
    round_passed: tuple[bool, ...]
    round_microusd: tuple[int, ...]
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        for value in (self.profile_sha256, self.runtime_sha256, self.initial_source_sha256,
                      self.final_source_sha256, self.oracle_sha256):
            _digest(value)
        if (not self.case_id or not self.language or not self.model_id
                or self.outcome not in {"verified", "needs_revision"}
                or type(self.invocations) is not int or not 1 <= self.invocations <= 3
                or len(self.round_passed) != self.invocations
                or any(type(value) is not bool for value in self.round_passed)
                or len(self.round_microusd) != self.invocations
                or any(type(value) is not int or value < 1 for value in self.round_microusd)
                or self.actual_microusd != sum(self.round_microusd)
                or any(type(v) is not int or v < 1 for v in
                       (self.input_tokens, self.output_tokens, self.actual_microusd))
                or not self.evidence_refs or any(not ref for ref in self.evidence_refs)
                or any(self.round_passed[:-1])
                or ((self.outcome == "verified") != self.round_passed[-1])):
            raise ValueError("bounded observed repair rounds with complete usage required")


def repair_report(
    *, seeds_sha256: str, expected_cases: tuple[tuple[str, str], ...],
    receipts: tuple[RepairReceipt, ...],
) -> dict[str, object]:
    _digest(seeds_sha256)
    expected = dict(expected_cases)
    if not expected or len(expected) != len(expected_cases):
        raise ValueError("exact fixed repair selection required")
    seen: set[str] = set()
    identities: set[tuple[str, str, str]] = set()
    for receipt in receipts:
        if receipt.case_id in seen or expected.get(receipt.case_id) != receipt.language:
            raise ValueError("duplicate or unselected repair case")
        seen.add(receipt.case_id)
        identities.add((receipt.model_id, receipt.profile_sha256, receipt.runtime_sha256))
    if len(identities) > 1:
        raise ValueError("mixed repair model identities")
    passed = sum(receipt.outcome == "verified" for receipt in receipts)
    complete = seen == expected.keys()
    return {
        "schemaVersion": "foundry.recorded-failure-repair-report.v1",
        "evaluation": "repair of recorded public baseline failures; not first-attempt quality",
        "seedsSha256": seeds_sha256, "maximumNewCallsPerCase": 3,
        "expected": len(expected), "passed": passed, "failed": len(receipts) - passed,
        "notRun": len(expected) - len(receipts), "complete": complete,
        "regressionGatePassed": complete and passed == len(expected),
        "invocations": sum(r.invocations for r in receipts),
        "inputTokens": sum(r.input_tokens for r in receipts),
        "outputTokens": sum(r.output_tokens for r in receipts),
        "actualMicrousd": sum(r.actual_microusd for r in receipts),
        "releaseApproved": False, "marketRankClaim": False, "trainingUse": "forbidden",
        "receipts": [asdict(r) for r in sorted(receipts, key=lambda r: r.case_id)],
    }
