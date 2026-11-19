"""A complete first-attempt smoke report never implies a product release."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Literal


def _digest(value: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise ValueError("exact SHA-256 required")


@dataclass(frozen=True, slots=True)
class QualityReceipt:
    case_id: str
    language: str
    model_id: str
    profile_sha256: str
    runtime_sha256: str
    source_sha256: str
    oracle_sha256: str
    outcome: Literal["verified", "needs_revision"]
    input_tokens: int
    output_tokens: int
    actual_microusd: int
    invocations: int
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        for value in (self.profile_sha256, self.runtime_sha256, self.source_sha256, self.oracle_sha256):
            _digest(value)
        if (not self.model_id or not self.case_id or not self.language
                or self.outcome not in {"verified", "needs_revision"}
                or self.invocations != 1 or type(self.invocations) is not int
                or any(type(v) is not int or v <= 0 for v in
                       (self.input_tokens, self.output_tokens, self.actual_microusd))
                or not self.evidence_refs or any(not ref for ref in self.evidence_refs)):
            raise ValueError("one observed metered attempt with verification evidence required")


def quality_report(
    *, suite_sha256: str, expected_cases: tuple[tuple[str, str], ...],
    receipts: tuple[QualityReceipt, ...],
) -> dict[str, object]:
    _digest(suite_sha256)
    expected = dict(expected_cases)
    if not expected or len(expected) != len(expected_cases):
        raise ValueError("fixed unique case selection required")
    seen: set[str] = set()
    identities: set[tuple[str, str, str]] = set()
    for receipt in receipts:
        if receipt.case_id in seen or expected.get(receipt.case_id) != receipt.language:
            raise ValueError("duplicate or unselected quality case")
        seen.add(receipt.case_id)
        identities.add((receipt.model_id, receipt.profile_sha256, receipt.runtime_sha256))
    if len(identities) > 1:
        raise ValueError("mixed model configurations cannot share one quality report")
    passed = sum(r.outcome == "verified" for r in receipts)
    complete = seen == expected.keys()
    return {
        "schemaVersion": "foundry.public-quality-report.v1",
        "suiteSha256": suite_sha256,
        "evaluation": "public first-attempt smoke subset; not a market benchmark",
        "trainingUse": "forbidden", "marketRankClaim": False, "releaseApproved": False,
        "expected": len(expected), "passed": passed, "failed": len(receipts) - passed,
        "notRun": len(expected) - len(receipts), "complete": complete,
        "regressionGatePassed": complete and passed == len(expected),
        "inputTokens": sum(r.input_tokens for r in receipts),
        "outputTokens": sum(r.output_tokens for r in receipts),
        "actualMicrousd": sum(r.actual_microusd for r in receipts),
        "receipts": [asdict(r) for r in sorted(receipts, key=lambda r: r.case_id)],
    }
