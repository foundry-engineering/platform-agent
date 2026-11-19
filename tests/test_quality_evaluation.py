from dataclasses import replace

import pytest

from platform_agent.quality_evaluation import QualityReceipt, quality_report


def receipt(case="case-a", **changes):
    return replace(QualityReceipt(case, "py", "approved/model", "a"*64, "b"*64, "c"*64,
        "d"*64, "verified", 100, 50, 15, 1, ("evidence:actual",)), **changes)


def report(*receipts):
    return quality_report(suite_sha256="f"*64, expected_cases=(("case-a", "py"), ("case-b", "py")), receipts=receipts)


def test_complete_quality_report_remains_a_public_smoke_result_without_release_or_rank():
    value = report(receipt(), receipt("case-b"))
    assert value["complete"] and value["regressionGatePassed"]
    assert value["passed"] == 2 and value["inputTokens"] == 200
    assert value["releaseApproved"] is value["marketRankClaim"] is False


def test_failed_and_missing_cases_are_not_hidden_or_approved():
    value = report(receipt(outcome="needs_revision"))
    assert not value["complete"] and not value["regressionGatePassed"]
    assert (value["passed"], value["failed"], value["notRun"]) == (0, 1, 1)
    assert not value["releaseApproved"]


@pytest.mark.parametrize("receipts", [
    (receipt(), receipt()),
    (receipt("case-c"),),
    (receipt(), receipt("case-b", model_id="different/model")),
    (receipt(), receipt("case-b", profile_sha256="e"*64)),
    (receipt(language="go"),),
])
def test_incomparable_or_unselected_results_cannot_form_a_quality_report(receipts):
    with pytest.raises(ValueError):
        report(*receipts)


@pytest.mark.parametrize("changes", [{"invocations":2}, {"invocations":True}, {"input_tokens":0},
    {"source_sha256":"bad"}, {"evidence_refs":()}, {"outcome":"unknown"}])
def test_unknown_unmetered_or_retried_cases_cannot_be_scored(changes):
    with pytest.raises(ValueError):
        receipt(**changes)
