from dataclasses import replace

import pytest

from platform_agent.repair_evaluation import RepairReceipt, repair_report


def receipt(**changes):
    return replace(RepairReceipt("case-a","go","approved/model","a"*64,"b"*64,"c"*64,"d"*64,
        "e"*64,"verified",100,50,30,2,(False,True),(10,20),("sha256:"+"f"*64,)),**changes)


def report(*receipts):
    return repair_report(seeds_sha256="1"*64,expected_cases=(("case-a","go"),),receipts=receipts)


def test_actual_repair_counts_every_attempt_without_replacing_first_attempt_scores():
    value=report(receipt())
    assert value["complete"] and value["regressionGatePassed"]
    assert value["invocations"]==2 and value["actualMicrousd"]==30
    assert value["releaseApproved"] is value["marketRankClaim"] is False
    assert value["maximumNewCallsPerCase"]==3


@pytest.mark.parametrize("changes",[{"invocations":4},{"invocations":True},{"round_microusd":(30,)},
    {"actual_microusd":10},{"round_passed":(True,False)},{"round_passed":(True,True)},{"input_tokens":0},{"initial_source_sha256":"invalid"}])
def test_incomplete_unmetered_or_excess_repair_attempts_are_rejected(changes):
    with pytest.raises(ValueError):
        receipt(**changes)


def test_failed_missing_duplicate_or_mixed_repairs_never_form_a_passing_report():
    assert not report()["complete"]
    assert not report(receipt(outcome="needs_revision",round_passed=(False,False)))["regressionGatePassed"]
    with pytest.raises(ValueError):
        report(receipt(),receipt())
    with pytest.raises(ValueError):
        repair_report(seeds_sha256="1"*64,expected_cases=(("case-a","go"),("case-b","go")),
            receipts=(receipt(),receipt(case_id="case-b",profile_sha256="2"*64)))
