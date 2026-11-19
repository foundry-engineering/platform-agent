"""Qualify the evaluation machinery with explicit controlled implementations.

These are harness checks, never model-quality scores. They run before inference.
"""
from __future__ import annotations

import json
import os

import pytest

from builder_runtime_fixture import Harness, IMAGE
from public_quality import CASES, configure


REFERENCE = {
    "py": {
        "has_close_elements": "def has_close_elements(numbers, threshold):\n return any(abs(a-b)<threshold for i,a in enumerate(numbers) for b in numbers[i+1:])\n",
        "make_palindrome": "def make_palindrome(string):\n for i in range(len(string)+1):\n  suffix=string[i:]\n  if suffix==suffix[::-1]: return string+string[:i][::-1]\n",
        "get_positive": "def get_positive(l):\n return [n for n in l if n>0]\n",
    },
    "js": {
        "has_close_elements": "function has_close_elements(numbers,threshold){return numbers.some((a,i)=>numbers.slice(i+1).some(b=>Math.abs(a-b)<threshold))}\n",
        "make_palindrome": "function make_palindrome(string){for(let i=0;i<=string.length;i++){let s=string.slice(i);if(s===[...s].reverse().join(''))return string+[...string.slice(0,i)].reverse().join('')}}\n",
        "get_positive": "function get_positive(l){return l.filter(n=>n>0)}\n",
    },
    "go": {
        "has_close_elements": "package main\nfunc has_close_elements(numbers []float64,threshold float64) bool {for i,a:=range numbers{for _,b:=range numbers[i+1:]{d:=a-b;if d<0{d=-d};if d<threshold{return true}}};return false}\n",
        "make_palindrome": "package main\nfunc make_palindrome(s string) string {for i:=0;i<=len(s);i++{ok:=true;for l,r:=i,len(s)-1;l<r;l,r=l+1,r-1{if s[l]!=s[r]{ok=false;break}};if ok{result:=s;for j:=i-1;j>=0;j--{result+=string(s[j])};return result}};panic(\"unreachable\")}\n",
        "get_positive": "package main\nfunc get_positive(l []int) []int {var result []int;for _,n:=range l{if n>0{result=append(result,n)}};return result}\n",
    },
}


@pytest.mark.parametrize("case", CASES, ids=[c["case_id"] for c in CASES])
def test_actual_runtime_harness_accepts_correct_and_rejects_stub(tmp_path, case):
    if os.environ.get("FOUNDRY_BUILDER_REAL_DOCKER") != "1":
        pytest.skip("actual language runtime required to qualify the quality harness")
    h = Harness(tmp_path)
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    verifier = configure(case, h.workspace, evidence, tmp_path / "oracle", IMAGE)
    assert not verifier.verify(h.task, round_number=1).passed
    source = h.workspace / case["source_path"]
    source.write_text(REFERENCE[case["language"]][case["entry_point"]])
    result = verifier.verify(h.task, round_number=2)
    assert result.passed, result.feedback
    records = [json.loads(p.read_bytes()) for p in evidence.glob("*.json")]
    assert len(records) == 2 and all(r["schema_version"] == "foundry.builder.sandbox-evidence.v3" for r in records)
