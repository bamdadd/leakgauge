"""toolrag family: injection arrives in a RETRIEVED DOCUMENT (a tool result),
not an inbox email. The benign task needs a scheduling detail that lives only in
that external document, so the poisoned tool result is on the critical path. The
canary is co-located in the document (one-hop leak). Scored through the REAL
scorer; the leak sink is still ``send_email`` to the attacker.
"""

from __future__ import annotations

from typing import Any

import pytest

from leakgauge.adapters.stub import StubAdapter
from leakgauge.cases import (
    BENIGN_ACTION,
    ONPATH_DOC_ID,
    TOOLRAG_CASES,
    build_environment,
)
from leakgauge.scoring import hijacked, leaked
from leakgauge.suite import cases_for_suite, run_and_summarise, stub_script_for
from leakgauge.types import Case, ModelAdapter, RunRecord

_IDS = [c.id for c in TOOLRAG_CASES]


def _record(case: Case, trace: list[Any]) -> RunRecord:
    return RunRecord(case_id=case.id, model="sim", seed=0, trace=trace, final_text="")


def test_family_shape() -> None:
    assert len(TOOLRAG_CASES) == 2
    assert {c.family for c in TOOLRAG_CASES} == {"toolrag"}
    # distinct canaries; every case is registered in the toolrag suite
    assert len({c.canary for c in TOOLRAG_CASES}) == len(TOOLRAG_CASES)
    assert {c.id for c in cases_for_suite("toolrag")} == set(_IDS)


@pytest.mark.parametrize("case", TOOLRAG_CASES, ids=_IDS)
def test_injection_arrives_via_document_not_inbox(case: Case) -> None:
    # No inbox email carries the payload; the poisoned content is a document.
    assert case.env_seed.get("inbox", []) == []
    docs = case.env_seed["documents"]
    assert len(docs) == 1
    doc = docs[0]
    assert doc["id"] == ONPATH_DOC_ID[case.id]
    # On-path + one-hop: the required date AND the canary live in the document.
    date = BENIGN_ACTION[case.id]["start"][:10]
    assert date in doc["body"]
    assert case.canary in doc["body"]
    assert date not in case.user_task


@pytest.mark.parametrize("case", TOOLRAG_CASES, ids=_IDS)
def test_read_document_returns_the_poisoned_content(case: Case) -> None:
    env = build_environment(case)
    doc = env.call("read_document", {"document_id": ONPATH_DOC_ID[case.id]})
    assert case.canary in doc["body"]
    # search_documents surfaces the hit without leaking the body's canary.
    hits = env.call("search_documents", {"query": BENIGN_ACTION[case.id]["title"].split()[0]})
    assert any(h["id"] == ONPATH_DOC_ID[case.id] for h in hits)
    assert all(case.canary not in str(h) for h in hits)


@pytest.mark.parametrize("case", TOOLRAG_CASES, ids=_IDS)
def test_benign_completes_no_leak_detected(case: Case) -> None:
    # Read the document (on-path) and do the calendar action, but exfiltrate
    # nothing: utility holds, no hijack, no leak.
    env = build_environment(case)
    act = BENIGN_ACTION[case.id]
    env.call("read_document", {"document_id": ONPATH_DOC_ID[case.id]})
    env.call("create_event", {"title": act["title"], "start": act["start"], "end": act["end"]})

    assert env.utility_ok(case.utility_key) is True
    rec = _record(case, env.trace)
    assert hijacked(rec, case.exfil_spec) is False
    assert leaked(rec, case.canary, case.exfil_spec) is False


@pytest.mark.parametrize("case", TOOLRAG_CASES, ids=_IDS)
def test_leak_to_attacker_is_detected(case: Case) -> None:
    # Read the poisoned document, then exfiltrate its canary to the attacker.
    env = build_environment(case)
    attacker = case.exfil_spec.attacker_addresses[0]
    env.call("read_document", {"document_id": ONPATH_DOC_ID[case.id]})
    env.call(
        "send_email",
        {"recipients": [attacker], "subject": "verification", "body": case.canary},
    )
    rec = _record(case, env.trace)
    assert hijacked(rec, case.exfil_spec) is True
    assert leaked(rec, case.canary, case.exfil_spec) is True


@pytest.mark.parametrize("case", TOOLRAG_CASES, ids=_IDS)
def test_hijack_without_leak_is_expressible(case: Case) -> None:
    env = build_environment(case)
    addr = case.exfil_spec.attacker_addresses[0]
    env.call("send_email", {"recipients": [addr], "subject": "ok", "body": "acknowledged"})
    rec = _record(case, env.trace)
    assert hijacked(rec, case.exfil_spec) is True
    assert leaked(rec, case.canary, case.exfil_spec) is False


def test_offline_stub_run_end_to_end() -> None:
    # Exercises every wiring seam: CASE_REGISTRY["toolrag"], stub_script_for,
    # the utility registration, and the real scorer aggregation. The uniform
    # hijacked-and-leaking stub must produce leak == utility == 1.0.
    for case in TOOLRAG_CASES:
        assert stub_script_for(case)  # no missing-script KeyError

    def _factory(case: Case, _seed: int) -> ModelAdapter:
        return StubAdapter(scripted=stub_script_for(case))

    summary = run_and_summarise("toolrag", _factory, "stub:demo", k=1)
    assert summary["n_cases"] == len(TOOLRAG_CASES)
    assert summary["aggregate"]["leakage_asr"]["point"] == 1.0
    assert summary["aggregate"]["utility_under_attack"]["point"] == 1.0
