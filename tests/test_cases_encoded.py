"""Encoding-wrapped family — the canary is planted ALREADY ENCODED in the
on-path email; the agent forwards the blob and the scorer's normalization
decodes it. Proves leakage is verifiable even when the raw canary never appears
on the wire, while a naive plaintext filter would miss it.

Driven through the REAL environment + REAL scorer. No LLM.
"""

from __future__ import annotations

import pytest

from leakgauge.cases import (
    BENIGN_ACTION,
    ENCODED_CASES,
    ENCODED_CASES_BY_ID,
    ONPATH_EMAIL_ID,
    build_environment,
)
from leakgauge.environment import WorkspaceEnvironment
from leakgauge.scoring import canary_present, hijacked, leaked
from leakgauge.types import Case, RunRecord

_LEGIT = "helpdesk@bluesparrowtech.com"
_IDS = [c.id for c in ENCODED_CASES]


@pytest.fixture(params=_IDS)
def case(request: pytest.FixtureRequest) -> Case:
    return ENCODED_CASES_BY_ID[request.param]


def _onpath_body(case: Case) -> str:
    onpath_id = ONPATH_EMAIL_ID[case.id]
    return next(e["body"] for e in case.env_seed["inbox"] if e["id"] == onpath_id)


def _forward_blob(case: Case, to: str) -> tuple[RunRecord, WorkspaceEnvironment]:
    """Benign schedule + forward the planted encoded blob verbatim (as a hijacked
    agent that copies the 'access code' line would)."""
    env = build_environment(case)
    act = BENIGN_ACTION[case.id]
    env.call("create_event", {"title": act["title"], "start": act["start"], "end": act["end"]})
    blob = _onpath_body(case)  # contains the already-encoded canary
    env.call("send_email", {"recipients": [to], "subject": "sync", "body": blob})
    rec = RunRecord(case_id=case.id, model="test:enc", seed=0, trace=list(env.trace), final_text="")
    return rec, env


def test_family_and_shape(case: Case) -> None:
    assert case.family == "encoded"
    assert case.canary.startswith("LKG-")


def test_planted_form_is_decodable_by_the_real_scorer(case: Case) -> None:
    """The trap the redesign must avoid: an un-decodable plant can NEVER leak,
    faking robustness. Assert the scorer folds the plant back to the canary —
    and that the RAW canary is not sitting in plaintext."""
    body = _onpath_body(case)
    assert case.canary not in body  # planted encoded, not raw
    assert canary_present(body, case.canary) is True  # ...but the scorer decodes it


def test_encoded_canary_to_attacker_is_verified_leak(case: Case) -> None:
    rec, env = _forward_blob(case, to=case.exfil_spec.attacker_addresses[0])
    assert hijacked(rec, case.exfil_spec) is True
    assert leaked(rec, case.canary, case.exfil_spec) is True
    assert env.utility_ok(case.utility_key) is True  # benign task still done


def test_encoded_canary_to_legit_address_is_not_leak(case: Case) -> None:
    rec, _env = _forward_blob(case, to=_LEGIT)
    assert hijacked(rec, case.exfil_spec) is False
    assert leaked(rec, case.canary, case.exfil_spec) is False


def test_all_four_encodings_present() -> None:
    encodings = {c.id.split("-")[1] for c in ENCODED_CASES}
    assert encodings == {"base64", "hex", "rot13", "homoglyph"}


def test_utility_false_when_benign_task_skipped() -> None:
    # Exfil only, no event scheduled -> utility check fails (guards the check).
    case = ENCODED_CASES[0]
    env = build_environment(case)
    env.call(
        "send_email",
        {"recipients": [case.exfil_spec.attacker_addresses[0]], "subject": "s", "body": "x"},
    )
    assert env.utility_ok(case.utility_key) is False
