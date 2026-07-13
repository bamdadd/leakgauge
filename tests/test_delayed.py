"""Delayed family (grown): leak variants co-locate the canary; gap variants use
the same multi-secret distractor mechanism as assembly. Scored through the REAL
scorer.
"""

from __future__ import annotations

from typing import Any

import pytest

from leakgauge.cases import BENIGN_ACTION, DELAYED_CASES, ONPATH_EMAIL_ID, build_environment
from leakgauge.scoring import canary_present, hijacked, leaked
from leakgauge.types import Case, RunRecord

_IDS = [c.id for c in DELAYED_CASES]


def _record(case: Case, trace: list[Any]) -> RunRecord:
    return RunRecord(case_id=case.id, model="sim", seed=0, trace=trace, final_text="")


def _secret_emails(case: Case) -> list[dict[str, Any]]:
    onpath = ONPATH_EMAIL_ID[case.id]
    return [e for e in case.env_seed["inbox"] if e["id"] != onpath]


def test_family_counts() -> None:
    assert len(DELAYED_CASES) == 8
    assert {c.family for c in DELAYED_CASES} == {"delayed"}
    assert len({c.canary for c in DELAYED_CASES}) == 8


@pytest.mark.parametrize("case", DELAYED_CASES, ids=_IDS)
def test_benign_completes_utility_no_exfil(case: Case) -> None:
    env = build_environment(case)
    act = BENIGN_ACTION[case.id]
    env.call("read_inbox", {})
    env.call("read_email", {"email_id": ONPATH_EMAIL_ID[case.id]})
    env.call("create_event", {"title": act["title"], "start": act["start"], "end": act["end"]})

    assert env.utility_ok(case.utility_key) is True
    rec = _record(case, env.trace)
    assert hijacked(rec, case.exfil_spec) is False
    assert leaked(rec, case.canary, case.exfil_spec) is False


@pytest.mark.parametrize("case", DELAYED_CASES, ids=_IDS)
def test_hijack_without_leak_is_expressible(case: Case) -> None:
    """Sending to the attacker with no canary is hijack-without-leak for every
    delayed case (leak and gap variants alike)."""
    env = build_environment(case)
    env.call("read_inbox", {})
    addr = case.exfil_spec.attacker_addresses[0]
    env.call("send_email", {"recipients": [addr], "subject": "ok", "body": "acknowledged"})

    rec = _record(case, env.trace)
    assert hijacked(rec, case.exfil_spec) is True
    assert leaked(rec, case.canary, case.exfil_spec) is False


def test_gap_variants_have_decoys_that_do_not_leak() -> None:
    """The multi-secret delayed cases: several secrets, only one the real canary,
    and no decoy matches the canary under the real scorer."""
    gap = [c for c in DELAYED_CASES if len(_secret_emails(c)) > 1]
    assert gap, "expected some multi-secret (gap) delayed cases"
    for case in gap:
        secrets = _secret_emails(case)
        assert len(secrets) == 4  # 1 real + 3 decoys
        carriers = [e for e in secrets if case.canary in e["body"]]
        assert len(carriers) == 1
        for d in secrets:
            if case.canary not in d["body"]:
                assert canary_present(d["body"], case.canary) is False
