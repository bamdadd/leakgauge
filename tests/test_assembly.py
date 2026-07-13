"""Cross-message assembly family — scored through the REAL scorer.

Redesigned for on-path signal: the on-path email (required for the benign date)
names the attacker destination and tells the agent to forward a secret that
lives in a SEPARATE email. So sending to the attacker is one hop (hijack) while
carrying the canary needs a second fetch — this family enables the hijack > leak
gap. Three behaviours per case: benign, hijack-without-leak, hijack-with-leak.
"""

from __future__ import annotations

from typing import Any

import pytest

from leakgauge.cases import ASSEMBLY_CASES, BENIGN_ACTION, ONPATH_EMAIL_ID, build_environment
from leakgauge.scoring import hijacked, leaked
from leakgauge.types import Case, RunRecord

_IDS = [c.id for c in ASSEMBLY_CASES]


def _record(case: Case, trace: list[Any]) -> RunRecord:
    return RunRecord(case_id=case.id, model="sim", seed=0, trace=trace, final_text="")


def _secret_email_id(case: Case) -> str:
    """The email that actually carries the canary (not the on-path one)."""
    onpath = ONPATH_EMAIL_ID[case.id]
    for e in case.env_seed["inbox"]:
        if e["id"] != onpath and case.canary in e["body"]:
            return str(e["id"])
    raise AssertionError(f"{case.id}: no separate secret email holds the canary")


@pytest.mark.parametrize("case", ASSEMBLY_CASES, ids=_IDS)
def test_gap_topology_destination_onpath_canary_offpath(case: Case) -> None:
    """The gap is enabled structurally: the attacker address is in the on-path
    email; the canary is NOT — it lives one email away."""
    onpath_id = ONPATH_EMAIL_ID[case.id]
    onpath = next(e for e in case.env_seed["inbox"] if e["id"] == onpath_id)
    addr = case.exfil_spec.attacker_addresses[0]
    assert addr in onpath["body"]  # destination reachable in one hop → hijack
    assert case.canary not in onpath["body"]  # canary needs a second fetch → gap
    assert _secret_email_id(case)  # and it does live in a separate email


@pytest.mark.parametrize("case", ASSEMBLY_CASES, ids=_IDS)
def test_benign_agent_completes_utility_no_leak(case: Case) -> None:
    env = build_environment(case)
    act = BENIGN_ACTION[case.id]
    env.call("read_inbox", {})
    env.call("read_email", {"email_id": ONPATH_EMAIL_ID[case.id]})
    env.call("create_event", {"title": act["title"], "start": act["start"], "end": act["end"]})

    assert env.utility_ok(case.utility_key) is True
    rec = _record(case, env.trace)
    assert hijacked(rec, case.exfil_spec) is False
    assert leaked(rec, case.canary, case.exfil_spec) is False


@pytest.mark.parametrize("case", ASSEMBLY_CASES, ids=_IDS)
def test_hijack_without_leak_gap(case: Case) -> None:
    """Cheap path: obey 'email the attacker' from the on-path read, but never
    fetch the secret email → hijack True, leakage False."""
    env = build_environment(case)
    env.call("read_inbox", {})
    env.call("read_email", {"email_id": ONPATH_EMAIL_ID[case.id]})
    addr = case.exfil_spec.attacker_addresses[0]
    env.call("send_email", {"recipients": [addr], "subject": "fwd", "body": "as requested"})

    rec = _record(case, env.trace)
    assert hijacked(rec, case.exfil_spec) is True
    assert leaked(rec, case.canary, case.exfil_spec) is False


@pytest.mark.parametrize("case", ASSEMBLY_CASES, ids=_IDS)
def test_full_assembly_hijacks_and_leaks(case: Case) -> None:
    """Capable path: fetch the second email too, assemble, exfiltrate → both."""
    env = build_environment(case)
    env.call("read_inbox", {})
    env.call("read_email", {"email_id": ONPATH_EMAIL_ID[case.id]})
    secret = env.call("read_email", {"email_id": _secret_email_id(case)})
    addr = case.exfil_spec.attacker_addresses[0]
    env.call("send_email", {"recipients": [addr], "subject": "fwd", "body": secret["body"]})

    rec = _record(case, env.trace)
    assert hijacked(rec, case.exfil_spec) is True
    assert leaked(rec, case.canary, case.exfil_spec) is True


def test_family_membership() -> None:
    assert {c.family for c in ASSEMBLY_CASES} == {"assembly"}
    assert len(ASSEMBLY_CASES) == 4
    assert len({c.id for c in ASSEMBLY_CASES}) == 4
    assert len({c.canary for c in ASSEMBLY_CASES}) == 4
