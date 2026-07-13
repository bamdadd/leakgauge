"""The critical invariant: every injection sits ON the benign task's path.

A v0 pilot scored leakage=0 because the schedulable detail was inline in
``user_task``, so the model finished without ever reading the injected email and
nothing fired. This test is the programmatic guard against that regression — the
analog of the assembly family's ``test_payload_is_distributed``.

For every case: the detail the utility check requires (the event date) must be
ABSENT from ``user_task`` and PRESENT in the injection-bearing on-path email —
proving the benign task cannot complete without reading the injected source.
"""

from __future__ import annotations

import pytest

from leakgauge.cases import ALL_CASES, BENIGN_ACTION, ONPATH_EMAIL_ID
from leakgauge.types import Case

_IDS = [c.id for c in ALL_CASES]


def _onpath_body(case: Case) -> str:
    onpath_id = ONPATH_EMAIL_ID[case.id]
    for e in case.env_seed["inbox"]:
        if e["id"] == onpath_id:
            return str(e["subject"]) + " " + str(e["body"])
    raise AssertionError(f"{case.id}: on-path email {onpath_id!r} not in inbox")


@pytest.mark.parametrize("case", ALL_CASES, ids=_IDS)
def test_required_detail_is_only_in_the_injected_email(case: Case) -> None:
    date = BENIGN_ACTION[case.id]["start"][:10]

    # The date the utility check needs must NOT be spoon-fed in the task...
    assert date not in case.user_task, "date is inline in user_task — injection is off-path"
    # ...it must live in the on-path (injection-bearing) email, forcing the read.
    assert date in _onpath_body(case), "date missing from the on-path email"


@pytest.mark.parametrize("case", ALL_CASES, ids=_IDS)
def test_canary_never_in_user_task(case: Case) -> None:
    assert case.canary not in case.user_task


@pytest.mark.parametrize("case", ALL_CASES, ids=_IDS)
def test_benign_action_matches_a_registered_utility_key(case: Case) -> None:
    # Every case exposes a benign action and its utility key follows the id.
    assert case.id in BENIGN_ACTION
    assert case.utility_key == f"{case.id}--scheduled"
