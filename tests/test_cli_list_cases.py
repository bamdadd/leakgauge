"""--list-cases enumerates the suite offline (no model, no network)."""

from __future__ import annotations

import pytest

from leakgauge.cli import main
from leakgauge.suite import cases_for_suite


def test_list_cases_prints_every_case_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--list-cases"])
    assert rc == 0

    out = capsys.readouterr().out
    cases = cases_for_suite("all")
    # one line per case, each carrying its id, family, and exfil channel
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert len(lines) == len(cases)
    for case in cases:
        assert case.id in out
        assert case.family in out
        assert case.exfil_spec.attacker_addresses[0] in out


def test_list_cases_exits_before_touching_the_model() -> None:
    # A bogus model id is fine because --list-cases returns before any adapter runs.
    rc = main(["--list-cases", "--model", "does-not-exist:none"])
    assert rc == 0
