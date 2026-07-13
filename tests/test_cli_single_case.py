"""--case <id> runs exactly one case (respecting --k/--model), erroring clearly
on an unknown id."""

from __future__ import annotations

import json
from pathlib import Path

from leakgauge.cli import main
from leakgauge.suite import cases_for_suite


def test_case_runs_single_case_with_stub(tmp_path: Path) -> None:
    case_id = cases_for_suite("all")[0].id
    rc = main(
        ["--case", case_id, "--model", "stub:demo", "--k", "2", "--results-dir", str(tmp_path)]
    )
    assert rc == 0

    summary = json.loads((tmp_path / "stub_demo.json").read_text(encoding="utf-8"))
    assert summary["n_cases"] == 1
    assert summary["k"] == 2  # respects --k
    assert summary["suite"] == f"case:{case_id}"
    assert [row["case_id"] for row in summary["cases"]] == [case_id]


def test_unknown_case_id_errors_cleanly(tmp_path: Path) -> None:
    rc = main(["--case", "no-such-case", "--results-dir", str(tmp_path)])
    assert rc == 2
    assert not (tmp_path / "stub_demo.json").exists()  # nothing written on error
