"""Multi-case suite runner + results serialisation + rank-reorder report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from leakgauge.cli import _adapter_factory, main
from leakgauge.suite import (
    SCHEMA_VERSION,
    cases_for_suite,
    load_summary,
    rank_reorder,
    run_and_summarise,
    stub_script_for,
    write_summary,
)
from leakgauge.types import Case, ExfilSpec

_STUB = _adapter_factory("stub:demo")


def _summary(suite: str = "all", k: int = 3) -> dict[str, Any]:
    # Small bootstrap for test speed; the CI math is unchanged.
    return run_and_summarise(suite, _STUB, "stub:demo", k=k, bootstrap_iters=200)


def test_run_and_summarise_shape_and_rates() -> None:
    summary = _summary(k=3)

    assert summary["schema_version"] == SCHEMA_VERSION
    assert summary["model"] == "stub:demo"
    assert summary["k"] == 3
    assert summary["seeds"] == [0, 1, 2]
    assert summary["n_cases"] == len(cases_for_suite("all"))
    assert summary["wall_clock_s"] >= 0.0

    agg = summary["aggregate"]
    assert agg["hijack_asr"]["point"] == 1.0
    assert agg["leakage_asr"]["point"] == 1.0
    assert agg["utility_under_attack"]["point"] == 1.0

    assert len(summary["cases"]) == summary["n_cases"]
    row = summary["cases"][0]
    assert row["hijack_mean"] == 1.0 and row["hijack_std"] == 0.0
    assert row["leakage_mean"] == 1.0
    assert row["n"] == 3


def test_write_summary_is_tracked_json_and_roundtrips(tmp_path: Path) -> None:
    summary = _summary()
    path = write_summary(summary, tmp_path)

    assert path.name == "stub_demo.json"  # ':' sanitised for the filename
    assert not path.name.endswith(".raw.json")  # tracked, not the gitignored form
    assert load_summary(path) == summary


def test_missing_stub_script_raises() -> None:
    orphan = Case(
        id="no-script-case",
        family="delayed",
        user_task="x",
        env_seed={},
        canary="LKG-" + "0" * 32,
        exfil_spec=ExfilSpec(attacker_addresses=["a@b.test"], external_tools=[]),
        utility_key="delayed_kickoff_scheduled",
    )
    with pytest.raises(KeyError):
        stub_script_for(orphan)


def test_load_summary_rejects_non_summary(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"not": "a summary"}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_summary(bad)


def _fake_summary(model: str, hijack: float, leakage: float) -> dict[str, Any]:
    ci = lambda p: {"point": p, "lo": p, "hi": p}  # noqa: E731
    return {
        "schema_version": SCHEMA_VERSION,
        "model": model,
        "n_cases": 5,
        "aggregate": {"hijack_asr": ci(hijack), "leakage_asr": ci(leakage)},
    }


def test_rank_reorder_detects_reordering() -> None:
    # A hijacks more but leaks less; B the reverse -> ranking flips.
    a = _fake_summary("model-a", hijack=0.9, leakage=0.2)
    b = _fake_summary("model-b", hijack=0.5, leakage=0.8)
    reorder = rank_reorder([a, b])

    assert reorder is not None
    assert reorder.models_by_hijack == ["model-a", "model-b"]
    assert reorder.models_by_leakage == ["model-b", "model-a"]
    assert reorder.hijack_ranks["model-a"] == 1
    assert reorder.leakage_ranks["model-a"] == 2
    assert reorder.kendall_tau < 0  # perfect anti-correlation on two models


def test_rank_reorder_needs_two_models() -> None:
    assert rank_reorder([_fake_summary("solo", 0.5, 0.5)]) is None


def test_cli_run_writes_results_and_report_reads_them(tmp_path: Path) -> None:
    assert (
        main(["--model", "stub:demo", "--suite", "all", "--k", "3", "--results-dir", str(tmp_path)])
        == 0
    )
    written = tmp_path / "stub_demo.json"
    assert written.exists()

    # Two model files -> the report subcommand runs the reorder end to end.
    second = tmp_path / "other.json"
    second.write_text(
        json.dumps(_fake_summary("stub:other", hijack=0.4, leakage=0.9)) + "\n", encoding="utf-8"
    )
    assert main(["report", str(written), str(second)]) == 0
