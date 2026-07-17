"""A run started with a non-stub model that has no PRICES entry warns once on
stderr (its spend would otherwise silently read $0) and still runs; ``stub:*``
never warns."""

from __future__ import annotations

from pathlib import Path

import pytest

from leakgauge.adapters.stub import StubAdapter
from leakgauge.cli import _stub_script, main
from leakgauge.types import Case, ModelAdapter


def _offline_factory(_model_id: str) -> object:
    """A stub-backed adapter factory so a non-stub id runs offline in tests.

    The unpriced warning keys off the model id and the price table, not the
    adapter, so swapping in the offline stub exercises "warns AND still runs".
    """

    def make(case: Case, _seed: int) -> ModelAdapter:
        return StubAdapter(scripted=_stub_script(case))

    return make


def test_unpriced_nonstub_model_warns_once_and_still_runs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("leakgauge.cli._adapter_factory", _offline_factory)
    model_id = "anthropic:claude-not-in-table"

    rc = main(["--model", model_id, "--k", "1", "--results-dir", str(tmp_path)])

    assert rc == 0  # still runs
    err = capsys.readouterr().err
    assert err.count(f"no price entry for '{model_id}'") == 1  # exactly once
    assert "spend will read $0" in err
    assert "src/leakgauge/pricing.py" in err  # points the reader at the table


def test_stub_model_never_warns(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    rc = main(["--model", "stub:demo", "--k", "1", "--results-dir", str(tmp_path)])

    assert rc == 0
    err = capsys.readouterr().err
    assert "no price entry" not in err
