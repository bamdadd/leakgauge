"""--k and --seed are validated before a run starts, so a degenerate value
(zero repeats, negative seed) fails with a clear message instead of a confusing
empty run downstream."""

from __future__ import annotations

from pathlib import Path

from leakgauge.cli import main


def test_k_zero_errors_cleanly(tmp_path: Path) -> None:
    rc = main(["--k", "0", "--results-dir", str(tmp_path)])
    assert rc == 2
    assert not (tmp_path / "stub_demo.json").exists()  # nothing written on error


def test_k_negative_errors_cleanly(tmp_path: Path) -> None:
    rc = main(["--k", "-1", "--results-dir", str(tmp_path)])
    assert rc == 2
    assert not (tmp_path / "stub_demo.json").exists()


def test_seed_negative_errors_cleanly(tmp_path: Path) -> None:
    rc = main(["--seed", "-1", "--results-dir", str(tmp_path)])
    assert rc == 2
    assert not (tmp_path / "stub_demo.json").exists()


def test_valid_k_and_seed_still_run(tmp_path: Path) -> None:
    rc = main(["--k", "2", "--seed", "0", "--results-dir", str(tmp_path)])
    assert rc == 0
    assert (tmp_path / "stub_demo.json").exists()
