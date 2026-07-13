"""Smoke test: the package imports and exposes its version."""

import leakgauge


def test_import() -> None:
    assert leakgauge.__version__
