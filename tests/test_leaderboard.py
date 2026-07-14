"""Render-path tests for the static leaderboard, against the CURRENT results
schema (aggregate {point,lo,hi} + optional cost block). Fixtures are built
in-test — no fabricated model rows are shipped.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from leakgauge.leaderboard import render_html, write_site
from leakgauge.suite import rank_reorder


def _summary(model: str, hijack: float, leakage: float, *, n: int = 37) -> dict[str, Any]:
    def ci(p: float) -> dict[str, float]:
        return {"point": p, "lo": max(0.0, p - 0.15), "hi": min(1.0, p + 0.15)}

    return {
        "schema_version": 1,
        "model": model,
        "suite": "all",
        "n_cases": n,
        "aggregate": {
            "hijack_asr": ci(hijack),
            "leakage_asr": ci(leakage),
            "utility_under_attack": ci(0.7),
        },
        "cost": {"spend_usd": 0.25, "priced": True},
    }


def test_single_model_renders_table_and_reorder_pending() -> None:
    out = render_html(
        [_summary("openai:gpt-4o", 0.2, 0.2)], rank_reorder([_summary("m", 0.2, 0.2)])
    )
    # rank_reorder needs >=2 models, so single-model shows the pending note + table
    assert "rank reorder needs" in out.lower() or "≥2" in out or "&ge;2" in out
    assert "openai:gpt-4o" in out
    assert "leakage-verified ASR" in out
    assert "[0.05, 0.35]" in out  # a bootstrap CI shown, not hidden
    assert "THREAT_MODEL.md" in out


def test_reorder_figure_appears_with_two_models() -> None:
    # A hijacks more, B leaks more -> the ranking crosses.
    summaries = [_summary("prov:a", 0.9, 0.3), _summary("prov:b", 0.6, 0.7)]
    reorder = rank_reorder(summaries)
    assert reorder is not None

    out = render_html(summaries, reorder)
    assert "<svg" in out and "</svg>" in out
    assert "Kendall" in out and f"{reorder.kendall_tau:.2f}" in out
    assert "change rank" in out  # explicit crossing count
    assert "prov:a" in out and "prov:b" in out


def test_final_null_framing_when_ranks_agree() -> None:
    # Ranks agree on hijack and leakage (tau = 1) -> the honest negative result.
    summaries = [
        _summary("openai:gpt-4o", 0.081, 0.077),
        _summary("openrouter:meta-llama/llama-3.3-70b-instruct", 0.023, 0.018),
        _summary("openai:gpt-4o-mini", 0.005, 0.005),
    ]
    reorder = rank_reorder(summaries)
    assert reorder is not None and reorder.kendall_tau >= 0.999

    out = render_html(summaries, reorder)
    assert "Final result: no." in out
    assert "does NOT reorder these models" in out
    assert "near the" in out and "floor" in out  # caveat
    assert "future work" in out
    assert "qwen-2.5-72b stalled" in out  # limitations
    assert "gpt-4o, gpt-4o-mini, llama-3.3-70b-instruct" in out  # subtitle names
    assert "THREAT_MODEL.md" in out
    assert "no model changes rank" in out  # figure crossing count for the null


def test_provenance_shows_n_and_spend() -> None:
    out = render_html([_summary("m1", 0.2, 0.2, n=9)], None)
    assert "n=9 cases" in out
    assert "roster compute $0.25" in out


def test_write_site_emits_index_html(tmp_path: Path) -> None:
    summaries = [_summary("prov:a", 0.9, 0.3), _summary("prov:b", 0.6, 0.7)]
    path = write_site(summaries, rank_reorder(summaries), tmp_path)
    assert path == tmp_path / "index.html"
    assert path.read_text(encoding="utf-8").startswith("<!doctype html>")
