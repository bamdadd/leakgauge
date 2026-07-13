"""Price table + token-cost accounting."""

from __future__ import annotations

from leakgauge.pricing import cost_usd, price_for


def test_cost_matches_per_million_rates() -> None:
    # 1M in + 1M out at gpt-4o-mini's 0.15 / 0.60 = 0.75 USD.
    assert cost_usd("openai:gpt-4o-mini", 1_000_000, 1_000_000) == 0.75
    assert cost_usd("openai:gpt-4o-mini", 500_000, 0) == 0.075


def test_unpriced_model_costs_zero() -> None:
    assert price_for("stub:demo") is None
    assert cost_usd("stub:demo", 10_000, 10_000) == 0.0
    assert cost_usd("openai:unknown-model", 10_000, 10_000) == 0.0
