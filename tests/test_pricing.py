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


def test_current_anthropic_ids_are_priced() -> None:
    # The claude-3.5 *-latest aliases are retired (404); the current ids must be
    # priced, not silently $0.
    for model_id in ("anthropic:claude-sonnet-4-6", "anthropic:claude-haiku-4-5-20251001"):
        assert price_for(model_id) is not None
        assert cost_usd(model_id, 1_000_000, 1_000_000) > 0.0
    # The retired aliases must no longer be in the table.
    assert price_for("anthropic:claude-3-5-sonnet-latest") is None
    assert price_for("anthropic:claude-3-5-haiku-latest") is None
