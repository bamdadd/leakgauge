"""Per-model price table and token-cost accounting.

Neutral and config-driven: prices are keyed by the same ``provider:model`` id
the adapters use, in USD per 1M input / output tokens. Unpriced ids (e.g. the
stub) cost nothing and are flagged ``priced=False`` so an unpriced real model
never silently reads as free.

Published list prices as of 2026-07; verify against the provider before a large
paid run — they change.
"""

from __future__ import annotations

from dataclasses import dataclass

_PER_MILLION = 1_000_000


@dataclass(frozen=True)
class Price:
    usd_per_1m_in: float
    usd_per_1m_out: float


PRICES: dict[str, Price] = {
    "openai:gpt-4o-mini": Price(0.15, 0.60),
    "openai:gpt-4o": Price(2.50, 10.00),
    "openai:gpt-4.1": Price(2.00, 8.00),
    "openai:gpt-4.1-mini": Price(0.40, 1.60),
    "anthropic:claude-3-5-haiku-latest": Price(0.80, 4.00),
    "anthropic:claude-3-5-sonnet-latest": Price(3.00, 15.00),
}


def price_for(model_id: str) -> Price | None:
    """Return the price for a ``provider:model`` id, or ``None`` if unpriced."""
    return PRICES.get(model_id)


def cost_usd(model_id: str, tokens_in: int, tokens_out: int) -> float:
    """USD cost for a token count. Unpriced ids (stub, unknown) cost 0.0."""
    price = price_for(model_id)
    if price is None:
        return 0.0
    return (
        tokens_in / _PER_MILLION * price.usd_per_1m_in
        + tokens_out / _PER_MILLION * price.usd_per_1m_out
    )
