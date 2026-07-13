"""Model adapters — neutral, config-driven ``provider:model`` dispatch.

Every adapter translates the shared :class:`~leakgauge.types.ToolSpec` list into
its provider's tool format and returns a :class:`~leakgauge.types.Response` with
normalised ``tool_calls`` of the form ``{"id", "name", "args"}``.

The ``stub`` provider needs no API key and runs fully offline, so the whole
skeleton (and CI) works with zero credentials.
"""

from __future__ import annotations

from leakgauge.types import ModelAdapter

__all__ = ["get_adapter"]


def get_adapter(model_id: str) -> ModelAdapter:
    """Return the adapter for a ``provider:model`` id, e.g. ``anthropic:foo``.

    The ``stub`` provider returns a no-op echo adapter (no scripted tool calls);
    callers that need deterministic scripted behaviour construct
    :class:`~leakgauge.adapters.stub.StubAdapter` directly.
    """
    provider, _, model = model_id.partition(":")
    if not model:
        raise ValueError(f"model id must be 'provider:model', got {model_id!r}")

    if provider == "stub":
        from leakgauge.adapters.stub import StubAdapter

        return StubAdapter(scripted=[])
    if provider == "anthropic":
        from leakgauge.adapters.anthropic import AnthropicAdapter

        return AnthropicAdapter(model=model)
    if provider == "openai":
        from leakgauge.adapters.openai import OpenAIAdapter

        return OpenAIAdapter(model=model)
    if provider == "vllm":
        # OpenAI-compatible local endpoint; base_url comes from the environment.
        from leakgauge.adapters.vllm import VLLMAdapter

        return VLLMAdapter(model=model)

    raise ValueError(f"unknown provider {provider!r} in model id {model_id!r}")
