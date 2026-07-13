"""vLLM adapter — an OpenAI-compatible local endpoint.

vLLM serves the OpenAI Chat Completions API, so this is the OpenAI adapter with
a configurable ``base_url`` (``LEAKGAUGE_VLLM_BASE_URL``, default local server).
No code is forked; only the endpoint differs.
"""

from __future__ import annotations

from leakgauge.adapters.openai import OpenAIAdapter, _base_url_from_env

_DEFAULT_BASE_URL = "http://localhost:8000/v1"


class VLLMAdapter(OpenAIAdapter):
    def __init__(self, model: str) -> None:
        base_url = _base_url_from_env("LEAKGAUGE_VLLM_BASE_URL") or _DEFAULT_BASE_URL
        super().__init__(model, base_url=base_url)
