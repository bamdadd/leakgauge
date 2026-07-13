"""OpenAI Chat Completions adapter (also the base for the vLLM adapter).

Not exercised in offline CI — it needs a live endpoint and an API key. The
skeleton is proven end to end by the stub adapter; this is the thin translation
layer for real runs.
"""

from __future__ import annotations

import json
import os
from typing import Any

from leakgauge.types import Message, Response, ToolSpec


def _tool_to_openai(spec: ToolSpec) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": spec.parameters,
        },
    }


def _message_to_openai(message: Message) -> dict[str, Any]:
    payload: dict[str, Any] = {"role": message.role, "content": message.content}
    if message.tool_calls is not None:
        payload["tool_calls"] = [
            {
                "id": call["id"],
                "type": "function",
                "function": {"name": call["name"], "arguments": json.dumps(call["args"])},
            }
            for call in message.tool_calls
        ]
    if message.tool_call_id is not None:
        payload["tool_call_id"] = message.tool_call_id
    return payload


class OpenAIAdapter:
    """Translate the neutral interface to/from the OpenAI SDK."""

    def __init__(self, model: str, *, base_url: str | None = None) -> None:
        from openai import OpenAI

        self.model = model
        self._client = OpenAI(base_url=base_url) if base_url else OpenAI()

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> Response:
        completion = self._client.chat.completions.create(
            model=self.model,
            messages=[_message_to_openai(m) for m in messages],
            tools=[_tool_to_openai(t) for t in tools] or None,
        )
        choice = completion.choices[0].message
        tool_calls: list[dict[str, Any]] = []
        for call in choice.tool_calls or []:
            tool_calls.append(
                {
                    "id": call.id,
                    "name": call.function.name,
                    "args": json.loads(call.function.arguments or "{}"),
                }
            )
        return Response(text=choice.content or "", tool_calls=tool_calls)


def _base_url_from_env(var: str) -> str | None:
    return os.environ.get(var)
