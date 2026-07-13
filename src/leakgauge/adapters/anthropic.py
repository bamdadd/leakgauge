"""Anthropic Messages adapter.

Not exercised in offline CI — needs a live endpoint and an API key. Thin
translation only: ToolSpec -> Anthropic tool blocks, and tool_use content back
into the neutral ``{"id", "name", "args"}`` shape.
"""

from __future__ import annotations

from typing import Any

from leakgauge.types import Message, Response, ToolSpec

_MAX_TOKENS = 1024


def _tool_to_anthropic(spec: ToolSpec) -> dict[str, Any]:
    return {
        "name": spec.name,
        "description": spec.description,
        "input_schema": spec.parameters,
    }


def _message_to_anthropic(message: Message) -> dict[str, Any] | None:
    # Anthropic carries the system prompt out of band, not as a turn.
    if message.role == "system":
        return None
    if message.role == "tool":
        return {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": message.tool_call_id,
                    "content": message.content,
                }
            ],
        }
    if message.tool_calls:
        content: list[dict[str, Any]] = []
        if message.content:
            content.append({"type": "text", "text": message.content})
        for call in message.tool_calls:
            content.append(
                {
                    "type": "tool_use",
                    "id": call["id"],
                    "name": call["name"],
                    "input": call["args"],
                }
            )
        return {"role": "assistant", "content": content}
    return {"role": message.role, "content": message.content}


class AnthropicAdapter:
    def __init__(self, model: str) -> None:
        from anthropic import Anthropic

        self.model = model
        self._client = Anthropic()

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> Response:
        system = "\n".join(m.content for m in messages if m.role == "system")
        turns = [t for t in (_message_to_anthropic(m) for m in messages) if t is not None]
        message = self._client.messages.create(
            model=self.model,
            max_tokens=_MAX_TOKENS,
            system=system or None,
            messages=turns,
            tools=[_tool_to_anthropic(t) for t in tools] or None,
        )
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for block in message.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append({"id": block.id, "name": block.name, "args": dict(block.input)})
        return Response(text="".join(text_parts), tool_calls=tool_calls)
