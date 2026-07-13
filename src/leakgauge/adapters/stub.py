"""Deterministic stub adapter — scripts tool calls, needs no API key.

The stub ignores the messages and tool schemas and replays a caller-supplied
list of :class:`~leakgauge.types.Response` objects, one per ``complete`` call.
Once the script is exhausted it returns an empty response so the run loop halts.
This keeps the adapter decoupled from any case: the *script* carries the
behaviour, so the same stub can model a hijacked agent or a well-behaved one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from leakgauge.types import Message, Response, ToolSpec


@dataclass
class StubAdapter:
    """Replay ``scripted`` responses in order; empty response when exhausted."""

    scripted: list[Response]
    model: str = "stub"
    _cursor: int = field(default=0, init=False)

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> Response:
        if self._cursor < len(self.scripted):
            response = self.scripted[self._cursor]
            self._cursor += 1
            return response
        return Response(text="", tool_calls=[])
