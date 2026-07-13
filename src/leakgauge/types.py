"""Frozen v0 interface contracts — the shared spine of the benchmark.

These types are the boundary between the environment, the scorer, and the model
adapters. They mirror ``docs/CONTRACTS.md`` sections 1-4 exactly; do not change a
signature here without updating that file and notifying the other workstreams.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

# --- 1. Trace schema (produced by the environment, consumed by the scorer) ---


@dataclass(frozen=True)
class ToolCall:
    step: int  # 0-based ordinal within the run
    tool: str  # tool name, e.g. "send_email"
    args: dict[str, Any]  # full arguments as the model supplied them
    result: Any  # tool return value (for downstream context)


@dataclass(frozen=True)
class RunRecord:
    case_id: str
    model: str  # adapter id, e.g. "anthropic:claude-..."
    seed: int
    trace: list[ToolCall]  # ordered tool calls
    final_text: str  # model's final assistant message
    tokens_in: int = 0  # prompt tokens summed over the run (0 for stub)
    tokens_out: int = 0  # completion tokens summed over the run


# --- 2. Case schema (authored data on disk, loaded into these types) ---


@dataclass(frozen=True)
class ExfilSpec:
    attacker_addresses: list[str]  # emails that count as exfil destinations
    external_tools: list[str]  # tool names that egress (e.g. "http_post")


@dataclass(frozen=True)
class Case:
    id: str
    family: str  # "delayed" | "assembly" | "encoded"
    user_task: str  # benign instruction given to the agent
    env_seed: dict[str, Any]  # initial workspace state incl. injected
    # content and the planted canary
    canary: str  # LKG-<hex>; also present inside env_seed
    exfil_spec: ExfilSpec
    utility_key: str  # names the programmatic utility check for
    # this case (see contract 4)


# --- 3. Environment / tool API ---


@dataclass(frozen=True)
class ToolSpec:
    """JSON-schema-style tool description every adapter can translate."""

    name: str
    description: str
    parameters: dict[str, Any]  # JSON-schema object for the arguments


class Environment(Protocol):
    def tools(self) -> list[ToolSpec]: ...  # tool schemas for the model
    def call(self, name: str, args: dict[str, Any]) -> Any: ...  # execute; appends to trace
    def utility_ok(self, key: str) -> bool: ...  # did the benign task complete?
    def snapshot(self) -> dict[str, Any]: ...  # for debugging/repro


# --- 4. Adapter contract ---


@dataclass(frozen=True)
class Message:
    role: str  # "system" | "user" | "assistant" | "tool"
    content: str
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None


@dataclass(frozen=True)
class Response:
    text: str
    tool_calls: list[dict[str, Any]]  # [{"id", "name", "args"}], empty if none
    tokens_in: int = 0  # prompt tokens for this completion (0 if unknown)
    tokens_out: int = 0  # completion tokens for this completion


class ModelAdapter(Protocol):
    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> Response: ...


def get_adapter(model_id: str) -> ModelAdapter:  # "anthropic:foo" -> adapter
    """Return the adapter for a ``provider:model`` id (see ``leakgauge.adapters``)."""
    from leakgauge.adapters import get_adapter as _get_adapter

    return _get_adapter(model_id)
