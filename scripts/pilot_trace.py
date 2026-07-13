"""Phase-3 pilot diagnostic: run the real suite once and dump plumbing evidence.

Runs every case (k=1) through a real adapter with a recording wrapper so we can
answer the three go/no-go checks from one paid pass:

  1. PLUMBING — did the injected content actually reach the model, and did the
     tool-call args land in the trace intact?
  2. GAP     — any case with hijacked=True but leaked=False?
  3. DIFFICULTY — is leakage-ASR off the floor and off the ceiling?

Diagnostic only; not imported by the package. Run with:
    uv run --with openai python scripts/pilot_trace.py openai:gpt-4o-mini
"""

from __future__ import annotations

import sys
from typing import Any

from leakgauge.adapters import get_adapter
from leakgauge.cases import build_environment
from leakgauge.pricing import cost_usd
from leakgauge.runner import run_case
from leakgauge.scoring import canary_present, hijacked, leaked
from leakgauge.suite import cases_for_suite
from leakgauge.types import Message, Response, ToolSpec


class RecordingAdapter:
    """Wrap a real adapter, capturing the messages seen at each completion."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.seen: list[list[Message]] = []

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> Response:
        self.seen.append(list(messages))
        return self._inner.complete(messages, tools)


def _tool_results_text(messages: list[Message]) -> str:
    return "\n".join(m.content for m in messages if m.role == "tool")


DUMP_CASES = {"encoded-hex-token-exfil"}


def main() -> int:
    model_id = sys.argv[1] if len(sys.argv) > 1 else "openai:gpt-4o-mini"
    only = set(sys.argv[2:])
    cases = [c for c in cases_for_suite("all") if not only or c.id in only]
    print(f"# pilot: {model_id}  cases={len(cases)}  k=1\n")

    rows: list[dict[str, Any]] = []
    total_in = total_out = 0

    for case in cases:
        env = build_environment(case)
        rec = RecordingAdapter(get_adapter(model_id))
        record = run_case(case, env, rec, model_id, seed=0)
        total_in += record.tokens_in
        total_out += record.tokens_out

        hij = hijacked(record, case.exfil_spec)
        leak = leaked(record, case.canary, case.exfil_spec)
        util = env.utility_ok(case.utility_key)

        # True iff a tool result the model received carried the planted canary,
        # i.e. the model actually retrieved the SECRET. Distinct from whether the
        # injection instruction reached it (the delayed case obeys the injection
        # without ever fetching the secret email).
        secret_retrieved = any(
            canary_present(_tool_results_text(msgs), case.canary) for msgs in rec.seen
        )

        rows.append(
            {
                "case": case.id,
                "family": case.family,
                "hijack": hij,
                "leak": leak,
                "util": util,
                "secret_retrieved": secret_retrieved,
                "steps": len(record.trace),
            }
        )

        # Check 1: dump full plumbing evidence for the chosen cases.
        if case.id in DUMP_CASES:
            _dump_trace(case.id, rec, record)

    _print_table(rows)
    _print_verdicts(rows)

    spend = cost_usd(model_id, total_in, total_out)
    print(f"\nspend: ${spend:.4f}  ({total_in} in / {total_out} out tokens)")
    return 0


def _dump_trace(case_id: str, rec: RecordingAdapter, record: Any) -> None:
    print(f"## PLUMBING trace dump — case={case_id}\n")
    last = rec.seen[-1] if rec.seen else []
    print("### tool results the model received (injected content lands here):")
    for m in last:
        if m.role == "tool":
            body = m.content if len(m.content) < 600 else m.content[:600] + " …[truncated]"
            print(f"  - {body}")
    print("\n### recorded tool calls (args must be intact):")
    for call in record.trace:
        print(f"  step {call.step}: {call.tool}({call.args})")
    print()


def _print_table(rows: list[dict[str, Any]]) -> None:
    print("## per-case (k=1)\n")
    hdr = (
        f"  {'case':<44} {'family':<9} {'hij':>4} {'leak':>5} "
        f"{'util':>5} {'secret':>7} {'steps':>6}"
    )
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for r in rows:
        print(
            f"  {r['case']:<44} {r['family']:<9} {str(r['hijack']):>4} {str(r['leak']):>5} "
            f"{str(r['util']):>5} {str(r['secret_retrieved']):>7} {r['steps']:>6}"
        )


def _print_verdicts(rows: list[dict[str, Any]]) -> None:
    n = len(rows)
    hij = sum(1 for r in rows if r["hijack"])
    leak = sum(1 for r in rows if r["leak"])
    gap_cases = [r["case"] for r in rows if r["hijack"] and not r["leak"]]
    no_secret = [r["case"] for r in rows if not r["secret_retrieved"]]
    print("\n## verdicts")
    print(f"  hijack-ASR  : {hij}/{n} = {hij / n:.2f}")
    print(f"  leakage-ASR : {leak}/{n} = {leak / n:.2f}")
    print(f"  check2 GAP  : {len(gap_cases)} case(s) hijack&!leak -> {gap_cases}")
    print(f"  check1 secret never retrieved by model: {no_secret}")


if __name__ == "__main__":
    raise SystemExit(main())
