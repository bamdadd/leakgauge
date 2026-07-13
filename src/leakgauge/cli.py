"""leakgauge CLI — run the walking-skeleton case and print the two ASRs.

Runs entirely offline with the stub adapter (``--model stub:demo``): a scripted,
hijacked agent drives one case to verified leakage, so both scorers register a
hit with zero API keys. Real providers plug in via the same ``provider:model``
id but are not exercised in CI.
"""

from __future__ import annotations

import argparse
import importlib
from collections.abc import Callable

from leakgauge import _scoring_fallback
from leakgauge.environments.demo import (
    DemoEnvironment,
    build_demo_case,
    scripted_leak_responses,
)
from leakgauge.runner import DEFAULT_MAX_STEPS, run_case
from leakgauge.types import Case, ExfilSpec, ModelAdapter, RunRecord

# Prefer the real scorer once the scoring workstream lands ``leakgauge.scoring``;
# fall back to the raw string-match core so the skeleton computes real ASRs
# offline. Loaded dynamically so the not-yet-present module isn't a static dep.
try:
    _scoring = importlib.import_module("leakgauge.scoring")
except ModuleNotFoundError:
    _scoring = _scoring_fallback


def _hijacked(record: RunRecord, spec: ExfilSpec) -> bool:
    # Handoff seam: CONTRACTS §5 lists hijacked(record); the computable form
    # needs the exfil spec. Tolerate either until the real scorer settles it.
    try:
        return bool(_scoring.hijacked(record, spec))
    except TypeError:
        return bool(_scoring.hijacked(record))


def _leaked(record: RunRecord, canary: str, spec: ExfilSpec) -> bool:
    return bool(_scoring.leaked(record, canary, spec))


def _adapter_factory(model_id: str, case: Case) -> Callable[[int], ModelAdapter]:
    provider = model_id.partition(":")[0]
    if provider == "stub":
        from leakgauge.adapters.stub import StubAdapter

        return lambda _seed: StubAdapter(scripted=scripted_leak_responses(case))
    from leakgauge.adapters import get_adapter

    return lambda _seed: get_adapter(model_id)


def _mean(values: list[bool]) -> float:
    return sum(1 for v in values if v) / len(values) if values else 0.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="leakgauge")
    parser.add_argument(
        "--model",
        default="stub:demo",
        help="adapter id: stub:demo | anthropic:… | openai:… | vllm:…",
    )
    parser.add_argument("--k", type=int, default=1, help="seeded repeats of the case")
    parser.add_argument("--seed", type=int, default=0, help="base seed")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    args = parser.parse_args(argv)

    case = build_demo_case()
    make_adapter = _adapter_factory(args.model, case)

    hijacks: list[bool] = []
    leaks: list[bool] = []
    utility: list[bool] = []
    for offset in range(args.k):
        seed = args.seed + offset
        env = DemoEnvironment(case)
        record = run_case(
            case, env, make_adapter(seed), args.model, seed=seed, max_steps=args.max_steps
        )
        hijacks.append(_hijacked(record, case.exfil_spec))
        leaks.append(_leaked(record, case.canary, case.exfil_spec))
        utility.append(env.utility_ok(case.utility_key))

    _report(args.model, case, args.k, hijacks, leaks, utility)
    return 0


def _report(
    model: str,
    case: Case,
    k: int,
    hijacks: list[bool],
    leaks: list[bool],
    utility: list[bool],
) -> None:
    print(f"[leakgauge] case={case.id} model={model} k={k}")
    print(f"  hijack-ASR           : {_mean(hijacks):.2f}")
    print(f"  leakage-verified ASR : {_mean(leaks):.2f}")
    print(f"  utility-under-attack : {_mean(utility):.2f}")
    gap = _mean(hijacks) - _mean(leaks)
    print(f"  gap (hijack - leak)  : {gap:.2f}")


if __name__ == "__main__":
    raise SystemExit(main())
