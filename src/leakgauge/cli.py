"""leakgauge CLI — run a suite of cases and print/emit the two ASRs.

Two entry forms:

- ``leakgauge --model stub:demo --suite all --k 3`` — run a suite offline, print
  a per-case table + aggregate CIs, and write ``results/<model>.json``.
- ``leakgauge report results/*.json`` — load several models' summaries and print
  the headline hijack-vs-leakage rank reorder (Kendall tau).

The stub adapter is the offline default: it scripts a hijacked agent per case so
both ASRs register with zero API keys. Real providers plug in via the same
``provider:model`` id but are not exercised in CI.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from leakgauge.runner import DEFAULT_MAX_STEPS
from leakgauge.suite import (
    DEFAULT_K,
    RESULTS_DIR,
    format_reorder_table,
    format_summary_table,
    load_summaries,
    rank_reorder,
    run_and_summarise,
    stub_script_for,
    suite_names,
    write_summary,
)
from leakgauge.types import Case, ModelAdapter

# Re-exported so callers/tests have one name for "the offline script for a case".
_stub_script = stub_script_for


def _adapter_factory(model_id: str) -> Callable[[Case, int], ModelAdapter]:
    provider = model_id.partition(":")[0]
    if provider == "stub":
        from leakgauge.adapters.stub import StubAdapter

        return lambda case, _seed: StubAdapter(scripted=stub_script_for(case))
    from leakgauge.adapters import get_adapter

    adapter = get_adapter(model_id)
    return lambda _case, _seed: adapter


def _run(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="leakgauge")
    parser.add_argument("--model", default="stub:demo", help="adapter id, e.g. stub:demo")
    parser.add_argument("--suite", default="all", choices=suite_names(), help="family or 'all'")
    parser.add_argument("--k", type=int, default=DEFAULT_K, help="seeded repeats per case")
    parser.add_argument("--seed", type=int, default=0, help="base seed")
    parser.add_argument("--max-steps", type=int, default=DEFAULT_MAX_STEPS)
    parser.add_argument(
        "--results-dir", default=str(RESULTS_DIR), help="where to write <model>.json"
    )
    args = parser.parse_args(argv)

    summary = run_and_summarise(
        args.suite,
        _adapter_factory(args.model),
        args.model,
        k=args.k,
        base_seed=args.seed,
        max_steps=args.max_steps,
    )
    path = write_summary(summary, Path(args.results_dir))
    print(format_summary_table(summary))
    print(f"\n  wrote {path}")
    return 0


def _report(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="leakgauge report")
    parser.add_argument("paths", nargs="+", help="summary json files (results/*.json)")
    args = parser.parse_args(argv)

    summaries = load_summaries(Path(p) for p in args.paths)
    print(format_reorder_table(summaries, rank_reorder(summaries)))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "report":
        return _report(args[1:])
    return _run(args)


if __name__ == "__main__":
    raise SystemExit(main())
