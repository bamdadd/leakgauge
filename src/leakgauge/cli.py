"""leakgauge — run the benchmark suite against a configured model adapter."""

from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="leakgauge")
    parser.add_argument("--model", required=True, help="adapter id, e.g. openai:… / vllm:…")
    parser.add_argument(
        "--suite", default="all", help="attack family: delayed|assembly|encoded|all"
    )
    args = parser.parse_args(argv)
    # TODO: run cases -> score ASR + Utility-under-Attack + leakage-verified ASR.
    # Success = actual verified leakage / tool call, never LLM-judged alone.
    print(f"[leakgauge] TODO run suite={args.suite} against {args.model}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
