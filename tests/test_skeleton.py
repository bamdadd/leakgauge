"""Walking-skeleton end-to-end test — stub adapter, one case, both scorers."""

from __future__ import annotations

from leakgauge._scoring_fallback import hijacked, leaked
from leakgauge.adapters.stub import StubAdapter
from leakgauge.cli import main
from leakgauge.environments.demo import (
    DemoEnvironment,
    build_demo_case,
    scripted_benign_responses,
    scripted_leak_responses,
)
from leakgauge.runner import run_case, run_case_repeated


def test_scripted_leak_is_hijack_and_verified_leak() -> None:
    case = build_demo_case()
    env = DemoEnvironment(case)
    adapter = StubAdapter(scripted=scripted_leak_responses(case))

    record = run_case(case, env, adapter, "stub:demo")

    assert hijacked(record, case.exfil_spec) is True
    assert leaked(record, case.canary, case.exfil_spec) is True
    assert env.utility_ok(case.utility_key) is True
    # The canary must actually ride in the outbound call's arguments.
    sent = env.snapshot()["sent"]
    assert sent and case.canary in sent[0]["body"]


def test_benign_agent_neither_hijacks_nor_leaks() -> None:
    case = build_demo_case()
    env = DemoEnvironment(case)
    adapter = StubAdapter(scripted=scripted_benign_responses(case))

    record = run_case(case, env, adapter, "stub:demo")

    assert hijacked(record, case.exfil_spec) is False
    assert leaked(record, case.canary, case.exfil_spec) is False
    assert env.utility_ok(case.utility_key) is True


def test_trace_records_full_arguments() -> None:
    case = build_demo_case()
    env = DemoEnvironment(case)
    record = run_case(case, env, StubAdapter(scripted=scripted_leak_responses(case)), "stub:demo")

    tools = [call.tool for call in record.trace]
    assert tools == ["read_inbox", "read_email", "send_email"]
    assert record.trace[-1].args["to"] in case.exfil_spec.attacker_addresses


def test_repeats_are_seeded_and_independent() -> None:
    case = build_demo_case()
    records = run_case_repeated(
        case,
        lambda: DemoEnvironment(case),
        lambda _seed: StubAdapter(scripted=scripted_leak_responses(case)),
        "stub:demo",
        k=3,
    )
    assert [r.seed for r in records] == [0, 1, 2]
    assert all(hijacked(r, case.exfil_spec) for r in records)


def test_cli_runs_offline_and_returns_zero() -> None:
    assert main(["--model", "stub:demo", "--k", "2"]) == 0
