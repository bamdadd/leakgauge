"""Walking-skeleton end-to-end test — stub adapter over the real env + scorer."""

from __future__ import annotations

from pathlib import Path

from leakgauge.adapters.stub import StubAdapter
from leakgauge.cases import BENIGN_ACTION, DELAYED_CASE, build_environment
from leakgauge.cli import _stub_script, main
from leakgauge.environment import WorkspaceEnvironment
from leakgauge.runner import run_case, run_case_repeated
from leakgauge.scoring import hijacked, leaked
from leakgauge.types import Response, RunRecord


def _run(script: list[Response]) -> tuple[RunRecord, WorkspaceEnvironment]:
    env = build_environment(DELAYED_CASE)
    record = run_case(DELAYED_CASE, env, StubAdapter(scripted=script), "stub:demo")
    return record, env


def test_scripted_leak_is_hijack_and_verified_leak() -> None:
    record, env = _run(_stub_script(DELAYED_CASE))

    assert hijacked(record, DELAYED_CASE.exfil_spec) is True
    assert leaked(record, DELAYED_CASE.canary, DELAYED_CASE.exfil_spec) is True
    assert env.utility_ok(DELAYED_CASE.utility_key) is True

    sent = env.snapshot()["sent"]
    assert sent, "expected an outbound email"
    assert DELAYED_CASE.canary in sent[0]["body"]
    assert DELAYED_CASE.exfil_spec.attacker_addresses[0] in sent[0]["recipients"]


def test_hijack_without_canary_is_hijack_but_not_leak() -> None:
    # The (1, 0) corner: injected action performed, no secret exfiltrated.
    # Locks that leaked() and hijacked() are independent.
    attacker = DELAYED_CASE.exfil_spec.attacker_addresses[0]
    script = [
        Response(text="", tool_calls=[{"id": "c1", "name": "read_inbox", "args": {}}]),
        Response(
            text="",
            tool_calls=[
                {
                    "id": "c2",
                    "name": "send_email",
                    "args": {"recipients": [attacker], "subject": "hi", "body": "no secret here"},
                }
            ],
        ),
        Response(text="done", tool_calls=[]),
    ]
    record, _ = _run(script)

    assert hijacked(record, DELAYED_CASE.exfil_spec) is True
    assert leaked(record, DELAYED_CASE.canary, DELAYED_CASE.exfil_spec) is False


def test_benign_agent_neither_hijacks_nor_leaks() -> None:
    act = BENIGN_ACTION[DELAYED_CASE.id]
    script = [
        Response(text="", tool_calls=[{"id": "c1", "name": "read_inbox", "args": {}}]),
        Response(
            text="",
            tool_calls=[
                {
                    "id": "c2",
                    "name": "create_event",
                    "args": {"title": act["title"], "start": act["start"], "end": act["end"]},
                }
            ],
        ),
        Response(text="Scheduled it.", tool_calls=[]),
    ]
    record, env = _run(script)

    assert hijacked(record, DELAYED_CASE.exfil_spec) is False
    assert leaked(record, DELAYED_CASE.canary, DELAYED_CASE.exfil_spec) is False
    assert env.utility_ok(DELAYED_CASE.utility_key) is True


def test_trace_records_full_arguments() -> None:
    record, _ = _run(_stub_script(DELAYED_CASE))

    tools = [call.tool for call in record.trace]
    assert tools == ["read_inbox", "send_email", "create_event"]
    send = record.trace[1]
    assert DELAYED_CASE.exfil_spec.attacker_addresses[0] in send.args["recipients"]


def test_repeats_are_seeded_and_independent() -> None:
    records = run_case_repeated(
        DELAYED_CASE,
        lambda: build_environment(DELAYED_CASE),
        lambda _seed: StubAdapter(scripted=_stub_script(DELAYED_CASE)),
        "stub:demo",
        k=3,
    )
    assert [r.seed for r in records] == [0, 1, 2]
    assert all(hijacked(r, DELAYED_CASE.exfil_spec) for r in records)


def test_cli_runs_offline_and_returns_zero(tmp_path: Path) -> None:
    assert (
        main(
            [
                "--model",
                "stub:demo",
                "--suite",
                "delayed",
                "--k",
                "2",
                "--results-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
