"""--help should mention the 'report' subcommand.

'report' is handled as a special case in main() before the argparse parser
in _run() ever sees it, so the top-level --help output didn't used to
mention it at all, even though it's a real, working subcommand (see cli.py's
module docstring). This pins that --help now surfaces it.
"""

from __future__ import annotations

import pytest

from leakgauge.cli import main


def test_help_mentions_report_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0

    out = capsys.readouterr().out
    assert "report" in out
    assert "results/" in out
