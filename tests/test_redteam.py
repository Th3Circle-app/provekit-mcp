"""Run the full red-team against the live server as part of the test suite, so
CI fails if any trust boundary regresses. This spawns the real MCP server over
stdio, exactly as `python -m redteam.run` does."""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_redteam_all_controls_hold():
    from redteam.run import main
    exit_code = asyncio.run(main())
    assert exit_code == 0, "red-team found a breach, regression, or inconclusive control"
