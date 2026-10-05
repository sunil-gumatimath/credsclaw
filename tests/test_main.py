import inspect
from unittest.mock import patch

import pytest

from auditor.__main__ import main, run


@pytest.mark.asyncio
async def test_main_exits_nonzero_on_exception():
    with (
        patch("sys.argv", ["auditor", "--mode", "code", "--providers", "openai"]),
        patch("auditor.__main__.get_github_token", side_effect=ValueError("Token required")),
        patch("sys.exit") as mock_exit,
    ):
        await main()
        mock_exit.assert_called_once_with(1)


def test_console_entry_point_is_synchronous():
    """``[project.scripts]`` must target a sync callable.

    setuptools invokes ``sys.exit(target())``; pointing it at the coroutine
    function ``main`` produced ``<coroutine object main ...>`` and exit code 1
    without ever running a scan. ``run`` is the real console-script target.
    """
    assert not inspect.iscoroutinefunction(run)
    assert inspect.iscoroutinefunction(main)


def test_console_entry_point_executes_scan(tmp_path, monkeypatch):
    """``run()`` must actually drive a scan end to end."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_TOKEN", "fake-token")
    with patch(
        "sys.argv",
        ["credsclaw", "--mode", "local", "--dir", str(tmp_path), "--providers", "openai"],
    ):
        run()
    assert (tmp_path / "output" / "audit.log").exists()
