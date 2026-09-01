from unittest.mock import patch

import pytest

from auditor.__main__ import main


@pytest.mark.asyncio
async def test_main_exits_nonzero_on_exception():
    with (
        patch("sys.argv", ["auditor", "--mode", "code", "--providers", "openai"]),
        patch("auditor.__main__.get_github_token", side_effect=ValueError("Token required")),
        patch("sys.exit") as mock_exit,
    ):
        await main()
        mock_exit.assert_called_once_with(1)
