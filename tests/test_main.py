import sys
import pytest
from unittest.mock import patch
from auditor.__main__ import main

@pytest.mark.asyncio
async def test_main_exits_nonzero_on_exception():
    with patch("sys.argv", ["auditor", "--mode", "code", "--providers", "openai"]):
        with patch("auditor.__main__.get_github_token", side_effect=ValueError("Token required")):
            with patch("sys.exit") as mock_exit:
                await main()
                mock_exit.assert_called_once_with(1)
