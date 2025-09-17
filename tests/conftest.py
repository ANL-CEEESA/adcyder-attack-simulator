"""
conftest.py: Pytest configuration file.

This file adds the project's root directory to the system path, allowing
tests to import modules from the `src` directory.
"""
import os
import pytest
from unittest.mock import patch, MagicMock

# Set MSFRPCD_PATH for tests that require it (set at module level)
if not os.getenv("MSFRPCD_PATH"):
    os.environ["MSFRPCD_PATH"] = "/usr/bin/msfrpcd"

@pytest.fixture(scope="session", autouse=True)
def setup_environment():
    """Set up environment variables and mock Attack class methods for all tests."""
    # Mock the Attack class setUpClass and tearDownClass methods to prevent
    # actual msfrpcd startup when pytest discovers unittest methods in source code
    with patch('controller.Attack.Attack.setUpClass'), \
         patch('controller.Attack.Attack.tearDownClass'), \
         patch('controller.WateringHoleAttack.Attack.setUpClass'), \
         patch('controller.WateringHoleAttack.Attack.tearDownClass'):
        yield
