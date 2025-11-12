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
    # Patch setUpClass to prevent msfrpcd startup during test collection and execution
    # We only patch setUpClass because that's where msfrpcd is started
    with patch('controller.Attack.Attack.setUpClass'):
        yield


def pytest_collection_modifyitems(config, items):
    """
    Modify test collection to mark integration tests.

    This hook marks test methods found in source code classes (unittest-style tests)
    as integration tests, so they can be skipped when running unit tests only.
    """
    for item in items:
        # Mark unittest-style test methods from source code classes as integration tests
        if (
            hasattr(item, 'cls') and
            item.cls is not None and
            item.cls.__module__.startswith('controller.') and
            not item.get_closest_marker('unit')
        ):
            item.add_marker(pytest.mark.integration)
