import pytest
from unittest.mock import patch

from controller.Attack import Attack, wait_for_port


@patch('socket.create_connection')
def test_wait_for_port_success(mock_create_connection) -> None:
    """Test that wait_for_port returns True when the port is open."""
    host = "localhost"
    port = 1234
    assert wait_for_port(host, port, timeout=1)
    mock_create_connection.assert_called_with((host, port), timeout=2)


@patch('socket.create_connection', side_effect=OSError)
@patch('time.sleep', return_value=None)
def test_wait_for_port_timeout(mock_sleep, mock_create_connection) -> None:
    """Test that wait_for_port returns False when the port is never open."""
    host = "localhost"
    port = 1234
    assert not wait_for_port(host, port, timeout=0.1)


@pytest.mark.parametrize(
    "platform, expected_path",
    [
        ("linux/x64", "linux/x64/meterpreter/reverse_tcp"),
        ("linux/x86", "linux/x86/meterpreter/reverse_tcp"),
        ("linux/arm64", "linux/aarch64/meterpreter/reverse_tcp"),
        ("linux/aarch64", "linux/aarch64/meterpreter/reverse_tcp"),
        ("linux/armle", "linux/armle/meterpreter/reverse_tcp"),
        ("linux", "linux/x64/meterpreter/reverse_tcp"),
        ("windows/x64", "windows/x64/meterpreter/reverse_tcp"),
        ("windows/x86", "windows/meterpreter/reverse_tcp"),
        ("windows", "windows/x64/meterpreter/reverse_tcp"),
    ],
)
def test_get_payload_module_path_supported(platform, expected_path) -> None:
    """Test get_payload_module_path for various supported platforms."""
    attack = Attack()
    assert attack.get_payload_module_path(platform) == expected_path


@pytest.mark.parametrize(
    "platform",
    [
        ("linux/unsupported_arch"),
        ("unsupported_os/x64"),
    ],
)
def test_get_payload_module_path_unsupported(platform) -> None:
    """Test get_payload_module_path raises ValueError for unsupported platforms."""
    attack = Attack()
    with pytest.raises(ValueError):
        attack.get_payload_module_path(platform)
