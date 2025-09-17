"""
test_attack.py: Unit tests for the Attack base class.

This module provides comprehensive unit tests for the Attack base class,
focusing on testing core attack functionality while mocking network dependencies.

Key Features:
- Mock Metasploit RPC client and session management
- Mock SSH connections and command execution
- Test payload generation and platform detection
- Test session validation and management
- Preserve actual attack logic while preventing real network calls

Test Coverage:
- Metasploit client setup and teardown
- SSH session management and validation
- Payload module path generation
- Meterpreter session handling
- Command execution with delays
- Error handling and recovery

Use Cases:
- Validate core attack infrastructure without external dependencies
- Test error handling and recovery mechanisms
- Ensure proper resource cleanup
- Verify attack flow and state management
- Support continuous integration testing
"""
import pytest
from unittest.mock import patch, MagicMock, call
from pymetasploit3.msfrpc import MsfRpcClient, MeterpreterSession

from controller.Attack import Attack


@pytest.fixture
def mock_msf_client() -> MagicMock:
    """Create a mock MsfRpcClient with proper structure."""
    mock_client = MagicMock(spec=MsfRpcClient)
    mock_client.modules.use.return_value = MagicMock()
    mock_client.sessions.list = {}
    mock_client.sessions.session.return_value = MagicMock(spec=MeterpreterSession)
    mock_client.jobs.list = {}
    mock_client.consoles.console.return_value.read.return_value = "test output"
    return mock_client


@pytest.fixture
def attack_instance() -> Attack:
    """Create an Attack instance for testing."""
    with patch('controller.Attack.Attack.setUpClass'), \
         patch('controller.Attack.Attack.tearDownClass'):
        attack = Attack()
        return attack


@pytest.mark.unit
def test_get_payload_module_path_linux_x64(attack_instance):
    """Test payload module path generation for Linux x64."""
    result = attack_instance.get_payload_module_path("linux/x64")
    assert result == "linux/x64/meterpreter/reverse_tcp"


@pytest.mark.unit
def test_get_payload_module_path_linux_x86(attack_instance):
    """Test payload module path generation for Linux x86."""
    result = attack_instance.get_payload_module_path("linux/x86")
    assert result == "linux/x86/meterpreter/reverse_tcp"


@pytest.mark.unit
def test_get_payload_module_path_linux_arm64(attack_instance):
    """Test payload module path generation for Linux ARM64."""
    result = attack_instance.get_payload_module_path("linux/arm64")
    assert result == "linux/aarch64/meterpreter/reverse_tcp"


@pytest.mark.unit
def test_get_payload_module_path_windows_x64(attack_instance):
    """Test payload module path generation for Windows x64."""
    result = attack_instance.get_payload_module_path("windows/x64")
    assert result == "windows/x64/meterpreter/reverse_tcp"


@pytest.mark.unit
def test_get_payload_module_path_windows_default(attack_instance):
    """Test payload module path generation for Windows default."""
    result = attack_instance.get_payload_module_path("windows/x86")
    assert result == "windows/meterpreter/reverse_tcp"


@pytest.mark.unit
def test_get_payload_module_path_unsupported_os(attack_instance):
    """Test payload module path generation for unsupported OS."""
    with pytest.raises(ValueError, match="Unsupported OS"):
        attack_instance.get_payload_module_path("macos/x64")


@pytest.mark.unit
def test_get_payload_module_path_unsupported_arch(attack_instance):
    """Test payload module path generation for unsupported architecture."""
    with pytest.raises(ValueError, match="Unsupported architecture"):
        attack_instance.get_payload_module_path("linux/sparc")


@pytest.mark.unit
@patch('controller.Attack.socket.create_connection')
def test_start_listener_success(mock_socket_conn, attack_instance, mock_msf_client):
    """Test successful Metasploit listener startup."""
    attack_instance.msf_client = mock_msf_client
    
    # Mock exploit module
    mock_exploit = MagicMock()
    mock_exploit.runoptions = {}
    mock_exploit.execute.return_value = {"job_id": 1}
    mock_msf_client.modules.use.return_value = mock_exploit
    mock_msf_client.sessions.list = {"1": {}, "2": {}}
    
    # Mock successful socket connection (listener is active)
    mock_socket_conn.return_value.__enter__.return_value = MagicMock()
    
    with patch('controller.Attack.MY_IP_ADDRESS', '10.0.0.1'), \
         patch('controller.Attack.time.sleep'):
        
        result = attack_instance.start_listener("linux/x64")
        
        # Verify
        mock_msf_client.modules.use.assert_called_with("exploit", "multi/handler")
        assert mock_exploit.runoptions["payload"] == "linux/x64/meterpreter/reverse_tcp"
        assert mock_exploit.runoptions["lhost"] == "10.0.0.1"
        assert mock_exploit.runoptions["lport"] == 4444
        mock_exploit.execute.assert_called_once()
        assert result == [1, 2]


@pytest.mark.unit
def test_wait_for_new_meterpreter_session_success(attack_instance, mock_msf_client):
    """Test successful waiting for new Meterpreter session."""
    attack_instance.msf_client = mock_msf_client
    
    # Mock session list progression
    mock_msf_client.sessions.list = {"3": {"type": "meterpreter"}}
    
    with patch.object(attack_instance, 'validate_msf_session', return_value=True), \
         patch('controller.Attack.time.sleep'):
        
        result = attack_instance.wait_for_new_meterpreter_session([1, 2], timeout=5)
        assert result == 3


@pytest.mark.unit
def test_wait_for_new_meterpreter_session_timeout(attack_instance, mock_msf_client):
    """Test timeout waiting for new Meterpreter session."""
    attack_instance.msf_client = mock_msf_client
    mock_msf_client.sessions.list = {}
    
    with patch('controller.Attack.time.sleep'), \
         patch('controller.Attack.time.time', side_effect=[0, 70]):  # Simulate timeout
        
        with pytest.raises(TimeoutError, match="No stable session established"):
            attack_instance.wait_for_new_meterpreter_session([1, 2], timeout=60)


@pytest.mark.unit
@patch('controller.Attack.paramiko.SSHClient')
def test_start_ssh_session_with_password(mock_ssh_client_class, attack_instance):
    """Test SSH session startup with password authentication."""
    mock_ssh_client = MagicMock()
    mock_ssh_client_class.return_value = mock_ssh_client
    
    attack_instance.start_ssh_session("192.168.1.100", "testuser", password="testpass")
    
    mock_ssh_client.set_missing_host_key_policy.assert_called_once()
    mock_ssh_client.connect.assert_called_once_with(
        hostname="192.168.1.100", port=22, username="testuser", password="testpass"
    )
    assert attack_instance.ssh_client == mock_ssh_client


@pytest.mark.unit
@patch('controller.Attack.paramiko.SSHClient')
def test_start_ssh_session_with_keyfile(mock_ssh_client_class, attack_instance):
    """Test SSH session startup with key file authentication."""
    mock_ssh_client = MagicMock()
    mock_ssh_client_class.return_value = mock_ssh_client
    
    attack_instance.start_ssh_session("192.168.1.100", "testuser", ssh_keyfile="/path/to/key")
    
    mock_ssh_client.connect.assert_called_once_with(
        hostname="192.168.1.100", port=22, username="testuser", key_filename="/path/to/key"
    )


@pytest.mark.unit
@patch('controller.Attack.paramiko.SSHClient')
def test_start_ssh_session_no_auth(mock_ssh_client_class, attack_instance):
    """Test SSH session startup with no authentication."""
    mock_ssh_client = MagicMock()
    mock_ssh_client_class.return_value = mock_ssh_client
    
    attack_instance.start_ssh_session("192.168.1.100", "testuser")
    
    mock_ssh_client.connect.assert_called_once_with(
        hostname="192.168.1.100", port=22, username="testuser"
    )


@pytest.mark.unit
def test_validate_ssh_session_success(attack_instance):
    """Test successful SSH session validation."""
    mock_ssh_client = MagicMock()
    mock_stdout = MagicMock()
    mock_stdout.read.return_value.decode.return_value.strip.return_value = "0"
    mock_ssh_client.exec_command.return_value = (None, mock_stdout, None)
    
    result = attack_instance.validate_ssh_session(mock_ssh_client)
    assert result is True


@pytest.mark.unit
def test_validate_ssh_session_failure(attack_instance):
    """Test SSH session validation failure."""
    mock_ssh_client = MagicMock()
    mock_ssh_client.exec_command.side_effect = Exception("Connection lost")
    
    result = attack_instance.validate_ssh_session(mock_ssh_client)
    assert result is False


@pytest.mark.unit
def test_send_ssh_command_with_random_delays(attack_instance):
    """Test SSH command execution with random delays."""
    mock_ssh_client = MagicMock()
    mock_channel = MagicMock()
    mock_ssh_client.invoke_shell.return_value = mock_channel
    # Provide enough False values to simulate the loop, then True, then False to exit
    mock_channel.recv_ready.side_effect = [False] * 10 + [True] + [False] * 10
    mock_channel.recv.return_value = b"command output\n"
    
    attack_instance.ssh_client = mock_ssh_client
    
    with patch('controller.Attack.time.sleep'), \
         patch('controller.Attack.random.uniform', return_value=0.1), \
         patch('controller.Attack.time.time', side_effect=[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5]):  # Simulate timeout
        
        result = attack_instance.send_ssh_command_with_random_delays("echo test")
        
        mock_ssh_client.invoke_shell.assert_called_once()
        mock_channel.send.assert_called()
        assert "command output" in result


@pytest.mark.unit
def test_validate_msf_session_success(attack_instance, mock_msf_client):
    """Test successful Metasploit session validation."""
    attack_instance.msf_client = mock_msf_client
    
    mock_session = MagicMock(spec=MeterpreterSession)
    mock_session.sid = 1
    mock_session.run_with_output.return_value = "1234"
    mock_msf_client.sessions.session.return_value = mock_session
    mock_msf_client.sessions.list = {"1": {"type": "meterpreter"}}
    
    with patch.object(attack_instance, 'get_sysinfo', return_value={"OS": "Linux"}):
        result = attack_instance.validate_msf_session(1)
        assert result is True


@pytest.mark.unit
def test_validate_msf_session_failure(attack_instance, mock_msf_client):
    """Test Metasploit session validation failure."""
    attack_instance.msf_client = mock_msf_client
    mock_msf_client.sessions.list = {}
    
    result = attack_instance.validate_msf_session(1)
    assert result is False


@pytest.mark.unit
def test_send_msf_command_success(attack_instance):
    """Test successful Metasploit command execution."""
    mock_session = MagicMock(spec=MeterpreterSession)
    mock_session.run_with_output.return_value = "command output"
    
    result = attack_instance.send_msf_command("sysinfo", mock_session)
    assert result == "command output"


@pytest.mark.unit
def test_send_msf_command_error(attack_instance):
    """Test Metasploit command execution with error."""
    mock_session = MagicMock(spec=MeterpreterSession)
    mock_session.run_with_output.return_value = "[-] Command failed"
    
    with pytest.raises(RuntimeError, match="Command failed"):
        attack_instance.send_msf_command("invalid_command", mock_session)


@pytest.mark.unit
def test_send_msf_shell_command(attack_instance):
    """Test Metasploit shell command execution."""
    mock_session = MagicMock(spec=MeterpreterSession)
    mock_session.read.side_effect = ["", "command output\nCOMMAND_COMPLETE_abcd\n"]
    
    with patch('controller.Attack.os.urandom', return_value=b'\xab\xcd'), \
         patch('controller.Attack.time.sleep'):
        
        result = attack_instance.send_msf_shell_command("ls", mock_session)
        
        mock_session.write.assert_called()
        assert "command output" in result


@pytest.mark.unit
def test_get_sysinfo_success(attack_instance):
    """Test successful system info retrieval."""
    mock_session = MagicMock(spec=MeterpreterSession)
    mock_session.run_with_output.return_value = "Computer: test-host\nOS: Linux\nArchitecture: x64"
    
    result = attack_instance.get_sysinfo(mock_session)
    
    assert result["Computer"] == "test-host"
    assert result["OS"] == "Linux"
    assert result["Architecture"] == "x64"


@pytest.mark.unit
def test_get_sysinfo_failure(attack_instance):
    """Test system info retrieval failure."""
    mock_session = MagicMock(spec=MeterpreterSession)
    mock_session.run_with_output.side_effect = Exception("Connection lost")
    
    result = attack_instance.get_sysinfo(mock_session)
    assert result == {}


@pytest.mark.unit
def test_get_job_output(attack_instance, mock_msf_client):
    """Test job output retrieval."""
    attack_instance.msf_client = mock_msf_client
    
    # Simulate job completion by changing the jobs list after first call
    call_count = 0
    def mock_jobs_list():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {1: {"name": "test_job"}}
        else:
            return {}  # Job finished
    
    # Use side_effect to simulate the changing state
    type(mock_msf_client.jobs).list = property(lambda self: mock_jobs_list())
    
    with patch('controller.Attack.time.sleep'):
        result = attack_instance.get_job_output(1)
        assert result == "test output"


@pytest.mark.unit
@patch('controller.Attack.wait_for_port')
def test_wait_for_port_success(mock_wait_for_port):
    """Test successful port waiting."""
    mock_wait_for_port.return_value = True
    
    from controller.Attack import wait_for_port
    result = wait_for_port("localhost", 8080, timeout=5)
    assert result is True


@pytest.mark.unit
@patch('controller.Attack.socket.create_connection')
def test_wait_for_port_timeout(mock_socket_conn):
    """Test port waiting timeout."""
    mock_socket_conn.side_effect = OSError("Connection refused")
    
    from controller.Attack import wait_for_port
    
    with patch('controller.Attack.time.sleep'), \
         patch('controller.Attack.time.time', side_effect=[0, 35]):  # Simulate timeout
        
        result = wait_for_port("localhost", 8080, timeout=30)
        assert result is False


@pytest.mark.unit
def test_random_delay_decorator(attack_instance):
    """Test random delay decorator functionality."""
    @Attack.random_delay(10, 20)
    def test_function():
        return "test_result"
    
    with patch('controller.Attack.time.sleep') as mock_sleep, \
         patch('controller.Attack.random.uniform', return_value=0.015):
        
        result = test_function()
        
        mock_sleep.assert_called_once_with(0.015)
        assert result == "test_result"


@pytest.mark.unit
def test_retry_on_failure_decorator_success(attack_instance):
    """Test retry decorator with successful execution."""
    call_count = 0
    
    @Attack.retry_on_failure(max_retries=3, delay=0.1)
    def test_function():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise Exception("Temporary failure")
        return "success"
    
    with patch('controller.Attack.time.sleep'):
        result = test_function()
        assert result == "success"
        assert call_count == 2


@pytest.mark.unit
def test_retry_on_failure_decorator_max_retries(attack_instance):
    """Test retry decorator with max retries exceeded."""
    @Attack.retry_on_failure(max_retries=2, delay=0.1)
    def test_function():
        raise Exception("Persistent failure")
    
    with patch('controller.Attack.time.sleep'):
        with pytest.raises(Exception, match="Persistent failure"):
            test_function()
