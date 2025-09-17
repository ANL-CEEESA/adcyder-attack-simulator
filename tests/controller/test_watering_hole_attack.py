"""
test_watering_hole_attack.py: Unit tests for the WateringHoleAttack class.

This module provides comprehensive unit tests for the WateringHoleAttack class,
focusing on testing the attack logic while mocking network dependencies.

Key Features:
- Mock network components (SSH, Metasploit, HTTP server, sockets)
- Test attack flow and error handling
- Validate payload generation and serving
- Test cleanup operations
- Preserve actual attack logic while preventing real network calls

Test Coverage:
- HTTP server setup and teardown
- Payload generation and serving
- SSH connection and command execution
- Metasploit listener setup and session handling
- Error handling and cleanup operations

Use Cases:
- Validate attack simulation logic without external dependencies
- Test error handling and recovery mechanisms
- Ensure proper resource cleanup
- Verify attack flow and state management
- Support continuous integration testing
"""
import pytest
from unittest.mock import patch, MagicMock, mock_open, call
from pymetasploit3.msfrpc import MsfRpcClient, MeterpreterSession

from controller.WateringHoleAttack import WateringHoleAttack


@pytest.fixture
def mock_msf_client() -> MagicMock:
    """Create a mock MsfRpcClient with proper structure."""
    mock_client = MagicMock(spec=MsfRpcClient)
    mock_client.modules.use.return_value = MagicMock()
    mock_client.sessions.list = {}
    mock_client.sessions.session.return_value = MagicMock(spec=MeterpreterSession)
    return mock_client


@pytest.fixture
def attack_instance(mock_msf_client: MagicMock) -> WateringHoleAttack:
    """Fixture to create a WateringHoleAttack instance for testing."""
    with patch('controller.WateringHoleAttack.Attack.setUpClass'), \
         patch('controller.WateringHoleAttack.Attack.tearDownClass'):
        attack = WateringHoleAttack(is_helper=True)
        attack.msf_client = mock_msf_client
        attack.target_ip = "192.168.1.100"
        attack.target_port = 80
        return attack


@pytest.mark.unit
@patch('controller.WateringHoleAttack.socketserver.TCPServer')
@patch('controller.WateringHoleAttack.socket.create_connection')
@patch('controller.WateringHoleAttack.Thread')
@patch('controller.WateringHoleAttack.time.sleep')
def test_start_http_server_success(mock_sleep, mock_thread, mock_socket_conn, mock_tcp_server, attack_instance):
    """Test successful HTTP server startup."""
    # Setup mocks
    mock_server = MagicMock()
    mock_tcp_server.return_value = mock_server
    mock_thread_instance = MagicMock()
    mock_thread.return_value = mock_thread_instance
    
    # Mock successful socket connection (server is running)
    mock_socket_conn.return_value.__enter__.return_value = MagicMock()
    
    # Test
    attack_instance.start_http_server("/tmp/test")
    
    # Verify
    mock_tcp_server.assert_called_once()
    mock_server.allow_reuse_address = True
    mock_thread_instance.start.assert_called_once()
    assert attack_instance.httpd == mock_server


@pytest.mark.unit
@patch('controller.WateringHoleAttack.socketserver.TCPServer')
@patch('controller.WateringHoleAttack.socket.create_connection')
@patch('controller.WateringHoleAttack.Thread')
@patch('controller.WateringHoleAttack.time.sleep')
def test_start_http_server_failure(mock_sleep, mock_thread, mock_socket_conn, mock_tcp_server, attack_instance):
    """Test HTTP server startup failure."""
    # Setup mocks
    mock_server = MagicMock()
    mock_tcp_server.return_value = mock_server
    mock_thread_instance = MagicMock()
    mock_thread.return_value = mock_thread_instance
    
    # Mock socket connection failure (server not running)
    mock_socket_conn.side_effect = Exception("Connection failed")
    
    # Test
    with pytest.raises(Exception, match=r"Failed to start HTTP server"):
        attack_instance.start_http_server("/tmp/test")
    
    # Verify cleanup was attempted
    mock_server.shutdown.assert_called_once()
    mock_server.server_close.assert_called_once()


@pytest.mark.unit
def test_generate_reverse_shell_payload(attack_instance, mock_msf_client):
    """Test reverse shell payload generation."""
    # Setup mock payload
    mock_payload = MagicMock()
    mock_payload.runoptions = {}
    mock_payload.payload_generate.return_value = b"fake_payload_data"
    mock_msf_client.modules.use.return_value = mock_payload
    
    # Test
    result = attack_instance.generate_reverse_shell_payload("linux/x64")
    
    # Verify
    mock_msf_client.modules.use.assert_called_with("payload", "linux/x64/meterpreter/reverse_tcp")
    assert mock_payload.runoptions["LHOST"] is not None
    assert mock_payload.runoptions["LPORT"] == 4444
    assert mock_payload.runoptions["Format"] == "elf"
    assert result == b"fake_payload_data"


@pytest.mark.unit
def test_serve_payload(attack_instance):
    """Test payload serving functionality."""
    test_payload = b"test_payload_data"
    test_dir = "/tmp/test"
    
    with patch("builtins.open", mock_open()) as mock_file:
        attack_instance.serve_payload(test_dir, test_payload)
        
        mock_file.assert_called_once_with(f"{test_dir}/malware", "wb")
        mock_file().write.assert_called_once_with(test_payload)


@pytest.mark.unit
def test_serve_payload_io_error(attack_instance):
    """Test payload serving with IO error."""
    test_payload = b"test_payload_data"
    test_dir = "/tmp/test"
    
    with patch("builtins.open", side_effect=IOError("Permission denied")):
        with pytest.raises(Exception, match="Failed to write payload"):
            attack_instance.serve_payload(test_dir, test_payload)


@pytest.mark.unit
def test_cleanup_target_processes(attack_instance):
    """Test target process cleanup functionality."""
    # Setup mock SSH client
    mock_ssh_client = MagicMock()
    attack_instance.ssh_client = mock_ssh_client
    
    # Mock the send_ssh_command_with_random_delays method
    with patch.object(attack_instance, 'send_ssh_command_with_random_delays') as mock_send_cmd:
        attack_instance.cleanup_target_processes()
        
        # Verify cleanup commands were sent
        expected_commands = [
            "pkill -f 'malware$' 2>/dev/null || true",
            "pkill -f malware_launcher 2>/dev/null || true",
            "rm -f /tmp/malware /tmp/malware_launcher.sh /tmp/malware.lock /tmp/malware.pid /tmp/malware.log 2>/dev/null || true",
        ]
        
        assert mock_send_cmd.call_count == len(expected_commands)
        for i, expected_cmd in enumerate(expected_commands):
            mock_send_cmd.assert_any_call(expected_cmd)


@pytest.mark.unit
@patch('controller.WateringHoleAttack.tempfile.mkdtemp')
@patch('controller.WateringHoleAttack.time.sleep')
def test_establish_reverse_shell_missing_msf_client(mock_sleep, mock_mkdtemp, attack_instance):
    """Test establish_reverse_shell with missing msf_client."""
    attack_instance.msf_client = None
    
    with pytest.raises(RuntimeError, match="msf_client not initialized"):
        attack_instance.establish_reverse_shell()


@pytest.mark.unit
@patch('controller.WateringHoleAttack.tempfile.mkdtemp')
@patch('controller.WateringHoleAttack.time.sleep')
@patch('controller.WateringHoleAttack.socket.create_connection')
@patch('controller.WateringHoleAttack.socketserver.TCPServer')
@patch('controller.WateringHoleAttack.Thread')
@patch('paramiko.SSHClient')
def test_establish_reverse_shell_ssh_failure(
    mock_ssh_client_class, mock_thread, mock_tcp_server, mock_socket_conn, 
    mock_sleep, mock_mkdtemp, attack_instance, mock_msf_client
):
    """Test establish_reverse_shell with SSH connection failure."""
    # Setup mocks
    mock_mkdtemp.return_value = "/tmp/test"
    mock_server = MagicMock()
    mock_tcp_server.return_value = mock_server
    mock_socket_conn.return_value.__enter__.return_value = MagicMock()
    
    # Mock payload generation
    mock_payload = MagicMock()
    mock_payload.runoptions = {}
    mock_payload.payload_generate.return_value = b"fake_payload"
    mock_msf_client.modules.use.return_value = mock_payload
    mock_msf_client.sessions.list = {}
    
    # Mock SSH client failure
    mock_ssh_client = MagicMock()
    mock_ssh_client_class.return_value = mock_ssh_client
    mock_ssh_client.connect.side_effect = Exception("SSH connection failed")
    
    # Mock settings
    with patch('controller.WateringHoleAttack.TARGET_IP', '192.168.1.100'), \
         patch('controller.WateringHoleAttack.TARGET_SSH_USER', 'testuser'), \
         patch('controller.WateringHoleAttack.TARGET_SSH_PASSWORD', 'testpass'), \
         patch('controller.WateringHoleAttack.TARGET_SSH_USER_KEYFILE', None), \
         patch('controller.WateringHoleAttack.TARGET_PLATFORM', 'linux/x64'), \
         patch('controller.WateringHoleAttack.MY_IP_ADDRESS', '10.0.0.1'), \
         patch.object(attack_instance, 'start_listener', return_value=[]), \
         patch("builtins.open", mock_open()):
        
        with pytest.raises(Exception, match="SSH connection failed"):
            attack_instance.establish_reverse_shell()


@pytest.mark.unit
def test_teardown_class_cleanup(attack_instance):
    """Test tearDownClass cleanup functionality."""
    # Setup mock objects
    mock_httpd = MagicMock()
    mock_temp_dir = "/tmp/test_dir"
    
    WateringHoleAttack.httpd = mock_httpd
    WateringHoleAttack.temp_dir = mock_temp_dir
    
    with patch('controller.WateringHoleAttack.shutil.rmtree') as mock_rmtree, \
         patch('controller.WateringHoleAttack.Attack.tearDownClass') as mock_super_teardown:
        
        WateringHoleAttack.tearDownClass()
        
        # Verify cleanup
        mock_httpd.shutdown.assert_called_once()
        mock_httpd.server_close.assert_called_once()
        mock_rmtree.assert_called_once_with(mock_temp_dir)
        mock_super_teardown.assert_called_once()


@pytest.mark.unit
@patch('controller.WateringHoleAttack.logging.error')
def test_teardown_class_cleanup_error(mock_log_error, attack_instance):
    """Test tearDownClass cleanup with error handling."""
    # Setup mock objects
    mock_httpd = MagicMock()
    mock_temp_dir = "/tmp/test_dir"
    
    WateringHoleAttack.httpd = mock_httpd
    WateringHoleAttack.temp_dir = mock_temp_dir
    
    with patch('controller.WateringHoleAttack.shutil.rmtree', side_effect=Exception("Cleanup error")) as mock_rmtree, \
         patch('controller.WateringHoleAttack.Attack.tearDownClass') as mock_super_teardown:
        
        WateringHoleAttack.tearDownClass()
        
        # Verify error was logged
        mock_log_error.assert_called_once()
        mock_super_teardown.assert_called_once()


@pytest.mark.unit
def test_set_msf_client(attack_instance):
    """Test setting MSF client when using as helper class."""
    new_client = MagicMock(spec=MsfRpcClient)
    attack_instance.set_msf_client(new_client)
    assert attack_instance.msf_client == new_client


@pytest.mark.unit
@patch.dict('os.environ', {'MSFRPCD_PATH': '/usr/bin/msfrpcd'})
def test_run_watering_hole_phishing(attack_instance):
    """Test the main test method calls establish_reverse_shell."""
    with patch.object(attack_instance, 'establish_reverse_shell') as mock_establish:
        attack_instance.run_watering_hole_phishing()
        mock_establish.assert_called_once()
