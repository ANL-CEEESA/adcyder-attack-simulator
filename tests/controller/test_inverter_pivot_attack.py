"""
test_inverter_pivot_attack.py: Unit tests for the InverterPivotAttack class.

This module provides comprehensive unit tests for the InverterPivotAttack class,
focusing on testing the attack logic while mocking network dependencies and SSH operations.

Key Features:
- Mock SSH connections to inverter and historian/AGX gateway
- Test pivot operations and iptables configuration
- Validate Modbus proxy deployment and management
- Test error handling and cleanup operations
- Preserve actual attack logic while preventing real network calls

Test Coverage:
- SSH pivot from inverter to historian/AGX gateway
- iptables redirection rule configuration and cleanup
- Modbus MITM proxy deployment and lifecycle management
- Error handling for connection failures and configuration issues
- Resource cleanup and teardown operations

Use Cases:
- Validate attack simulation logic without external dependencies
- Test error handling and recovery mechanisms
- Ensure proper resource cleanup and iptables rule removal
- Verify attack flow orchestration and state management
- Support continuous integration testing
"""
import pytest
from unittest.mock import patch, MagicMock, call
import paramiko

from controller.modbus.InverterPivotAttack import InverterPivotAttack
from controller.modbus.modbus_proxy import ModbusMITMProxy


@pytest.fixture
def mock_msf_client() -> MagicMock:
    """Create a mock MsfRpcClient with proper structure."""
    mock_client = MagicMock()
    mock_client.modules.use.return_value = MagicMock()
    mock_client.sessions.list = {}
    mock_client.sessions.session.return_value = MagicMock()
    return mock_client


@pytest.fixture
def attack_instance(mock_msf_client: MagicMock) -> InverterPivotAttack:
    """Fixture to create an InverterPivotAttack instance for testing."""
    with patch('controller.Attack.Attack.setUpClass'), \
         patch('controller.Attack.Attack.tearDownClass'):
        attack = InverterPivotAttack(is_helper=True)
        attack.msf_client = mock_msf_client
        return attack


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_IP_ADDRESS', '192.168.1.200')
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_SSH_USER', 'aggregator_user')
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_SSH_PASSWORD', 'aggregator_pass')
def test_pivot_to_aggregator_success(attack_instance):
    """Test successful pivot to aggregator/AGX gateway."""
    # Setup mocks
    mock_ssh_client = MagicMock(spec=paramiko.SSHClient)
    
    with patch.object(attack_instance, 'start_ssh_session') as mock_start_ssh, \
         patch.object(attack_instance, 'validate_ssh_session', return_value=True) as mock_validate:
        
        # Set up the ssh_client attribute that start_ssh_session would set
        attack_instance.ssh_client = mock_ssh_client
        
        # Test
        attack_instance.pivot_to_aggregator()
        
        # Verify
        mock_start_ssh.assert_called_once_with(
            '192.168.1.200',
            'aggregator_user', 
            'aggregator_pass',
            None
        )
        mock_validate.assert_called_once_with(mock_ssh_client)
        assert attack_instance.aggregator_ssh_client == mock_ssh_client


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_IP_ADDRESS', '')
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_SSH_USER', 'historian_user')
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_SSH_PASSWORD', 'historian_pass')
def test_pivot_to_aggregator_missing_ip(attack_instance):
    """Test pivot to historian with missing IP configuration."""
    with pytest.raises(ValueError, match="Aggregator connection parameters not configured"):
        attack_instance.pivot_to_aggregator()


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_IP_ADDRESS', '192.168.1.200')
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_SSH_USER', 'historian_user')
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_SSH_PASSWORD', '')
def test_pivot_to_aggregator_missing_password(attack_instance):
    """Test pivot to historian with missing password."""
    with pytest.raises(ValueError, match="Aggregator authentication credentials not configured"):
        attack_instance.pivot_to_aggregator()


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_IP_ADDRESS', '192.168.1.200')
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_SSH_USER', 'historian_user')
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_SSH_PASSWORD', 'historian_pass')
def test_pivot_to_aggregator_ssh_failure(attack_instance):
    """Test pivot to historian with SSH connection failure."""
    with patch.object(attack_instance, 'start_ssh_session', side_effect=Exception("SSH failed")):
        with pytest.raises(RuntimeError, match="Failed to pivot to aggregator: SSH failed"):
            attack_instance.pivot_to_aggregator()


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_IP_ADDRESS', '192.168.1.200')
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_SSH_USER', 'historian_user')
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_SSH_PASSWORD', 'historian_pass')
def test_pivot_to_aggregator_validation_failure(attack_instance):
    """Test pivot to historian with SSH validation failure."""
    mock_ssh_client = MagicMock(spec=paramiko.SSHClient)

    with patch.object(attack_instance, 'start_ssh_session') as mock_start_ssh, \
         patch.object(attack_instance, 'validate_ssh_session', return_value=False):

        attack_instance.ssh_client = mock_ssh_client

        with pytest.raises(RuntimeError, match="Failed to pivot to aggregator: Aggregator SSH session validation failed"):
            attack_instance.pivot_to_aggregator()


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.MODBUS_TARGET_PORT', 502)
@patch('controller.modbus.InverterPivotAttack.MODBUS_PROXY_PORT', 8502)
def test_setup_iptables_redirection_success(attack_instance):
    """Test successful iptables redirection setup."""
    # Setup mock SSH client
    mock_ssh_client = MagicMock(spec=paramiko.SSHClient)
    attack_instance.aggregator_ssh_client = mock_ssh_client

    # Mock _send_sudo_command to return appropriate output for validation
    def mock_send_sudo_side_effect(cmd: str) -> str:
        # For check commands, return output containing the port numbers
        if "grep" in cmd:
            return "tcp dpt:502 redir ports 8502"
        # For add commands, return empty string
        return ""

    with patch.object(attack_instance, '_send_sudo_command', side_effect=mock_send_sudo_side_effect) as mock_send_cmd:
        # Test
        attack_instance.setup_iptables_redirection()

        # Verify the method was called (exact calls depend on implementation)
        assert mock_send_cmd.called
        assert attack_instance.iptables_rules_applied is True


@pytest.mark.unit
def test_setup_iptables_redirection_no_ssh(attack_instance):
    """Test iptables redirection setup without SSH session."""
    attack_instance.aggregator_ssh_client = None
    
    with pytest.raises(RuntimeError, match="Aggregator SSH session not established"):
        attack_instance.setup_iptables_redirection()


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.MODBUS_TARGET_PORT', 502)
@patch('controller.modbus.InverterPivotAttack.MODBUS_PROXY_PORT', 8502)
def test_setup_iptables_redirection_command_failure(attack_instance):
    """Test iptables redirection setup with command failure."""
    mock_ssh_client = MagicMock(spec=paramiko.SSHClient)
    attack_instance.aggregator_ssh_client = mock_ssh_client
    
    with patch.object(attack_instance, '_send_sudo_command', side_effect=Exception("Command failed")):
        with pytest.raises(RuntimeError, match="Failed to configure iptables redirection: Command failed"):
            attack_instance.setup_iptables_redirection()


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.MODBUS_PROXY_PORT', 8502)
@patch('controller.modbus.InverterPivotAttack.MODBUS_TARGET_PORT', 502)
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_IP_ADDRESS', '192.168.1.200')
@patch('controller.modbus.InverterPivotAttack.time.sleep')
def test_deploy_modbus_proxy_success(mock_sleep, attack_instance):
    """Test successful Modbus proxy deployment."""
    # Setup mock SSH client
    mock_ssh_client = MagicMock(spec=paramiko.SSHClient)
    attack_instance.aggregator_ssh_client = mock_ssh_client

    # Mock the ModbusMITMProxy
    mock_proxy = MagicMock(spec=ModbusMITMProxy)
    mock_proxy.is_running = True
    mock_proxy.initial_period = 60
    mock_proxy.transition_duration = 30
    mock_proxy.get_status.return_value = {'listen_port': 8502}

    with patch('controller.modbus.InverterPivotAttack.ModbusMITMProxy', return_value=mock_proxy) as mock_proxy_class, \
         patch('controller.modbus.InverterPivotAttack.threading.Thread') as mock_thread_class:

        mock_thread = MagicMock()
        mock_thread_class.return_value = mock_thread

        # Test
        attack_instance.deploy_modbus_proxy()

        # Verify proxy creation
        mock_proxy_class.assert_called_once_with(
            listen_port=8502,
            target_host='192.168.1.200',
            target_port=502
        )

        # Verify thread creation and start
        mock_thread_class.assert_called_once()
        mock_thread.start.assert_called_once()

        # Verify proxy assignment
        assert attack_instance.modbus_proxy == mock_proxy
        assert attack_instance.proxy_thread == mock_thread


@pytest.mark.unit
def test_deploy_modbus_proxy_no_ssh(attack_instance):
    """Test Modbus proxy deployment without SSH session."""
    attack_instance.aggregator_ssh_client = None
    
    with pytest.raises(RuntimeError, match="Aggregator SSH session not established"):
        attack_instance.deploy_modbus_proxy()


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.MODBUS_PROXY_PORT', 8502)
@patch('controller.modbus.InverterPivotAttack.MODBUS_TARGET_PORT', 502)
@patch('controller.modbus.InverterPivotAttack.AGGREGATOR_IP_ADDRESS', '192.168.1.200')
@patch('controller.modbus.InverterPivotAttack.time.sleep')
def test_deploy_modbus_proxy_startup_failure(mock_sleep, attack_instance):
    """Test Modbus proxy deployment with startup failure."""
    mock_ssh_client = MagicMock(spec=paramiko.SSHClient)
    attack_instance.aggregator_ssh_client = mock_ssh_client

    # Mock proxy that fails to start
    mock_proxy = MagicMock(spec=ModbusMITMProxy)
    mock_proxy.is_running = False

    with patch('controller.modbus.InverterPivotAttack.ModbusMITMProxy', return_value=mock_proxy), \
         patch('controller.modbus.InverterPivotAttack.threading.Thread'):

        with pytest.raises(RuntimeError, match="Failed to deploy Modbus proxy: Proxy failed to start properly"):
            attack_instance.deploy_modbus_proxy()


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.MODBUS_TARGET_PORT', 502)
@patch('controller.modbus.InverterPivotAttack.MODBUS_PROXY_PORT', 8502)
def test_cleanup_iptables_rules_success(attack_instance):
    """Test successful iptables rules cleanup."""
    # Setup mock SSH client and mark rules as applied
    mock_ssh_client = MagicMock(spec=paramiko.SSHClient)
    attack_instance.aggregator_ssh_client = mock_ssh_client
    attack_instance.iptables_rules_applied = True

    with patch.object(attack_instance, '_send_sudo_command', return_value="") as mock_send_sudo:
        # Test
        attack_instance.cleanup_iptables_rules()

        # Verify cleanup was called (the method calls _send_sudo_command multiple times
        # for deletions and checks, so just verify it was called)
        assert mock_send_sudo.called
        assert attack_instance.iptables_rules_applied is False


@pytest.mark.unit
def test_cleanup_iptables_rules_no_ssh(attack_instance):
    """Test iptables cleanup without SSH session."""
    attack_instance.aggregator_ssh_client = None
    attack_instance.iptables_rules_applied = True
    
    # Should not raise exception, just return early
    attack_instance.cleanup_iptables_rules()


@pytest.mark.unit
def test_cleanup_iptables_rules_not_applied(attack_instance):
    """Test iptables cleanup when rules were not applied."""
    mock_ssh_client = MagicMock(spec=paramiko.SSHClient)
    attack_instance.aggregator_ssh_client = mock_ssh_client
    attack_instance.iptables_rules_applied = False
    
    with patch.object(attack_instance, 'send_ssh_command_with_random_delays') as mock_send_cmd:
        # Should not attempt cleanup
        attack_instance.cleanup_iptables_rules()
        mock_send_cmd.assert_not_called()


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.MODBUS_TARGET_PORT', 502)
@patch('controller.modbus.InverterPivotAttack.MODBUS_PROXY_PORT', 8502)
@patch('controller.modbus.InverterPivotAttack.logging.warning')
def test_cleanup_iptables_rules_command_failure(mock_log_warning, attack_instance):
    """Test iptables cleanup with command failure."""
    mock_ssh_client = MagicMock(spec=paramiko.SSHClient)
    attack_instance.aggregator_ssh_client = mock_ssh_client
    attack_instance.iptables_rules_applied = True
    
    with patch.object(attack_instance, 'send_ssh_command_with_random_delays', side_effect=Exception("Cleanup failed")):
        # Should log warning but not raise exception
        attack_instance.cleanup_iptables_rules()
        mock_log_warning.assert_called_once()


@pytest.mark.unit
def test_teardown_success(attack_instance):
    """Test successful tearDown operation."""
    # Setup mock objects
    mock_historian_ssh = MagicMock(spec=paramiko.SSHClient)
    mock_regular_ssh = MagicMock(spec=paramiko.SSHClient)
    
    attack_instance.aggregator_ssh_client = mock_historian_ssh
    attack_instance.ssh_client = mock_regular_ssh
    attack_instance.iptables_rules_applied = True
    
    with patch.object(attack_instance, 'cleanup_iptables_rules') as mock_cleanup, \
         patch('controller.WateringHoleAttack.WateringHoleAttack.tearDown') as mock_super_teardown:
        
        # Test
        attack_instance.tearDown()
        
        # Verify cleanup was called
        mock_cleanup.assert_called_once()
        
        # Verify historian SSH connection was closed
        mock_historian_ssh.close.assert_called_once()
        assert attack_instance.aggregator_ssh_client is None
        
        # Verify parent tearDown was called
        mock_super_teardown.assert_called_once()


@pytest.mark.unit
def test_teardown_same_ssh_client(attack_instance):
    """Test tearDown when historian and regular SSH clients are the same."""
    # Setup same SSH client for both
    mock_ssh_client = MagicMock(spec=paramiko.SSHClient)
    attack_instance.aggregator_ssh_client = mock_ssh_client
    attack_instance.ssh_client = mock_ssh_client
    
    with patch.object(attack_instance, 'cleanup_iptables_rules') as mock_cleanup, \
         patch('controller.WateringHoleAttack.WateringHoleAttack.tearDown') as mock_super_teardown:
        
        # Test
        attack_instance.tearDown()
        
        # Verify cleanup was called
        mock_cleanup.assert_called_once()
        
        # Verify SSH client was not closed (since it's the same as ssh_client)
        mock_ssh_client.close.assert_not_called()
        
        # Verify parent tearDown was called
        mock_super_teardown.assert_called_once()


@pytest.mark.unit
@patch('controller.modbus.InverterPivotAttack.logging.warning')
def test_teardown_ssh_close_failure(mock_log_warning, attack_instance):
    """Test tearDown with SSH close failure."""
    mock_historian_ssh = MagicMock(spec=paramiko.SSHClient)
    mock_historian_ssh.close.side_effect = Exception("Close failed")
    
    attack_instance.aggregator_ssh_client = mock_historian_ssh
    attack_instance.ssh_client = MagicMock()  # Different client
    
    with patch.object(attack_instance, 'cleanup_iptables_rules'), \
         patch('controller.WateringHoleAttack.WateringHoleAttack.tearDown') as mock_super_teardown:
        
        # Test - should not raise exception
        attack_instance.tearDown()
        
        # Verify warning was logged
        mock_log_warning.assert_called()
        
        # Verify aggregator_ssh_client was set to None despite error
        assert attack_instance.aggregator_ssh_client is None
        
        # Verify parent tearDown was still called
        mock_super_teardown.assert_called_once()


@pytest.mark.unit
def test_run_inverter_pivot_attack_success(attack_instance):
    """Test successful execution of complete attack sequence."""
    # Mock the baseline data that would be returned
    mock_baseline = {"parameters": {}, "traffic_detected": False}

    with patch.object(attack_instance, 'establish_reverse_shell') as mock_establish, \
         patch.object(attack_instance, 'pivot_to_aggregator') as mock_pivot, \
         patch.object(attack_instance, 'capture_authentic_traffic', return_value=mock_baseline) as mock_capture, \
         patch.object(attack_instance, 'setup_iptables_redirection') as mock_iptables, \
         patch.object(attack_instance, 'deploy_modbus_proxy') as mock_proxy, \
         patch.object(attack_instance, 'execute_fdia_with_baseline') as mock_fdia:

        # Test
        attack_instance.run_inverter_pivot_attack()

        # Verify all steps were called in order
        mock_establish.assert_called_once()
        mock_pivot.assert_called_once()
        mock_capture.assert_called_once()
        mock_iptables.assert_called_once()
        mock_proxy.assert_called_once()
        mock_fdia.assert_called_once_with(mock_baseline)


@pytest.mark.unit
def test_run_inverter_pivot_attack_establish_failure(attack_instance):
    """Test attack sequence with establish_reverse_shell failure."""
    with patch.object(attack_instance, 'establish_reverse_shell', side_effect=Exception("Establish failed")):
        
        with pytest.raises(Exception, match="Establish failed"):
            attack_instance.run_inverter_pivot_attack()


@pytest.mark.unit
def test_run_inverter_pivot_attack_pivot_failure(attack_instance):
    """Test attack sequence with pivot failure."""
    with patch.object(attack_instance, 'establish_reverse_shell'), \
         patch.object(attack_instance, 'pivot_to_aggregator', side_effect=Exception("Pivot failed")):
        
        with pytest.raises(Exception, match="Pivot failed"):
            attack_instance.run_inverter_pivot_attack()


@pytest.mark.unit
def test_initialization(attack_instance):
    """Test proper initialization of InverterPivotAttack instance."""
    # Verify initial state
    assert attack_instance.aggregator_ssh_client is None
    assert attack_instance.modbus_proxy is None
    assert attack_instance.proxy_thread is None
    assert attack_instance.proxy_loop is None
    assert attack_instance.iptables_rules_applied is False

    # Verify inheritance
    assert isinstance(attack_instance, InverterPivotAttack)
    assert hasattr(attack_instance, 'msf_client')  # From parent class


@pytest.mark.unit
def test_test_inverter_pivot_attack_method(attack_instance):
    """Test the test_inverter_pivot_attack method (unittest entry point)."""
    # This tests the unittest-style test method that calls run_inverter_pivot_attack
    mock_baseline = {"parameters": {}, "traffic_detected": False}

    with patch.object(attack_instance, 'establish_reverse_shell') as mock_establish, \
         patch.object(attack_instance, 'pivot_to_aggregator') as mock_pivot, \
         patch.object(attack_instance, 'capture_authentic_traffic', return_value=mock_baseline) as mock_capture, \
         patch.object(attack_instance, 'setup_iptables_redirection') as mock_iptables, \
         patch.object(attack_instance, 'deploy_modbus_proxy') as mock_proxy, \
         patch.object(attack_instance, 'execute_fdia_with_baseline') as mock_fdia:

        # Test the unittest-style test method
        attack_instance.test_inverter_pivot_attack()

        # Verify all steps were called
        mock_establish.assert_called_once()
        mock_pivot.assert_called_once()
        mock_capture.assert_called_once()
        mock_iptables.assert_called_once()
        mock_proxy.assert_called_once()
        mock_fdia.assert_called_once_with(mock_baseline)
