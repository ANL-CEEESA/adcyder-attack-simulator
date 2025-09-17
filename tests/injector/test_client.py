"""
test_client.py: Unit tests for the injector gRPC client.
"""
import pytest
from unittest.mock import patch, MagicMock

from injector import client
from historian import data_stream_pb2


class MockRpcError(Exception):
    """A mock class for grpc.RpcError."""
    def code(self):
        return 'TEST_ERROR'

    def details(self):
        return 'Test error details'


@pytest.mark.unit
@patch('injector.client.grpc.insecure_channel')
def test_stream_data_success(mock_insecure_channel):
    """Test successful data streaming."""
    # Create mock channel and stub
    mock_channel = MagicMock()
    mock_stub = MagicMock()
    mock_insecure_channel.return_value.__enter__.return_value = mock_channel
    mock_stub_class = MagicMock()
    mock_stub_class.return_value = mock_stub

    # Create mock data points
    mock_dp1 = MagicMock()
    mock_dp1.timestamp = 1678886400000
    mock_dp1.fields = {'col1': 'val1'}
    mock_dp2 = MagicMock()
    mock_dp2.timestamp = 1678886401000
    mock_dp2.fields = {'col1': 'val2'}
    mock_stub.StreamData.return_value = [mock_dp1, mock_dp2]

    with patch('historian.data_stream_pb2_grpc.DataStreamServiceStub', mock_stub_class):
        client.stream_data()

    # Assert that the channel and stub were created correctly
    mock_insecure_channel.assert_called_once_with('localhost:50051')
    mock_stub_class.assert_called_once_with(mock_channel)

    # Assert that StreamData was called
    mock_stub.StreamData.assert_called_once()


@pytest.mark.unit
@patch('injector.client.grpc.insecure_channel')
@patch('injector.client.logging')
def test_stream_data_rpc_error(mock_logging, mock_insecure_channel):
    """Test handling of grpc.RpcError."""
    # Create mock channel and stub
    mock_channel = MagicMock()
    mock_stub = MagicMock()
    mock_insecure_channel.return_value.__enter__.return_value = mock_channel
    mock_stub_class = MagicMock()
    mock_stub_class.return_value = mock_stub

    # Configure stub to raise the custom RpcError
    mock_stub.StreamData.side_effect = MockRpcError

    with patch('injector.client.grpc.RpcError', MockRpcError):
        with patch('historian.data_stream_pb2_grpc.DataStreamServiceStub', mock_stub_class):
            client.stream_data()

    # Assert that the error was logged
    mock_logging.info.assert_any_call("RPC error: TEST_ERROR: Test error details")
