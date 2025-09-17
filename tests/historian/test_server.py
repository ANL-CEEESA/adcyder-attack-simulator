"""
test_server.py: Unit tests for the historian gRPC server.
"""
import pytest
import time
from unittest.mock import patch, mock_open, MagicMock

from historian.server import DataStreamServicer
from historian import data_stream_pb2


@pytest.fixture
def servicer_instance():
    """Fixture to create a DataStreamServicer instance for testing."""
    return DataStreamServicer(csv_file_path="dummy.csv", frequency_ms=100)


@pytest.mark.unit
def test_servicer_initialization(servicer_instance):
    """Test that the DataStreamServicer is initialized correctly."""
    assert servicer_instance.csv_file_path == "dummy.csv"
    assert servicer_instance.frequency_ms == 100
    assert servicer_instance.delay == 0.1


@pytest.mark.unit
def test_stream_data_success():
    """Test successful data streaming from a CSV file."""
    csv_content = "col1,col2\nval1,val2\n"
    servicer = DataStreamServicer(csv_file_path="dummy.csv", frequency_ms=0)

    with patch("builtins.open", mock_open(read_data=csv_content)):
        with patch("time.time", return_value=12345.678):
            generator = servicer.StreamData(None, None)
            results = list(generator)

    assert len(results) == 1
    assert isinstance(results[0], data_stream_pb2.DataPoint)
    assert results[0].timestamp == 12345678
    assert results[0].fields["col1"] == "val1"
    assert results[0].fields["col2"] == "val2"


@pytest.mark.unit
def test_stream_data_file_not_found():
    """Test the StreamData method when the CSV file is not found."""
    servicer = DataStreamServicer(csv_file_path="nonexistent.csv", frequency_ms=0)
    mock_context = MagicMock()

    with patch("builtins.open", side_effect=FileNotFoundError):
        generator = servicer.StreamData(None, mock_context)
        list(generator)  # Consume the generator

    mock_context.set_code.assert_called_once()
    mock_context.set_details.assert_called_once()


@pytest.mark.unit
def test_stream_data_empty_file():
    """Test the StreamData method with an empty CSV file."""
    csv_content = "col1,col2\n"
    servicer = DataStreamServicer(csv_file_path="dummy.csv", frequency_ms=0)

    with patch("builtins.open", mock_open(read_data=csv_content)):
        generator = servicer.StreamData(None, None)
        results = list(generator)

    assert len(results) == 0
