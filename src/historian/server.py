import argparse
import csv
import concurrent.futures
import data_stream_pb2  # type: ignore
import data_stream_pb2_grpc  # type: ignore
import grpc  # type: ignore
import logging
import time
from typing import Generator, Any


class DataStreamServicer(data_stream_pb2_grpc.DataStreamServiceServicer):  # type: ignore
    def __init__(self, csv_file_path: str, frequency_ms: int) -> None:
        """
        Initialize the servicer with the path to the CSV file to stream
        and the frequency to stream at.

        Args:
            csv_file_path: Path to the CSV file that will be streamed
            frequency_ms: Delay between messages in milliseconds
        """
        self.csv_file_path = csv_file_path
        self.frequency_ms = frequency_ms
        self.delay = frequency_ms / 1000 if frequency_ms > 0 else 0
        logging.info(f"Server initialized with CSV file: {csv_file_path}")
        logging.info(
            f"Streaming frequency: {frequency_ms} ms ({1000/frequency_ms if frequency_ms > 0 else 'unlimited'} messages/second)"
        )

    def StreamData(self, request: Any, context: Any) -> Generator[Any, None, None]:
        """
        Implement the StreamData RPC method.
        This reads a CSV file and streams each row as a DataPoint message.
        """
        logging.info(
            f"Client connected, streaming data from file: {self.csv_file_path}"
        )
        try:
            with open(self.csv_file_path, "r", newline="") as csvfile:
                reader = csv.DictReader(csvfile)

                # Stream each row as a DataPoint
                for row in reader:
                    # Create a new DataPoint message
                    data_point = data_stream_pb2.DataPoint()

                    # Set timestamp to current time
                    data_point.timestamp = int(time.time() * 1000)

                    # Add all columns from the CSV as fields
                    for key, value in row.items():
                        data_point.fields[key] = value

                    # Yield the data point to the stream
                    yield data_point

                    # Sleep for the specified delay to control streaming rate
                    if self.delay > 0:
                        time.sleep(self.delay)

        except FileNotFoundError:
            logging.error(f"Error: File {self.csv_file_path} not found")
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"File {self.csv_file_path} not found")
            return
        except Exception as e:
            logging.error(f"Error streaming data: {str(e)}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Error streaming data: {str(e)}")
            return


def serve(csv_file_path: str, frequency_ms: int, port: int = 50051) -> None:
    """
    Start the gRPC server

    Args:
        csv_file_path: Path to the CSV file to stream
        frequency_ms: Delay between messages in milliseconds
        port: Port to listen on (default: 50051)
    """
    server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=10))
    data_stream_pb2_grpc.add_DataStreamServiceServicer_to_server(
        DataStreamServicer(csv_file_path, frequency_ms), server
    )

    server_address = f"[::]:{port}"
    server.add_insecure_port(server_address)
    server.start()
    logging.info(f"Server started on port {port}, streaming file: {csv_file_path}")

    try:
        # Keep server running until keyboard interrupt
        while True:
            time.sleep(86400)  # Sleep for 1 day
    except KeyboardInterrupt:
        server.stop(0)
        logging.info("Server stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stream CSV data via gRPC")
    parser.add_argument("file", help="Path to the CSV file to stream")
    parser.add_argument(
        "--frequency",
        type=int,
        default=1000,
        help="Delay between messages in milliseconds (default: 100)",
    )
    parser.add_argument(
        "--port", type=int, default=50051, help="Port to listen on (default: 50051)"
    )

    args = parser.parse_args()
    serve(args.file, args.frequency, args.port)
