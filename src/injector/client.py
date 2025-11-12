import argparse
from historian import data_stream_pb2
from historian import data_stream_pb2_grpc
import grpc
import logging

from datetime import datetime


def stream_data(server_address: str = "localhost:50051") -> None:
    """
    Connect to the server and receive the data stream.

    Args:
        server_address: The address of the gRPC server
    """
    # Create a gRPC channel
    with grpc.insecure_channel(server_address) as channel:
        # Create a stub (client)
        stub = data_stream_pb2_grpc.DataStreamServiceStub(channel)  # type: ignore[no-untyped-call]

        # Create an empty request
        request = data_stream_pb2.StreamRequest()  # type: ignore[attr-defined]

        logging.info(f"Requesting data stream from server at {server_address}")
        try:
            # Make the request and iterate over the response stream
            response_iterator = stub.StreamData(request)

            # Process each data point
            for data_point in response_iterator:
                # Convert timestamp to readable format
                timestamp = datetime.fromtimestamp(data_point.timestamp / 1000)
                formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

                # TODO: Actually inject the data

                # logging.info data point information
                logging.info(f"Received data point at {formatted_time}:")
                for key, value in data_point.fields.items():
                    logging.info(f"  {key}: {value}")
                logging.info("-" * 40)

        except grpc.RpcError as e:
            logging.info(f"RPC error: {e.code()}: {e.details()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stream data from a CSV file via gRPC")
    parser.add_argument(
        "--server",
        default="localhost:50051",
        help="Server address (default: localhost:50051)",
    )

    args = parser.parse_args()
    stream_data(args.server)
