"""
DNP3 UDP Client Library

A comprehensive DNP3 UDP client implementation supporting standard function codes
with both unicast and broadcast capabilities.

Current Functionality:
- Read Binary Inputs (Function Code 1)
- Read Analog Inputs (Function Code 2)
- Write Binary Outputs (Function Code 3)
- Write Analog Outputs (Function Code 4)
- Broadcast support for write functions
- Response parsing for read functions

TODO:
- Implement additional DNP3 function codes:
    - Confirm (Function Code 0)
    - Select (Function Code 3)
    - Operate (Function Code 4)
    - Direct Operate (Function Code 5)
    - Direct Operate No Ack (Function Code 6)
    - Freeze (Function Code 7)
    - Freeze No Ack (Function Code 8)
    - Freeze Clear (Function Code 9)
    - Freeze Clear No Ack (Function Code 10)
    - Cold Restart (Function Code 13)
    - Warm Restart (Function Code 14)
    - Enable Unsolicited (Function Code 20)
    - Disable Unsolicited (Function Code 21)
    - Assign Class (Function Code 22)
    - Delay Measurement (Function Code 23)
    - Record Current Time (Function Code 24)
    - File Operations (Function Codes 25-30)
    - Activate Configuration (Function Code 31)
    - Authentication (Function Codes 32-33)
- Add support for DNP3 over TCP
- Implement unit tests for all functions
"""

import json
import socket
import struct
import time
import logging
from typing import Dict, List, Optional, Any, Union

# Maintain original logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class DNP3Client:
    """
    A DNP3 UDP client for communicating with DNP3 devices.

    Supports both unicast and broadcast operations with comprehensive
    function code implementation for industrial control systems.
    """

    # Function code mappings
    FUNCTION_CODES = {
        "READ_BINARY": 1,
        "READ_ANALOG": 2,
        "WRITE_BINARY": 3,
        "WRITE_ANALOG": 4,
        # TODO: Add additional actions corresponding to new function codes.
    }

    def __init__(
        self, host: str = "localhost", port: int = 20000, timeout: float = 2.0
    ):
        """
        Initialize the DNP3 client.

        Args:
            host: Target device IP address or "broadcast" for broadcast operations
            port: DNP3 port (default 20000)
            timeout: Socket timeout in seconds (default 2.0)
        """
        self.host = host
        self.port = port
        self.timeout = timeout

    def _create_request(
        self,
        function_code: int,
        start_address: int,
        quantity: int,
        data: Optional[List[int]] = None,
    ) -> bytes:
        """
        Constructs a DNP3 request message.

        Args:
            function_code: DNP3 function code
            start_address: Starting address
            quantity: Number of points to read/write
            data: Data values for write operations

        Returns:
            Raw DNP3 request bytes
        """
        logger.debug(
            f"Creating DNP3 request - Function: {function_code}, Address: {start_address}, Quantity: {quantity}"
        )

        transport_header = struct.pack(">B", 0x44)
        app_control = struct.pack(">B", 0xE0)
        func_code = struct.pack(">B", function_code)
        iin_flags = struct.pack(">H", 0x0000)

        if function_code in [1, 2]:
            logger.debug("Constructing read operation request")
            obj_header = struct.pack(
                ">BBHH",
                0x01,
                0x02,
                0x00,
                quantity,
            )
            data_bytes = struct.pack(">HH", start_address, start_address + quantity - 1)
        else:
            logger.debug("Constructing write operation request")
            obj_header = struct.pack(
                ">BBHH",
                0x0A,
                0x02,
                0x28,
                len(data or []),
            )
            data_bytes = b""
            if data:
                for value in data:
                    data_bytes += struct.pack(">H", value)

        message = (
            transport_header
            + app_control
            + func_code
            + iin_flags
            + obj_header
            + data_bytes
        )
        crc = self._calculate_crc(message)

        logger.debug(f"DNP3 request created, total length: {len(message) + 2} bytes")
        return message + struct.pack(">H", crc)

    def _calculate_crc(self, data: bytes) -> int:
        """
        Calculates CRC-16 for DNP3 message.

        Args:
            data: Message bytes to calculate CRC for

        Returns:
            CRC-16 value
        """
        logger.debug("Calculating CRC-16 for DNP3 message")
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc = crc >> 1
        return crc

    def _setup_broadcast_socket(self) -> socket.socket:
        """
        Sets up a UDP socket configured for broadcast use.

        Returns:
            Configured UDP socket
        """
        logger.info(f"Setting up broadcast socket on port {self.port}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", self.port))
            logger.debug("Socket setup successful")
            return sock
        except Exception as e:
            logger.error(f"Failed to setup socket: {e}")
            raise

    def _collect_responses(
        self, sock: socket.socket, timeout: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Collects responses over a timeout window from multiple DNP3 devices.

        Args:
            sock: UDP socket to receive on
            timeout: Collection timeout (uses instance timeout if None)

        Returns:
            List of response dictionaries with source IP and parsed data
        """
        if timeout is None:
            timeout = self.timeout

        logger.info(f"Collecting responses (timeout: {timeout}s)")
        responses = []
        start_time = time.time()
        sock.settimeout(0.1)  # Keep original 0.1s timeout for individual receives

        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(1024)
                logger.info(f"Received response from {addr[0]}")
                logger.debug(f"Raw response data: {data.hex()}")
                response = self._parse_response(data)
                responses.append({"source": addr[0], "data": response})
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error receiving response: {e}")

        logger.info(f"Collection complete. Received {len(responses)} responses")
        return responses

    def _parse_response(self, response: bytes) -> Dict[str, Any]:
        """
        Parses a raw DNP3 response into structured fields.

        Args:
            response: Raw response bytes

        Returns:
            Dictionary containing parsed response data
        """
        logger.debug("Parsing DNP3 response")
        result: Dict[str, Any] = {
            "raw_hex": response.hex(),
            "length": len(response),
            "function_code": response[2] if len(response) > 2 else None,
        }

        if len(response) > 8:
            data_section = response[8:]
            values = []
            for i in range(0, len(data_section) - 2, 2):
                value = struct.unpack(">H", data_section[i : i + 2])[0]
                values.append(value)
            result["values"] = values
            logger.debug(f"Parsed values: {values}")

        return result

    def _send_request(
        self,
        function_code: int,
        address: int,
        number: int,
        data_points: Optional[List[int]] = None,
        broadcast: bool = False,
    ) -> Dict[str, Any]:
        """
        Sends a DNP3 request and handles the response.

        Args:
            function_code: DNP3 function code
            address: Starting address
            number: Number of points
            data_points: Data for write operations
            broadcast: Whether to broadcast the request

        Returns:
            Dictionary containing response data or error information
        """
        is_broadcast = broadcast or self.host in ["255.255.255.255", "broadcast"]
        target_ip = "255.255.255.255" if is_broadcast else self.host

        logger.info(
            f"Sending DNP3 request - IP: {target_ip}, Port: {self.port}, Function: {function_code}"
        )

        sock = None
        try:
            sock = self._setup_broadcast_socket()

            logger.debug(f"Mapped function code {function_code}")

            request = self._create_request(function_code, address, number, data_points)
            logger.info(f"Sending request to {target_ip}:{self.port}")
            sock.sendto(request, (target_ip, self.port))

            responses = self._collect_responses(sock)

            if not responses:
                logger.warning("No responses received")
                return {"error": "No responses received"}

            logger.info(f"Request complete. Received {len(responses)} response(s)")
            if len(responses) == 1:
                return responses[0]["data"]  # type: ignore
            else:
                return {"multi_device_response": responses}

        except Exception as e:
            logger.error(f"Error in DNP3 request: {e}")
            return {"error": str(e)}
        finally:
            if sock:
                logger.debug("Closing socket")
                sock.close()

    # Read Functions
    def read_binary_inputs(
        self, address: int, count: int = 1, broadcast: bool = False
    ) -> Dict[str, Any]:
        """Read binary input status (Function Code 1)."""
        return self._send_request(1, address, count, broadcast=broadcast)

    def read_analog_inputs(
        self, address: int, count: int = 1, broadcast: bool = False
    ) -> Dict[str, Any]:
        """Read analog input values (Function Code 2)."""
        return self._send_request(2, address, count, broadcast=broadcast)

    # Write Functions
    def write_binary_outputs(
        self, address: int, values: List[int], broadcast: bool = False
    ) -> Dict[str, Any]:
        """Write binary output values (Function Code 3)."""
        return self._send_request(3, address, len(values), values, broadcast=broadcast)

    def write_analog_outputs(
        self, address: int, values: List[int], broadcast: bool = False
    ) -> Dict[str, Any]:
        """Write analog output values (Function Code 4)."""
        return self._send_request(4, address, len(values), values, broadcast=broadcast)

    # Convenience Methods
    def send_command(
        self,
        action: str,
        address: int,
        number: int,
        data_points: Optional[str] = None,
        broadcast: bool = False,
    ) -> str:
        """
        Send a DNP3 command using string action names (backward compatibility).

        Args:
            action: Action name (e.g., "READ_BINARY", "WRITE_ANALOG")
            address: Starting address
            number: Number of points
            data_points: Data as comma-separated string
            broadcast: Whether to broadcast

        Returns:
            JSON string containing response
        """
        logger.info(f"Sending DNP3 command - Action: {action}, Address: {address}")

        if action not in self.FUNCTION_CODES:
            return json.dumps({"error": f"Unknown action: {action}"})

        function_code = self.FUNCTION_CODES[action]

        # Parse data_points - CRITICAL: Match original parsing logic exactly
        data: Optional[List[int]] = None
        if data_points:
            data = [int(x) for x in data_points.split(",")]
            logger.debug(f"Parsed data points: {data}")

        result = self._send_request(function_code, address, number, data, broadcast)
        return json.dumps(result)

    def broadcast_command(
        self,
        action: str,
        address: int,
        number: int,
        data_points: Optional[str] = None,
    ) -> str:
        """Convenience wrapper to broadcast a DNP3 command."""
        logger.info(f"Broadcasting DNP3 command - Action: {action}, Port: {self.port}")
        return self.send_command(action, address, number, data_points, broadcast=True)

    def __repr__(self) -> str:
        return f"DNP3Client(host='{self.host}', port={self.port})"
