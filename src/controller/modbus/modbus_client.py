"""
Modbus UDP Client Library

A comprehensive Modbus UDP client implementation supporting standard function codes
with both unicast and broadcast capabilities.

Features:
- Read Coils (Function Code 1)
- Read Discrete Inputs (Function Code 2)
- Read Holding Registers (Function Code 3)
- Read Input Registers (Function Code 4)
- Write Single Coil (Function Code 5)
- Write Single Register (Function Code 6)
- Write Multiple Coils (Function Code 15)
- Write Multiple Registers (Function Code 16)
- Broadcast support for write functions
- Response parsing for read functions

TODO:
- Implement additional Modbus function codes:
    - Read Exception Status (Function Code 7)
    - Diagnostics (Function Code 8)
    - Get Comm Event Counter (Function Code 11)
    - Get Comm Event Log (Function Code 12)
    - Report Slave ID (Function Code 17)
    - Mask Write Register (Function Code 22)
    - Read/Write Multiple Registers (Function Code 23)
    - Read FIFO Queue (Function Code 24)
    - Read Device Identification (Function Code 43/14)
- Add support for Modbus TCP
- Implement unit tests for all functions
"""

import socket
import struct
import json
import time
import logging
from typing import Dict, List, Optional, Any, Union

logger = logging.getLogger(__name__)


class ModbusClient:
    """
    A Modbus UDP client for communicating with Modbus devices.

    Supports both unicast and broadcast operations with comprehensive
    function code implementation for industrial control systems.
    """

    # Function code mappings
    FUNCTION_CODES = {
        "READ_COILS": 1,
        "READ_DISCRETE_INPUTS": 2,
        "READ_REGISTERS": 3,
        "READ_INPUT_REGISTERS": 4,
        "WRITE_SINGLE_COIL": 5,
        "WRITE_SINGLE_REGISTER": 6,
        "WRITE_MULTIPLE_COILS": 15,
        "WRITE_MULTIPLE_REGISTERS": 16,
    }

    def __init__(
        self,
        host: str = "localhost",
        port: int = 502,
        unit_id: int = 1,
        timeout: float = 2.0,
    ):
        """
        Initialize the Modbus client.

        Args:
            host: Target device IP address or "broadcast" for broadcast operations
            port: Modbus port (default 502)
            unit_id: Modbus unit/slave ID (default 1)
            timeout: Socket timeout in seconds (default 2.0)
        """
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.timeout = timeout

    def _create_request(
        self,
        function_code: int,
        start_address: int,
        quantity: int,
        data: Optional[List[int]] = None,
        is_broadcast: bool = False,
    ) -> bytes:
        """
        Constructs a Modbus request PDU + MBAP header for UDP.

        Args:
            function_code: Modbus function code
            start_address: Starting register/coil address
            quantity: Number of registers/coils to read/write
            data: Data values for write operations
            is_broadcast: Whether this is a broadcast request

        Returns:
            Raw Modbus request bytes
        """
        unit_id = 0 if is_broadcast else self.unit_id
        data = data or []

        # Calculate length field in MBAP (excluding the 6-byte header)
        if function_code in [5, 6]:
            length = 6
        elif function_code in [15, 16]:
            byte_count = (quantity + 7) // 8 if function_code == 15 else quantity * 2
            length = 7 + byte_count
        else:
            length = 6

        # MBAP header: Transaction ID, Protocol ID, Length, Unit ID
        header = struct.pack(">HHHB", 1, 0, length, unit_id)

        # Function-specific payload
        if function_code == 5:  # Write Single Coil
            value = 0xFF00 if data and data[0] else 0x0000
            data_bytes = struct.pack(">BHH", function_code, start_address, value)
        elif function_code == 6:  # Write Single Register
            data_bytes = struct.pack(">BHH", function_code, start_address, data[0])
        elif function_code == 15:  # Write Multiple Coils
            byte_count = (quantity + 7) // 8
            coil_data = bytearray(byte_count)
            for i, bit in enumerate(data):
                if bit:
                    coil_data[i // 8] |= 1 << (i % 8)
            data_bytes = (
                struct.pack(">BHHB", function_code, start_address, quantity, byte_count)
                + coil_data
            )
        elif function_code == 16:  # Write Multiple Registers
            byte_count = quantity * 2
            register_data = b"".join(struct.pack(">H", val) for val in data)
            data_bytes = (
                struct.pack(">BHHB", function_code, start_address, quantity, byte_count)
                + register_data
            )
        else:  # Read operations
            data_bytes = struct.pack(">BHH", function_code, start_address, quantity)

        return header + data_bytes

    def _setup_broadcast_socket(self) -> socket.socket:
        """Sets up a UDP socket configured for broadcast use."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", self.port))
        return sock

    def _collect_responses(
        self, sock: socket.socket, timeout: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """
        Collects responses over a timeout window from multiple Modbus devices.

        Args:
            sock: UDP socket to receive on
            timeout: Collection timeout (uses instance timeout if None)

        Returns:
            List of response dictionaries with source IP and parsed data
        """
        if timeout is None:
            timeout = self.timeout

        responses = []
        start_time = time.time()
        sock.settimeout(0.1)  # Keep original 0.1s timeout for individual receives

        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(1024)
                response = self._parse_response(data)
                responses.append({"source": addr[0], "data": response})
            except socket.timeout:
                continue
            except Exception as e:
                logger.warning(f"Error receiving response: {e}")

        return responses

    def _parse_response(self, response: bytes) -> Dict[str, Any]:
        """
        Parses a raw Modbus response into structured fields.

        Args:
            response: Raw response bytes

        Returns:
            Dictionary containing parsed response data
        """
        result: Dict[str, Any] = {
            "raw_hex": response.hex(),
            "length": len(response),
            "function_code": response[7] if len(response) > 7 else None,
        }

        # Exception response check
        if result["function_code"] is not None and result["function_code"] >= 0x80:
            result["exception_code"] = response[8] if len(response) > 8 else None
            result["error"] = "Modbus exception response"
            return result

        if len(response) > 9:
            data_length = response[8]
            data_bytes = response[9 : 9 + data_length]

            if result["function_code"] in [3, 4]:  # Register reads
                result["values"] = [
                    struct.unpack(">H", data_bytes[i : i + 2])[0]
                    for i in range(0, len(data_bytes), 2)
                ]
            elif result["function_code"] in [1, 2]:  # Coil/discrete input reads
                values = []
                for byte in data_bytes:
                    for bit in range(8):
                        values.append((byte >> bit) & 1)
                result["values"] = values

        return result

    def _send_request(
        self,
        function_code: int,
        start_address: int,
        quantity: int = 1,
        data: Optional[List[int]] = None,
        broadcast: bool = False,
    ) -> Dict[str, Any]:
        """
        Sends a Modbus request and handles the response.

        Args:
            function_code: Modbus function code
            start_address: Starting address
            quantity: Number of items to read/write
            data: Data for write operations
            broadcast: Whether to broadcast the request

        Returns:
            Dictionary containing response data or error information
        """
        sock = None
        try:
            is_broadcast = broadcast or self.host in ["255.255.255.255", "broadcast"]
            sock = (
                self._setup_broadcast_socket()
                if is_broadcast
                else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            )

            target_ip = "255.255.255.255" if is_broadcast else self.host

            request = self._create_request(
                function_code, start_address, quantity, data, is_broadcast
            )
            sock.sendto(request, (target_ip, self.port))

            if is_broadcast:
                if function_code in [5, 6, 15, 16]:  # Write operations
                    return {"status": "broadcast_write_complete"}
                # For broadcast reads, collect responses
                responses = self._collect_responses(sock)
                if len(responses) > 1:
                    return {"multi_device_response": responses}
                elif len(responses) == 1:
                    return responses[0]["data"]  # type: ignore
                else:
                    return {"error": "No responses received"}
            else:
                sock.settimeout(self.timeout)
                response, _ = sock.recvfrom(1024)
                return self._parse_response(response)

        except Exception as e:
            logger.error(f"Modbus request failed: {e}")
            return {"error": str(e)}
        finally:
            if sock:
                sock.close()

    # Read Functions
    def read_coils(
        self, start_address: int, count: int = 1, broadcast: bool = False
    ) -> Dict[str, Any]:
        """Read coil status (Function Code 1)."""
        return self._send_request(1, start_address, count, broadcast=broadcast)

    def read_discrete_inputs(
        self, start_address: int, count: int = 1, broadcast: bool = False
    ) -> Dict[str, Any]:
        """Read discrete input status (Function Code 2)."""
        return self._send_request(2, start_address, count, broadcast=broadcast)

    def read_holding_registers(
        self, start_address: int, count: int = 1, broadcast: bool = False
    ) -> Dict[str, Any]:
        """Read holding registers (Function Code 3)."""
        return self._send_request(3, start_address, count, broadcast=broadcast)

    def read_input_registers(
        self, start_address: int, count: int = 1, broadcast: bool = False
    ) -> Dict[str, Any]:
        """Read input registers (Function Code 4)."""
        return self._send_request(4, start_address, count, broadcast=broadcast)

    # Write Functions
    def write_single_coil(
        self, address: int, value: bool, broadcast: bool = False
    ) -> Dict[str, Any]:
        """Write single coil (Function Code 5)."""
        return self._send_request(
            5, address, 1, [1 if value else 0], broadcast=broadcast
        )

    def write_single_register(
        self, address: int, value: int, broadcast: bool = False
    ) -> Dict[str, Any]:
        """Write single register (Function Code 6)."""
        return self._send_request(6, address, 1, [value], broadcast=broadcast)

    def write_multiple_coils(
        self, start_address: int, values: List[bool], broadcast: bool = False
    ) -> Dict[str, Any]:
        """Write multiple coils (Function Code 15)."""
        data = [1 if v else 0 for v in values]
        return self._send_request(
            15, start_address, len(values), data, broadcast=broadcast
        )

    def write_multiple_registers(
        self, start_address: int, values: List[int], broadcast: bool = False
    ) -> Dict[str, Any]:
        """Write multiple registers (Function Code 16)."""
        return self._send_request(
            16, start_address, len(values), values, broadcast=broadcast
        )

    # Convenience Methods
    def send_command(
        self,
        action: str,
        address: int,
        number: int = 1,
        data_registers: Union[str, List[int]] = "",
        broadcast: bool = False,
    ) -> str:
        """
        Send a Modbus command using string action names (backward compatibility).

        Args:
            action: Action name (e.g., "READ_COILS", "WRITE_SINGLE_REGISTER")
            address: Starting address
            number: Number of items
            data_registers: Data as comma-separated string or list of integers
            broadcast: Whether to broadcast

        Returns:
            JSON string containing response
        """
        if action not in self.FUNCTION_CODES:
            return json.dumps({"error": f"Unknown action: {action}"})

        # Parse data_registers - CRITICAL: Match original parsing logic exactly
        if isinstance(data_registers, str):
            data = (
                [int(x) for x in data_registers.split(",") if x.strip()]
                if data_registers.strip()
                else []
            )
        else:
            data = data_registers or []

        function_code = self.FUNCTION_CODES[action]
        result = self._send_request(function_code, address, number, data, broadcast)
        return json.dumps(result)

    def broadcast_command(
        self,
        action: str,
        address: int,
        number: int = 1,
        data_registers: Union[str, List[int]] = "",
    ) -> str:
        """Convenience wrapper to broadcast a Modbus command."""
        return self.send_command(
            action, address, number, data_registers, broadcast=True
        )

    def __repr__(self) -> str:
        return f"ModbusClient(host='{self.host}', port={self.port}, unit_id={self.unit_id})"


# Convenience functions for backward compatibility
def send_modbus_request(
    ip: str,
    port: int,
    unit_id: int,
    action: str,
    address: int,
    number: int,
    data_registers: str,
) -> str:
    """Legacy function for backward compatibility."""
    client = ModbusClient(host=ip, port=port, unit_id=unit_id)
    return client.send_command(action, address, number, data_registers)


def broadcast_modbus_command(
    port: int,
    unit_id: int,
    action: str,
    address: int,
    number: int,
    data_registers: str,
) -> str:
    """Legacy function for backward compatibility."""
    client = ModbusClient(host="broadcast", port=port, unit_id=unit_id)
    return client.broadcast_command(action, address, number, data_registers)
