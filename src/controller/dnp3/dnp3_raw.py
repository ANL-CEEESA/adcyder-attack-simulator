"""
Raw DNP3 Protocol Implementation

Provides low-level DNP3 protocol functions for attack simulation.
This module contains the actual protocol implementation that is used
by dnp3_client.py to communicate with DNP3 devices.
"""

import struct
import socket
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


def calculate_crc(data: bytes) -> int:
    """Calculate DNP3 CRC-16."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc = crc >> 1
    return crc


def build_read_request(
    group: int, variation: int, start: int, count: int, sequence: int
) -> bytes:
    """Build a DNP3 read request frame."""
    # Application layer
    app_control = 0xC0 | (sequence & 0x0F)
    func_code = 0x01  # READ
    qualifier = 0x00  # 8-bit start/stop indices
    obj_header = struct.pack(
        ">BBBHH", group, variation, qualifier, start, start + count - 1
    )
    app_layer = struct.pack(">BB", app_control, func_code) + obj_header

    # Transport layer
    transport = 0xC0
    data = struct.pack(">B", transport) + app_layer

    # Add data CRC (every 16 bytes)
    data_with_crc = add_data_crcs(data)

    # Link layer header
    link_header = build_link_header(len(data_with_crc), control=0x44)

    return link_header + data_with_crc


def build_write_request(
    group: int,
    variation: int,
    start: int,
    values: List[int],
    sequence: int,
) -> bytes:
    """Build a DNP3 write request frame."""
    # Application layer
    app_control = 0xC0 | (sequence & 0x0F)
    func_code = 0x02  # WRITE
    qualifier = 0x00  # 8-bit start/stop indices
    count = len(values)

    # Build object header
    obj_header = struct.pack(
        ">BBBHH", group, variation, qualifier, start, start + count - 1
    )

    # Build data based on group/variation
    data_bytes = b""
    if group == 10:  # Binary Output
        # Pack binary values as bytes (8 bits per byte)
        for i in range(0, len(values), 8):
            byte_val = 0
            for bit in range(8):
                if i + bit < len(values) and values[i + bit]:
                    byte_val |= 1 << bit
            data_bytes += struct.pack("B", byte_val)
    elif group == 40:  # Analog Output
        # Pack analog values as 32-bit integers with flags
        for value in values:
            flags = 0x01  # ONLINE flag
            data_bytes += struct.pack("<Bi", flags, value)

    app_layer = struct.pack(">BB", app_control, func_code) + obj_header + data_bytes

    # Transport layer
    transport = 0xC0
    data = struct.pack(">B", transport) + app_layer

    # Add data CRC (every 16 bytes)
    data_with_crc = add_data_crcs(data)

    # Link layer header
    link_header = build_link_header(len(data_with_crc), control=0x44)

    return link_header + data_with_crc


def build_link_header(data_length: int, control: int = 0x44) -> bytes:
    """Build DNP3 link layer header."""
    sync1 = 0x05
    sync2 = 0x64
    length = data_length + 5
    dest_addr = 0x0001
    src_addr = 0x0000

    header = struct.pack("<BBBBHH", sync1, sync2, length, control, dest_addr, src_addr)
    header_crc = calculate_crc(header[2:])

    return header + struct.pack("<H", header_crc)


def add_data_crcs(data: bytes) -> bytes:
    """Add CRC to data blocks (every 16 bytes)."""
    result = b""
    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        result += block
        crc = calculate_crc(block)
        result += struct.pack("<H", crc)
    return result


def remove_data_crcs(data: bytes) -> bytes:
    """Remove CRCs from data blocks."""
    result = b""
    i = 0
    while i < len(data):
        block_size = min(16, len(data) - i)
        result += data[i : i + block_size]
        i += block_size + 2  # Skip 2-byte CRC
    return result


def receive_response(sock: socket.socket, timeout: float = 5.0) -> Optional[bytes]:
    """Receive DNP3 response from socket."""
    try:
        sock.settimeout(timeout)

        # Read link header (10 bytes)
        header = sock.recv(10)
        if len(header) < 10:
            return None

        # Verify sync bytes
        if header[0] != 0x05 or header[1] != 0x64:
            return None

        # Get data length
        data_length = header[2] - 5

        # Read remaining data
        remaining = sock.recv(data_length + 100)  # Extra buffer for CRCs

        return header + remaining

    except socket.timeout:
        logger.warning("Socket timeout waiting for DNP3 response")
        return None
    except Exception as e:
        logger.error(f"Error receiving response: {e}")
        return None


def parse_response(response: bytes, request_func_code: int) -> Dict[str, Any]:
    """Parse DNP3 response and extract data."""
    try:
        if len(response) < 10:
            return {"error": "Response too short"}

        # Skip link header (10 bytes) and extract data
        data_start = 10
        data = remove_data_crcs(response[data_start:])

        if len(data) < 2:
            return {"error": "No application data"}

        # Parse application layer
        transport = data[0]
        app_control = data[1]
        func_code = data[2] if len(data) > 2 else 0

        # Log the function code for debugging
        logger.debug(f"Received DNP3 function code: 0x{func_code:02x}")

        # Valid DNP3 response function codes:
        # 0x81 = Response
        # 0x82 = Unsolicited Response
        # For write operations, we may get echoes of the request function code
        # 0x02 = WRITE (echo)
        # We'll accept any function code and just log warnings for unexpected ones
        expected_codes = [0x81, 0x82, 0x02]

        if func_code not in expected_codes:
            logger.debug(
                f"Non-standard function code: 0x{func_code:02x}, parsing anyway"
            )

        # Parse IIN flags (may not be present for all response types)
        iin1 = data[3] if len(data) > 3 else 0
        iin2 = data[4] if len(data) > 4 else 0

        result: Dict[str, Any] = {
            "function_code": f"0x{func_code:02x}",
            "iin_flags": f"0x{iin1:02x}{iin2:02x}",
            "values": [],
        }

        # Parse object data (starts at byte 5 for standard responses)
        # For OPERATE responses (0x05), the format may differ
        if len(data) > 5:
            obj_data = data[5:]
            values = extract_values(obj_data, request_func_code)
            result["values"] = values
            result["count"] = len(values)

        return result

    except Exception as e:
        logger.error(f"Error parsing response: {e}")
        return {"error": f"Parse error: {str(e)}"}


def extract_values(obj_data: bytes, request_func_code: int) -> List[Any]:
    """Extract values from object data based on request type."""
    values: List[Any] = []

    try:
        if len(obj_data) < 4:
            logger.debug("Object data too short to parse")
            return values

        group: int = obj_data[0]
        variation: int = obj_data[1]
        qualifier: int = obj_data[2]

        logger.debug(
            f"Object: Group={group}, Variation={variation}, Qualifier=0x{qualifier:02x}"
        )

        # Parse based on group/variation
        if group == 30:  # Analog Inputs
            if variation == 6:  # 32-bit with flag
                data_start = 3
                if qualifier == 0x00:  # Start/stop
                    data_start = 7

                i = data_start
                while i + 5 <= len(obj_data):
                    flags = obj_data[i]
                    value = struct.unpack("<i", obj_data[i + 1 : i + 5])[0]
                    values.append(value)
                    i += 5

        elif group == 1:  # Binary Inputs
            data_start = 7 if qualifier == 0x00 else 3
            for byte in obj_data[data_start:]:
                for bit in range(8):
                    values.append((byte >> bit) & 1)

        elif group == 10:  # Binary Outputs (write response)
            logger.debug("Binary Output response - write operation confirmed")
            # Write responses typically don't contain data values
            # They just confirm the operation succeeded

        elif group == 40:  # Analog Outputs (write response)
            logger.debug("Analog Output response - write operation confirmed")
            # Write responses typically don't contain data values

        else:
            logger.debug(
                f"Unhandled group {group} - may be a write confirmation or unsupported type"
            )

        if values:
            logger.info(f"Extracted {len(values)} values from response")
        else:
            logger.debug(
                f"No data values in response (Group {group}) - likely a write confirmation"
            )

    except Exception as e:
        logger.error(f"Error extracting values: {e}")

    return values


def send_dnp3_request(
    sock: socket.socket,
    function_code: int,
    address: int,
    number: int,
    sequence: int,
    data_points: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """Send DNP3 request and receive response."""
    try:
        # Build request based on function code
        if function_code == 1:  # Read Binary Inputs
            request = build_read_request(
                group=1, variation=2, start=address, count=number, sequence=sequence
            )
        elif function_code == 2:  # Read Analog Inputs
            request = build_read_request(
                group=30, variation=6, start=address, count=number, sequence=sequence
            )
        elif function_code == 3:  # Write Binary Outputs
            if data_points is None:
                return {"error": "data_points required for write operations"}
            request = build_write_request(
                group=10,
                variation=2,
                start=address,
                values=data_points,
                sequence=sequence,
            )
        elif function_code == 4:  # Write Analog Outputs
            if data_points is None:
                return {"error": "data_points required for write operations"}
            request = build_write_request(
                group=40,
                variation=2,
                start=address,
                values=data_points,
                sequence=sequence,
            )
        else:
            return {"error": f"Unsupported function code: {function_code}"}

        # Send request
        sock.sendall(request)
        logger.debug(f"Sent DNP3 request: {request.hex()}")

        # Receive response
        response = receive_response(sock)
        if response:
            logger.debug(f"Received DNP3 response: {response.hex()}")
            return parse_response(response, function_code)
        else:
            return {"error": "No response received"}

    except Exception as e:
        logger.error(f"DNP3 request failed: {e}")
        return {"error": f"Request failed: {str(e)}"}
