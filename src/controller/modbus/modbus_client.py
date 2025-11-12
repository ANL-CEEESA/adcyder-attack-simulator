"""
Modbus TCP Client Library

A Modbus TCP client implementation using pymodbus library for standard operations
with custom attack-specific functionality for cybersecurity research.

Library Integration:
- Uses pymodbus library for all standard Modbus TCP operations
- Supports comprehensive Modbus function codes through the library
- Maintains proper Modbus protocol compliance and error handling
- Automatic connection management and retry logic

Attack-Specific Features:
- Device discovery via UDP broadcast and TCP port scanning
- Custom Modbus packet crafting with proper MBAP headers
- Multiple discovery packet types (device ID, simple read, diagnostics)
- Network enumeration capabilities for security assessment
- Device identification parsing for reconnaissance

Standard Operations (via pymodbus library):
- Read Coils (Function Code 1)
- Read Discrete Inputs (Function Code 2)
- Read Holding Registers (Function Code 3)
- Read Input Registers (Function Code 4)
- Write Single Coil (Function Code 5)
- Write Single Register (Function Code 6)
- Write Multiple Coils (Function Code 15)
- Write Multiple Registers (Function Code 16)
- All additional Modbus function codes supported by the library
"""

import ipaddress
import json
import logging
import socket
import struct
import time
import types

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException


class ModbusClient:
    """
    A Modbus TCP client for communicating with Modbus devices.

    Uses pymodbus library when available for standard operations,
    falls back to custom implementation for attack-specific scenarios.
    Provides persistent TCP connections with comprehensive
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
        Initialize the Modbus TCP client.

        Args:
            host: Target device IP address
            port: Modbus port (default 502)
            unit_id: Modbus unit/slave ID (default 1)
            timeout: Socket timeout in seconds (default 2.0)
        """
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.timeout = timeout
        self._socket: Optional[socket.socket] = None
        self._connected = False
        self._transaction_id = 0
        self._pymodbus_client: Optional[ModbusTcpClient] = None

        logger.debug("Initialized ModbusClient with pymodbus library")

    def connect(self) -> None:
        """Establish TCP connection to the Modbus device."""
        if self._connected and (self._socket or self._pymodbus_client):
            return

        try:
            self._connect_library()
            self._connected = True
            logger.debug(f"Connected to Modbus device at {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}:{self.port}: {e}")
            self._connected = False
            self._cleanup_connections()
            raise

    def _connect_library(self) -> None:
        """Connect using pymodbus library."""
        self._pymodbus_client = ModbusTcpClient(
            host=self.host, port=self.port, timeout=self.timeout
        )
        if not self._pymodbus_client.connect():  # type: ignore[no-untyped-call]
            raise ConnectionError(
                f"Failed to connect with pymodbus to {self.host}:{self.port}"
            )

    # Custom connection method removed - now using pymodbus library only

    def _cleanup_connections(self) -> None:
        """Clean up all connection resources."""
        if self._socket:
            self._socket.close()
            self._socket = None
        if self._pymodbus_client:
            self._pymodbus_client.close()  # type: ignore[no-untyped-call]
            self._pymodbus_client = None

    def disconnect(self) -> None:
        """Close the TCP connection."""
        self._cleanup_connections()
        self._connected = False
        logger.debug("Disconnected from Modbus device")

    # Custom request creation removed - now handled by pymodbus library integration

    # Custom response parsing removed - now handled by pymodbus library integration

    def _send_request_library(
        self,
        function_code: int,
        start_address: int,
        quantity: int = 1,
        data: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """
        Send Modbus request using pymodbus library.

        Args:
            function_code: Modbus function code
            start_address: Starting register/coil address
            quantity: Number of registers/coils to read/write
            data: Data values for write operations

        Returns:
            Dictionary containing response data or error information
        """
        if not self._pymodbus_client:
            return {"error": "Not connected to device"}

        try:
            logger.debug(f"Using pymodbus library for function code {function_code}")

            # Map function codes to pymodbus methods
            if function_code == 1:  # Read Coils
                response = self._pymodbus_client.read_coils(  # type: ignore[misc]
                    start_address, quantity, self.unit_id
                )
                if response.isError():
                    return {"error": f"Read coils error: {response}"}
                return {
                    "function_code": function_code,
                    "address": start_address,
                    "count": quantity,
                    "values": response.bits[:quantity],
                    "library": "pymodbus",
                }

            elif function_code == 2:  # Read Discrete Inputs
                response = self._pymodbus_client.read_discrete_inputs(  # type: ignore[misc]
                    start_address, quantity, self.unit_id
                )
                if response.isError():
                    return {"error": f"Read discrete inputs error: {response}"}
                return {
                    "function_code": function_code,
                    "address": start_address,
                    "count": quantity,
                    "values": response.bits[:quantity],
                    "library": "pymodbus",
                }

            elif function_code == 3:  # Read Holding Registers
                response = self._pymodbus_client.read_holding_registers(  # type: ignore[misc]
                    start_address, quantity, self.unit_id
                )
                if response.isError():
                    return {"error": f"Read holding registers error: {response}"}
                return {
                    "function_code": function_code,
                    "address": start_address,
                    "count": quantity,
                    "values": response.registers,
                    "library": "pymodbus",
                }

            elif function_code == 4:  # Read Input Registers
                response = self._pymodbus_client.read_input_registers(  # type: ignore[misc]
                    start_address, quantity, self.unit_id
                )
                if response.isError():
                    return {"error": f"Read input registers error: {response}"}
                return {
                    "function_code": function_code,
                    "address": start_address,
                    "count": quantity,
                    "values": response.registers,
                    "library": "pymodbus",
                }

            elif function_code == 5:  # Write Single Coil
                if not data:
                    return {"error": "Data required for write operation"}
                value = bool(data[0])
                response = self._pymodbus_client.write_coil(  # type: ignore[misc]
                    start_address, value, self.unit_id
                )
                if response.isError():
                    return {"error": f"Write single coil error: {response}"}
                return {
                    "function_code": function_code,
                    "address": start_address,
                    "value": value,
                    "success": True,
                    "library": "pymodbus",
                }

            elif function_code == 6:  # Write Single Register
                if not data:
                    return {"error": "Data required for write operation"}
                reg_value = int(data[0])
                response = self._pymodbus_client.write_register(  # type: ignore[misc]
                    start_address, reg_value, self.unit_id
                )
                if response.isError():
                    return {"error": f"Write single register error: {response}"}
                return {
                    "function_code": function_code,
                    "address": start_address,
                    "value": reg_value,
                    "success": True,
                    "library": "pymodbus",
                }

            elif function_code == 15:  # Write Multiple Coils
                if not data:
                    return {"error": "Data required for write operation"}
                values = [bool(x) for x in data[:quantity]]
                response = self._pymodbus_client.write_coils(  # type: ignore[misc]
                    start_address, values, self.unit_id
                )
                if response.isError():
                    return {"error": f"Write multiple coils error: {response}"}
                return {
                    "function_code": function_code,
                    "address": start_address,
                    "count": quantity,
                    "values": values,
                    "success": True,
                    "library": "pymodbus",
                }

            elif function_code == 16:  # Write Multiple Registers
                if not data:
                    return {"error": "Data required for write operation"}
                reg_values = [int(x) for x in data[:quantity]]
                response = self._pymodbus_client.write_registers(  # type: ignore[misc]
                    start_address, reg_values, self.unit_id
                )
                if response.isError():
                    return {"error": f"Write multiple registers error: {response}"}
                return {
                    "function_code": function_code,
                    "address": start_address,
                    "count": quantity,
                    "values": reg_values,
                    "success": True,
                    "library": "pymodbus",
                }

            else:
                logger.warning(f"Unsupported function code {function_code}")
                return {"error": f"Unsupported function code: {function_code}"}

        except Exception as e:
            logger.error(f"pymodbus library request failed: {e}")
            return {"error": f"Library request failed: {str(e)}"}

    # Custom _send_request method removed - now handled by pymodbus library integration

    # Custom _receive_all method removed - now handled by pymodbus library integration

    # Individual read/write methods removed - now handled by send_command() with library integration

    # Convenience Methods
    def send_command(
        self,
        action: str,
        address: int,
        number: int = 1,
        data_registers: Union[str, List[int]] = "",
    ) -> str:
        """
        Send a Modbus command using string action names (backward compatibility).

        Args:
            action: Action name (e.g., "READ_COILS", "WRITE_SINGLE_REGISTER")
            address: Starting address
            number: Number of items
            data_registers: Data as comma-separated string or list of integers

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

        result = self._send_request_library(function_code, address, number, data)
        return json.dumps(result)

    # ===================
    # ATTACK-SPECIFIC METHODS (Custom Implementation)
    # These methods are kept for attack simulation and discovery purposes
    # ===================
    def discover_devices(
        self,
        broadcast_address: str = "255.255.255.255",
        port: int = 502,
        timeout: float = 10.0,
        retries: int = 3,
        wait_between: float = 0.5,
        scan_network: bool = True,
        network_range: str = "192.168.1.0/24",
    ) -> List[Dict[str, Any]]:
        """
        Discover Modbus devices using multiple discovery methods.

        Args:
            broadcast_address: Broadcast address to send to (default: 255.255.255.255)
            port: Port to discover on (default: 502)
            timeout: Total time to wait for responses in seconds
            retries: Number of discovery packets to send
            wait_between: Time between retry packets in seconds
            scan_network: Whether to perform TCP port scanning
            network_range: Network range to scan (CIDR notation)

        Returns:
            List of discovered devices with their information
        """
        logger.info(f"Starting comprehensive Modbus device discovery")
        all_devices = []

        # Method 1: UDP Broadcast Discovery
        logger.info("Phase 1: UDP broadcast discovery")
        udp_devices = self._udp_broadcast_discovery(
            broadcast_address, port, timeout, retries, wait_between
        )
        all_devices.extend(udp_devices)

        # Method 2: TCP Port Scanning (if enabled)
        if scan_network:
            logger.info(f"Phase 2: TCP port scanning on {network_range}")
            tcp_devices = self._tcp_port_scan_discovery(network_range, port)
            all_devices.extend(tcp_devices)

        # Remove duplicates and merge information
        unique_devices = {}
        for device in all_devices:
            ip = device.get("ip")
            if ip and ip not in unique_devices:
                unique_devices[ip] = device
            elif ip in unique_devices:
                # Merge information from multiple discovery methods
                existing = unique_devices[ip]
                for key, value in device.items():
                    if key not in existing or existing[key] in ["Unknown", "N/A"]:
                        existing[key] = value

        final_devices = list(unique_devices.values())
        logger.info(f"Discovery complete. Found {len(final_devices)} unique devices")
        return final_devices

    def _udp_broadcast_discovery(
        self,
        broadcast_address: str,
        port: int,
        timeout: float,
        retries: int,
        wait_between: float,
    ) -> List[Dict[str, Any]]:
        """UDP broadcast discovery method."""
        devices = []

        # Try multiple Modbus packet types for better compatibility
        discovery_packets = [
            self._create_discovery_packet(),  # Device identification
            self._create_simple_read_packet(),  # Simple coil read
            self._create_diagnostic_packet(),  # Diagnostic packet
        ]

        for packet_type, packet in enumerate(discovery_packets):
            logger.debug(f"Trying Modbus discovery packet type {packet_type + 1}")

            sock = self._create_broadcast_socket(port)
            if not sock:
                continue

            try:
                # Send discovery packets
                for retry in range(retries):
                    sock.sendto(packet, (broadcast_address, port))
                    if retry < retries - 1:
                        time.sleep(wait_between)

                # Collect responses with shorter timeout per packet type
                packet_timeout = timeout / len(discovery_packets)
                packet_devices = self._collect_discovery_responses(sock, packet_timeout)
                devices.extend(packet_devices)

            finally:
                sock.close()

        return devices

    def _tcp_port_scan_discovery(
        self, network_range: str, port: int
    ) -> List[Dict[str, Any]]:
        """TCP port scanning discovery method."""
        devices = []

        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = list(network.hosts())

            logger.info(f"Scanning {len(hosts)} hosts for Modbus on port {port}")

            # Use thread pool for concurrent scanning
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_host = {
                    executor.submit(self._test_modbus_tcp, str(host), port): host
                    for host in hosts
                }

                for future in as_completed(future_to_host, timeout=60):
                    host = future_to_host[future]
                    try:
                        result = future.result()
                        if result:
                            devices.append(result)
                            logger.info(f"Found Modbus device via TCP: {result['ip']}")
                    except Exception as e:
                        logger.debug(f"TCP scan failed for {host}: {e}")

        except Exception as e:
            logger.error(f"Network scanning failed: {e}")

        return devices

    def _test_modbus_tcp(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Test if a host has Modbus service on TCP port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)  # Longer timeout for potentially filtered ports
            result = sock.connect_ex((host, port))

            if result == 0:
                # Port is open, try to send a Modbus packet
                try:
                    # Try device identification first
                    test_packet = self._create_discovery_packet()
                    sock.sendall(test_packet)

                    # Try to read response
                    sock.settimeout(2.0)
                    response = sock.recv(1024)

                    if response and len(response) >= 8:  # Valid MBAP response
                        device_info = self._parse_discovery_response(response, host)
                        if device_info:
                            device_info["discovery_method"] = "TCP_SCAN"
                            return device_info

                    # If device ID failed, try simple read
                    simple_packet = self._create_simple_read_packet()
                    sock.sendall(simple_packet)
                    response = sock.recv(1024)

                    if response:
                        return {
                            "ip": host,
                            "port": port,
                            "protocol": "Modbus",
                            "discovery_method": "TCP_SCAN",
                            "status": "responsive",
                            "vendor": "Unknown",
                            "model": "Unknown",
                            "raw_hex": response.hex(),
                        }
                    else:
                        return {
                            "ip": host,
                            "port": port,
                            "protocol": "Modbus",
                            "discovery_method": "TCP_SCAN",
                            "status": "port_open",
                            "vendor": "Unknown",
                            "model": "Unknown",
                            "raw_hex": "N/A",
                        }

                except Exception as e:
                    logger.debug(f"Modbus test failed for {host}: {e}")
                    # Port open but no valid Modbus response
                    return {
                        "ip": host,
                        "port": port,
                        "protocol": "Modbus",
                        "discovery_method": "TCP_SCAN",
                        "status": "port_open_no_response",
                        "vendor": "Unknown",
                        "model": "Unknown",
                        "raw_hex": "N/A",
                    }

            sock.close()
            return None

        except Exception:
            return None

    def auto_connect(
        self,
        broadcast_address: str = "255.255.255.255",
        port: int = 502,
        timeout: float = 10.0,
    ) -> bool:
        """
        Automatically discover devices and connect to the first responsive one.

        Args:
            broadcast_address: Broadcast address to send to (default: 255.255.255.255)
            port: Port to broadcast to (default: 502)
            timeout: Time to wait for discovery responses

        Returns:
            True if connected successfully, False otherwise
        """
        devices = self.discover_devices(broadcast_address, port, timeout)
        if not devices:
            logger.warning("No devices discovered for auto-connect")
            return False

        # Connect to first discovered device
        device = devices[0]
        self.host = device["ip"]
        self.port = port

        try:
            self.connect()
            logger.info(
                f"Auto-connected to {device['ip']} ({device.get('vendor', 'Unknown')})"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to auto-connect to {device['ip']}: {e}")
            return False

    def _create_discovery_packet(self) -> bytes:
        """
        Create a Modbus Read Device Identification packet for UDP broadcast.
        Function 0x2B (Read Device Identification), MEI Type 0x0E, Read Device ID 0x01, Object ID 0x00
        """
        # MBAP header for discovery: Transaction ID=1, Protocol=0, Length=5, Unit=1
        mbap_header = struct.pack(">HHHB", 1, 0, 5, 1)

        # PDU: Function 0x2B, MEI Type 0x0E, Read Device ID 0x01, Object ID 0x00
        pdu = struct.pack(">BBBB", 0x2B, 0x0E, 0x01, 0x00)

        return mbap_header + pdu

    def _create_simple_read_packet(self) -> bytes:
        """Create a simple Modbus read coils packet for discovery."""
        # MBAP header: Transaction ID=2, Protocol=0, Length=6, Unit=1
        mbap_header = struct.pack(">HHHB", 2, 0, 6, 1)
        # PDU: Function 0x01 (Read Coils), Start Address=0, Quantity=1
        pdu = struct.pack(">BHH", 0x01, 0x0000, 0x0001)
        return mbap_header + pdu

    def _create_diagnostic_packet(self) -> bytes:
        """Create a Modbus diagnostic packet for discovery."""
        # MBAP header: Transaction ID=3, Protocol=0, Length=6, Unit=1
        mbap_header = struct.pack(">HHHB", 3, 0, 6, 1)
        # PDU: Function 0x08 (Diagnostics), Sub-function=0x0000 (Return Query Data)
        pdu = struct.pack(">BHH", 0x08, 0x0000, 0x0000)
        return mbap_header + pdu

    def _create_broadcast_socket(self, bind_port: int) -> Optional[socket.socket]:
        """Create and configure a UDP socket for broadcast discovery."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.5)
            # Bind to any available port for sending
            sock.bind(("", 0))
            logger.debug("Created UDP broadcast socket")
            return sock
        except Exception as e:
            logger.error(f"Failed to create broadcast socket: {e}")
            return None

    def _collect_discovery_responses(
        self, sock: socket.socket, timeout: float
    ) -> List[Dict[str, Any]]:
        """Collect and parse discovery responses from the network."""
        devices = []
        seen_addresses = set()
        start_time = time.time()

        logger.info(f"Collecting discovery responses for {timeout} seconds...")

        while time.time() - start_time < timeout:
            try:
                remaining_time = timeout - (time.time() - start_time)
                if remaining_time <= 0:
                    break

                sock.settimeout(min(0.5, remaining_time))
                data, addr = sock.recvfrom(1024)

                # Skip duplicate responses from same IP
                if addr[0] in seen_addresses:
                    continue
                seen_addresses.add(addr[0])

                # Parse the response
                device_info = self._parse_discovery_response(data, addr[0])
                if device_info:
                    devices.append(device_info)
                    logger.info(f"Discovered device: {device_info}")

            except socket.timeout:
                continue
            except Exception as e:
                logger.warning(f"Error receiving discovery response: {e}")
                continue

        return devices

    def _parse_discovery_response(
        self, data: bytes, ip: str
    ) -> Optional[Dict[str, Any]]:
        """Parse a Modbus discovery response and extract device information."""
        try:
            if len(data) < 9:  # Minimum MBAP + function code
                logger.debug(f"Short response from {ip}: {data.hex()}")
                return {
                    "ip": ip,
                    "vendor": "Unknown",
                    "model": "Unknown",
                    "raw_hex": data.hex(),
                }

            # Parse MBAP header
            transaction_id, protocol_id, length, unit_id = struct.unpack(
                ">HHHB", data[:7]
            )

            if len(data) < 7 + length:
                logger.debug(f"Incomplete response from {ip}")
                return {
                    "ip": ip,
                    "vendor": "Unknown",
                    "model": "Unknown",
                    "raw_hex": data.hex(),
                }

            # Check if this is a Read Device Identification response (Function 0x2B)
            if len(data) > 7 and data[7] == 0x2B:
                return self._parse_device_identification(data[7:], ip)
            else:
                # Generic response - just record the device
                logger.debug(f"Generic Modbus response from {ip}")
                return {
                    "ip": ip,
                    "vendor": "Unknown",
                    "model": "Unknown",
                    "raw_hex": data.hex(),
                }

        except Exception as e:
            logger.warning(f"Error parsing discovery response from {ip}: {e}")
            return {
                "ip": ip,
                "vendor": "Error",
                "model": "Parse Failed",
                "raw_hex": data.hex(),
            }

    def _parse_device_identification(self, pdu: bytes, ip: str) -> Dict[str, Any]:
        """Parse Read Device Identification response data."""
        device_info = {
            "ip": ip,
            "vendor": "Unknown",
            "model": "Unknown",
            "serial": "Unknown",
        }

        try:
            if len(pdu) < 6:  # Minimum for device ID response
                return device_info

            # Basic parsing - this is a simplified version
            # Real device ID responses have complex TLV structure
            mei_type = pdu[1] if len(pdu) > 1 else 0
            conformity = pdu[2] if len(pdu) > 2 else 0

            if mei_type == 0x0E:  # Read Device Identification
                # Look for common device identification strings in the response
                response_str = pdu.hex()
                device_info["raw_response"] = response_str

                # Try to extract readable strings (simplified approach)
                try:
                    # Look for ASCII strings in the response
                    ascii_parts = []
                    for i in range(6, len(pdu)):
                        if 32 <= pdu[i] <= 126:  # Printable ASCII
                            ascii_parts.append(chr(pdu[i]))
                        else:
                            if ascii_parts:
                                break

                    if ascii_parts:
                        ascii_str = "".join(ascii_parts)
                        if len(ascii_str) > 2:
                            device_info["vendor"] = ascii_str[:20]  # Limit length

                except Exception:
                    pass

            logger.debug(f"Parsed device identification for {ip}: {device_info}")
            return device_info

        except Exception as e:
            logger.warning(f"Error parsing device identification from {ip}: {e}")
            return device_info

    def __del__(self) -> None:
        """Clean up connection when object is destroyed."""
        self.disconnect()

    def __enter__(self) -> "ModbusClient":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Context manager exit."""
        self.disconnect()

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
    with ModbusClient(host=ip, port=port, unit_id=unit_id) as client:
        return client.send_command(action, address, number, data_registers)
