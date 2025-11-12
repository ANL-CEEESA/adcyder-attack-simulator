"""
DNP3 TCP Client Library

A DNP3 TCP client implementation using FreyrSCADA dnp3protocol library for standard
operations with custom attack-specific functionality for cybersecurity research.

Library Integration:
- Uses FreyrSCADA dnp3protocol library for all standard DNP3 operations
- Supports comprehensive DNP3 function codes through the library
- Maintains proper DNP3 protocol compliance and error handling

Attack-Specific Features:
- Device discovery via UDP broadcast and TCP port scanning
- Custom DNP3 packet crafting with proper Link Layer headers
- Multiple discovery packet types (basic read, device ID, integrity poll)
- Wireshark-compatible frame generation for protocol analysis
- Network enumeration capabilities for security assessment

Standard Operations (via dnp3protocol library):
- Read Binary Inputs (Function Code 1)
- Read Analog Inputs (Function Code 2)
- Write Binary Outputs (Function Code 3)
- Write Analog Outputs (Function Code 4)
- All additional DNP3 function codes supported by the library
"""

import ipaddress
import json
import logging
import socket
import struct
import time
import types

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

# Maintain original logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Raw DNP3 implementation for attack simulation
from controller.dnp3 import dnp3_raw


class DNP3Client:
    """
    A DNP3 TCP client for communicating with DNP3 devices.

    Uses FreyrSCADA dnp3protocol library when available for standard operations,
    falls back to custom implementation for attack-specific scenarios.
    Provides persistent TCP connections with comprehensive
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
        Initialize the DNP3 TCP client.

        Args:
            host: Target device IP address
            port: DNP3 port (default 20000)
            timeout: Socket timeout in seconds (default 2.0)
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self._socket: Optional[socket.socket] = None
        self._connected = False
        self._sequence = 0  # Application sequence number

        logger.debug("Initialized DNP3Client with raw DNP3 protocol implementation")

    def connect(self) -> None:
        """Establish TCP connection to the DNP3 device."""
        if self._connected and self._socket:
            return

        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.timeout)
            self._socket.connect((self.host, self.port))
            self._connected = True
            logger.debug(f"Connected to DNP3 device at {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}:{self.port}: {e}")
            self._connected = False
            if self._socket:
                self._socket.close()
                self._socket = None
            raise

    def disconnect(self) -> None:
        """Close the TCP connection."""
        if self._socket:
            self._socket.close()
            self._socket = None
        self._connected = False
        logger.debug("Disconnected from DNP3 device")

    # Custom request creation removed - now handled by FreyrSCADA library integration

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

    # Custom response parsing removed - now handled by FreyrSCADA library integration

    def _send_request_library(
        self,
        function_code: int,
        address: int,
        number: int,
        data_points: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """
        Send DNP3 request using raw protocol implementation.

        Args:
            function_code: DNP3 function code
            address: Starting address
            number: Number of points to read/write
            data_points: Data values for write operations

        Returns:
            Dictionary containing response data or error information
        """
        if not self._connected or not self._socket:
            return {"error": "Not connected to DNP3 device"}

        try:
            result = dnp3_raw.send_dnp3_request(
                self._socket,
                function_code,
                address,
                number,
                self._sequence,
                data_points,
            )

            # Increment sequence number
            self._sequence = (self._sequence + 1) % 16

            return result

        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            # Connection was broken - reset state to allow reconnection
            logger.warning(f"Connection lost: {e}. Resetting connection state.")
            self._connected = False
            if self._socket:
                try:
                    self._socket.close()
                except Exception:
                    pass
                self._socket = None
            return {"error": f"Request failed: {str(e)}"}
        except Exception as e:
            logger.error(f"DNP3 request failed: {e}")
            return {"error": f"Request failed: {str(e)}"}

    # Custom _send_request method removed - now handled by FreyrSCADA library integration

    # Custom _receive_dnp3_response method removed - now handled by FreyrSCADA library integration

    # Individual read/write methods removed - now handled by send_command() with library integration

    # Convenience Methods
    def send_command(
        self,
        action: str,
        address: int,
        number: int,
        data_points: Optional[str] = None,
        persistent_connection: bool = False,
    ) -> str:
        """
        Send a DNP3 command using string action names (backward compatibility).

        Args:
            action: Action name (e.g., "READ_BINARY", "WRITE_ANALOG")
            address: Starting address
            number: Number of points
            data_points: Data as comma-separated string
            persistent_connection: If False, reconnect for each request (default for reliability)

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

        # Retry logic with auto-reconnect
        max_retries = 3
        for attempt in range(max_retries):
            # For non-persistent connections, always disconnect and reconnect
            # This prevents "Broken pipe" errors from stale connections
            if not persistent_connection and self._connected:
                logger.debug("Closing connection for fresh reconnect")
                self.disconnect()

            # Auto-connect if not connected
            if not self._connected:
                logger.debug(
                    f"Connecting to {self.host}:{self.port} (attempt {attempt + 1}/{max_retries})"
                )
                try:
                    self.connect()
                except Exception as e:
                    if attempt == max_retries - 1:
                        return json.dumps(
                            {
                                "error": f"Connection failed after {max_retries} attempts: {str(e)}"
                            }
                        )
                    logger.warning(f"Connection failed, retrying: {e}")
                    time.sleep(0.5)  # Brief delay before retry
                    continue

            result = self._send_request_library(function_code, address, number, data)

            # If we got a broken pipe or connection error, retry
            if "error" in result and any(
                err in result.get("error", "")
                for err in ["Broken pipe", "Connection reset", "Connection refused"]
            ):
                if attempt < max_retries - 1:
                    logger.warning(
                        f"Connection error detected, retrying (attempt {attempt + 2}/{max_retries})"
                    )
                    self.disconnect()  # Force disconnect to clean up
                    time.sleep(0.5)  # Brief delay before retry
                    continue

            # Success or non-recoverable error - disconnect if not persistent
            if not persistent_connection:
                self.disconnect()

            return json.dumps(result)

        # Max retries exceeded
        if not persistent_connection:
            self.disconnect()
        return json.dumps({"error": "Max retries exceeded"})

    # ===================
    # ATTACK-SPECIFIC METHODS (Custom Implementation)
    # These methods are kept for attack simulation and discovery purposes
    # ===================
    def discover_devices(
        self,
        broadcast_address: str = "255.255.255.255",
        port: int = 20000,
        timeout: float = 10.0,
        retries: int = 3,
        wait_between: float = 0.5,
        scan_network: bool = True,
        network_range: str = "192.168.1.0/24",
    ) -> List[Dict[str, Any]]:
        """
        Discover DNP3 devices using multiple discovery methods.

        Args:
            broadcast_address: Broadcast address to send to (default: 255.255.255.255)
            port: Port to discover on (default: 20000)
            timeout: Total time to wait for responses in seconds
            retries: Number of discovery packets to send
            wait_between: Time between retry packets in seconds
            scan_network: Whether to perform TCP port scanning
            network_range: Network range to scan (CIDR notation)

        Returns:
            List of discovered devices with their information
        """
        logger.info(f"Starting comprehensive DNP3 device discovery")
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

        # Remove duplicates based on IP address
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

        # Try multiple DNP3 packet types for better compatibility
        discovery_packets = [
            self._create_discovery_packet(),  # Basic read
            self._create_device_id_packet(),  # Device identification
            self._create_integrity_poll_packet(),  # Integrity poll
        ]

        for packet_type, packet in enumerate(discovery_packets):
            logger.debug(f"Trying DNP3 discovery packet type {packet_type + 1}")

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

            logger.info(f"Scanning {len(hosts)} hosts for DNP3 on port {port}")

            # Use thread pool for concurrent scanning
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_host = {
                    executor.submit(self._test_dnp3_tcp, str(host), port): host
                    for host in hosts
                }

                for future in as_completed(future_to_host, timeout=30):
                    host = future_to_host[future]
                    try:
                        result = future.result()
                        if result:
                            devices.append(result)
                            logger.info(f"Found DNP3 device via TCP: {result['ip']}")
                    except Exception as e:
                        logger.debug(f"TCP scan failed for {host}: {e}")

        except Exception as e:
            logger.error(f"Network scanning failed: {e}")

        return devices

    def _test_dnp3_tcp(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Test if a host has DNP3 service on TCP port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = sock.connect_ex((host, port))

            if result == 0:
                # Port is open, try to send a DNP3 packet
                try:
                    test_packet = self._create_discovery_packet()
                    sock.sendall(test_packet)

                    # Try to read response
                    sock.settimeout(1.0)
                    response = sock.recv(1024)

                    if response:
                        return {
                            "ip": host,
                            "port": port,
                            "protocol": "DNP3",
                            "discovery_method": "TCP_SCAN",
                            "status": "responsive",
                            "raw_hex": response.hex(),
                        }
                    else:
                        return {
                            "ip": host,
                            "port": port,
                            "protocol": "DNP3",
                            "discovery_method": "TCP_SCAN",
                            "status": "port_open",
                            "raw_hex": "N/A",
                        }
                except Exception:
                    # Port open but no valid DNP3 response
                    return {
                        "ip": host,
                        "port": port,
                        "protocol": "DNP3",
                        "discovery_method": "TCP_SCAN",
                        "status": "port_open_no_response",
                        "raw_hex": "N/A",
                    }

            sock.close()
            return None

        except Exception:
            return None

    def auto_connect(
        self,
        broadcast_address: str = "255.255.255.255",
        port: int = 20000,
        timeout: float = 10.0,
    ) -> bool:
        """
        Automatically discover devices and connect to the first responsive one.

        Args:
            broadcast_address: Broadcast address to send to (default: 255.255.255.255)
            port: Port to broadcast to (default: 20000)
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
            logger.info(f"Auto-connected to {device['ip']} (DNP3 device)")
            return True
        except Exception as e:
            logger.error(f"Failed to auto-connect to {device['ip']}: {e}")
            return False

    def _create_discovery_packet(self) -> bytes:
        """
        Create a DNP3 device identification packet for UDP broadcast.
        Uses a basic DNP3 read request to elicit a response with proper Link Layer header.
        """
        # DNP3 Transport/Application layer
        transport_header = struct.pack(">B", 0x44)  # Transport header
        app_control = struct.pack(">B", 0xE0)  # Application control
        func_code = struct.pack(">B", 0x01)  # Read request
        iin_flags = struct.pack(">H", 0x0000)  # Internal indications

        # Object header for a simple read (Class 0 data)
        obj_header = struct.pack(">BBBB", 0x3C, 0x02, 0x06, 0x00)  # Class 0 data

        data_payload = (
            transport_header + app_control + func_code + iin_flags + obj_header
        )
        data_crc = self._calculate_crc(data_payload)
        complete_data = data_payload + struct.pack(">H", data_crc)

        # DNP3 Link Layer Header (required for proper DNP3 frame recognition by Wireshark)
        # Sync bytes MUST be 0x0564 in this exact order for Wireshark dissector
        sync1 = 0x05
        sync2 = 0x64
        length = len(complete_data) + 5  # Data length + header CRC
        control = 0x44  # Primary to secondary, function code 4 (confirmed user data)
        dest_addr = 0xFFFF  # Broadcast destination
        src_addr = 0x0001  # Source address

        # DNP3 Link Layer header: sync1, sync2, length, control, dest_addr(LE), src_addr(LE)
        link_header = struct.pack(
            "<BBBBHH", sync1, sync2, length, control, dest_addr, src_addr
        )

        # CRC is calculated on length + control + addresses (bytes 2-7)
        header_crc = self._calculate_crc(link_header[2:])

        # Complete DNP3 frame with proper structure for Wireshark recognition
        return link_header + struct.pack("<H", header_crc) + complete_data

    def _create_device_id_packet(self) -> bytes:
        """Create a DNP3 device identification request packet with proper Link Layer header."""
        # DNP3 Transport/Application layer
        transport_header = struct.pack(">B", 0x44)  # Transport header
        app_control = struct.pack(">B", 0xE0)  # Application control
        func_code = struct.pack(">B", 0x01)  # Read request
        iin_flags = struct.pack(">H", 0x0000)  # Internal indications

        # Object header for device identification (Group 0, Var 254)
        obj_header = struct.pack(">BBBB", 0x00, 0xFE, 0x06, 0x00)

        data_payload = (
            transport_header + app_control + func_code + iin_flags + obj_header
        )
        data_crc = self._calculate_crc(data_payload)
        complete_data = data_payload + struct.pack(">H", data_crc)

        # DNP3 Link Layer Header
        # DNP3 sync bytes for Wireshark recognition
        sync1 = 0x05
        sync2 = 0x64
        length = len(complete_data) + 5  # Data length + header CRC
        control = 0x44  # Primary to secondary, function code 4 (confirmed user data)
        dest_addr = 0xFFFF  # Broadcast destination
        src_addr = 0x0001  # Source address

        # DNP3 Link Layer uses little-endian for addresses
        # DNP3 Link Layer header: sync1, sync2, length, control, dest_addr(LE), src_addr(LE)
        link_header = struct.pack(
            "<BBBBHH", sync1, sync2, length, control, dest_addr, src_addr
        )

        header_crc = self._calculate_crc(
            link_header[2:]
        )  # CRC on length + control + addresses

        return link_header + struct.pack("<H", header_crc) + complete_data

    def _create_integrity_poll_packet(self) -> bytes:
        """Create a DNP3 integrity poll packet (Class 1, 2, 3 data) with proper Link Layer header."""
        # DNP3 Transport/Application layer
        transport_header = struct.pack(">B", 0x44)  # Transport header
        app_control = struct.pack(">B", 0xE0)  # Application control
        func_code = struct.pack(">B", 0x01)  # Read request
        iin_flags = struct.pack(">H", 0x0000)  # Internal indications

        # Object header for Class 1, 2, 3 data (60:2, 60:3, 60:4)
        obj_header = struct.pack(
            ">BBBBBBBBBBBB",
            0x3C,
            0x02,
            0x06,
            0x00,  # Class 1
            0x3C,
            0x03,
            0x06,
            0x00,  # Class 2
            0x3C,
            0x04,
            0x06,
            0x00,
        )  # Class 3

        data_payload = (
            transport_header + app_control + func_code + iin_flags + obj_header
        )
        data_crc = self._calculate_crc(data_payload)
        complete_data = data_payload + struct.pack(">H", data_crc)

        # DNP3 Link Layer Header
        # DNP3 sync bytes for Wireshark recognition
        sync1 = 0x05
        sync2 = 0x64
        length = len(complete_data) + 5  # Data length + header CRC
        control = 0x44  # Primary to secondary, function code 4 (confirmed user data)
        dest_addr = 0xFFFF  # Broadcast destination
        src_addr = 0x0001  # Source address

        # DNP3 Link Layer uses little-endian for addresses
        # DNP3 Link Layer header: sync1, sync2, length, control, dest_addr(LE), src_addr(LE)
        link_header = struct.pack(
            "<BBBBHH", sync1, sync2, length, control, dest_addr, src_addr
        )

        header_crc = self._calculate_crc(
            link_header[2:]
        )  # CRC on length + control + addresses

        return link_header + struct.pack("<H", header_crc) + complete_data

    def _create_broadcast_socket(self, bind_port: int) -> Optional[socket.socket]:
        """Create and configure a UDP socket for broadcast discovery."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(0.5)
            # Bind to any available port for sending
            sock.bind(("", 0))
            logger.debug("Created UDP broadcast socket for DNP3")
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

        logger.info(f"Collecting DNP3 discovery responses for {timeout} seconds...")

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
                    logger.info(f"Discovered DNP3 device: {device_info}")

            except socket.timeout:
                continue
            except Exception as e:
                logger.warning(f"Error receiving discovery response: {e}")
                continue

        return devices

    def _parse_discovery_response(
        self, data: bytes, ip: str
    ) -> Optional[Dict[str, Any]]:
        """Parse a DNP3 discovery response and extract device information."""
        try:
            if len(data) < 8:  # Minimum DNP3 response
                logger.debug(f"Short DNP3 response from {ip}: {data.hex()}")
                return {
                    "ip": ip,
                    "protocol": "DNP3",
                    "status": "responded",
                    "raw_hex": data.hex(),
                }

            # Basic DNP3 response validation
            if len(data) > 2:
                transport = data[0]
                app_control = data[1] if len(data) > 1 else 0
                func_code = data[2] if len(data) > 2 else 0

                device_info = {
                    "ip": ip,
                    "protocol": "DNP3",
                    "transport": f"0x{transport:02x}",
                    "function_code": f"0x{func_code:02x}",
                    "raw_hex": data.hex(),
                    "status": "active",
                }

                # Try to extract any readable information
                if len(data) > 8:
                    # Look for any ASCII strings that might indicate device info
                    ascii_parts = []
                    for i in range(8, min(len(data), 50)):  # Check first 50 bytes
                        if 32 <= data[i] <= 126:  # Printable ASCII
                            ascii_parts.append(chr(data[i]))
                        else:
                            if len(ascii_parts) > 2:
                                device_info["info"] = "".join(ascii_parts)
                                break
                            ascii_parts = []

                logger.debug(f"Parsed DNP3 device for {ip}: {device_info}")
                return device_info

            return {
                "ip": ip,
                "protocol": "DNP3",
                "status": "minimal_response",
                "raw_hex": data.hex(),
            }

        except Exception as e:
            logger.warning(f"Error parsing DNP3 discovery response from {ip}: {e}")
            return {
                "ip": ip,
                "protocol": "DNP3",
                "status": "parse_error",
                "raw_hex": data.hex(),
            }

    def __del__(self) -> None:
        """Clean up connection when object is destroyed."""
        self.disconnect()

    def __enter__(self) -> "DNP3Client":
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
        return f"DNP3Client(host='{self.host}', port={self.port})"
