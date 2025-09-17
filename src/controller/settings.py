import logging
from typing import Optional

LOG_LEVEL = logging.WARNING

MSF_RPC_PASSWORD = None

RED_NODE_IP_ADDRESS = None

# Target connection details
INVERTER_IP_ADDRESS: str = "127.0.0.1"
INVERTER_SSH_USER: Optional[str] = None
INVERTER_SSH_PASSWORD: Optional[str] = None  # Will prefer keyfile, if set
INVERTER_SSH_USER_KEYFILE = None

# Historian connection details
AGGREGATOR_IP_ADDRESS: str = "127.0.0.1"
AGGREGATOR_SSH_USER: str = "user"
AGGREGATOR_SSH_PASSWORD: str = "password"

# Modbus proxy details
MODBUS_PROXY_PORT: int = 8502
MODBUS_TARGET_PORT: int = 502

# Modbus traffic capture configuration
MODBUS_TRAFFIC_CAPTURE_DURATION: int = 30  # seconds
MODBUS_TRAFFIC_CAPTURE_MESSAGES: int = 100  # maximum messages to capture

# Modbus polling rate matching configuration
MODBUS_POLLING_RATE_MATCHING_ENABLED: bool = True  # Enable/disable rate matching
MODBUS_DEFAULT_INJECTION_INTERVAL: float = 1.0  # Default injection interval in seconds
MODBUS_MIN_INJECTION_INTERVAL: float = 0.1  # Minimum allowed injection interval
MODBUS_MAX_INJECTION_INTERVAL: float = 10.0  # Maximum allowed injection interval
MODBUS_RATE_DETECTION_TOLERANCE: float = (
    0.2  # Tolerance for regular polling detection (20%)
)
MODBUS_TIMING_ACCURACY_THRESHOLD: float = 0.1  # Acceptable timing deviation (10%)

# aarch64 for AGX Endpoint
# (see: https://www.infosecmatter.com/list-of-metasploit-payloads-detailed-spreadsheet/)
TARGET_PLATFORM: str = "linux/aarch64"

STREAM_SOURCE_DATA_FILE: str = "src/historian/sample_data.csv"
STREAM_INTERVAL_MS: int = 1000

try:
    from controller.settingslocal import *  # type: ignore
except ImportError:
    try:
        from settingslocal import *  # type: ignore
    except ImportError:
        logging.warning(
            "Failed to import settingslocal.py - using default settings. Create settingslocal.py to override defaults."
        )
