"""
settingslocal.template.py: Configuration template for ADCyder Attack Simulator.

This template provides a starting point for local configuration overrides.
Copy this file to 'settingslocal.py' and modify the values according to your environment.

Key Features:
- Target system connection configuration
- Aggregator credentials
- Modbus proxy settings
- Metasploit RPC configuration
- Logging and platform settings

Configuration Categories:
- Network and connection settings
- Authentication credentials
- Attack-specific parameters
- Platform and payload configuration
- Data streaming configuration

Use Cases:
- Local development environment setup
- Production deployment configuration
- Testing environment customization
- CEEESA environment integration
- Security credential management
"""

import logging
from typing import Optional

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================
# Set the logging level for the attack framework
# Options: logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR
LOG_LEVEL = logging.INFO

# =============================================================================
# METASPLOIT RPC CONFIGURATION
# =============================================================================
# Password for Metasploit RPC daemon (msfrpcd)
# Set to a secure password for production environments
MSF_RPC_PASSWORD: Optional[str] = "your_msf_password_here"

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================
# Your local IP address for reverse connections
# This should be the IP that target systems can reach back to
RED_NODE_IP_ADDRESS: Optional[str] = "192.168.1.100"  # Replace with your actual IP

# =============================================================================
# INVERTER SYSTEM CONFIGURATION (Initial Compromise)
# =============================================================================
# Primary target system (inverter) connection details
INVERTER_IP: str = "192.168.1.10"  # Replace with target inverter IP
INVERTER_SSH_USER: Optional[str] = "pi"  # Common username for Raspberry Pi systems
INVERTER_SSH_PASSWORD: Optional[str] = "raspberry"  # Replace with actual password
INVERTER_SSH_USER_KEYFILE: Optional[str] = (
    None  # Path to SSH private key (preferred over password)
)

# =============================================================================
# AGGREGATOR CONFIGURATION (Pivot Target)
# =============================================================================
# Aggregator system for pivot attack
# In CEEESA environment, this is typically the same system handling data collection
AGGREGATOR_IP_ADDRESS: str = "192.168.1.200"  # Replace with aggregator IP
AGGREGATOR_SSH_USER: str = "admin"  # Replace with actual username
AGGREGATOR_SSH_PASSWORD: str = "admin_password"  # Replace with actual password

# =============================================================================
# MODBUS PROXY CONFIGURATION
# =============================================================================
# Port configuration for Modbus traffic interception
MODBUS_PROXY_PORT: int = (
    8502  # Local proxy port (should not conflict with existing services)
)
MODBUS_TARGET_PORT: int = 502  # Standard Modbus TCP port

# =============================================================================
# PLATFORM AND PAYLOAD CONFIGURATION
# =============================================================================
# Target platform architecture for payload generation
# Common options:
#   - "linux/aarch64" for ARM64 systems (AGX, modern Raspberry Pi)
#   - "linux/armle" for ARM little-endian systems
#   - "linux/x64" for 64-bit x86 systems
#   - "linux/x86" for 32-bit x86 systems
INVERTER_PLATFORM: str = "linux/aarch64"

# =============================================================================
# DATA STREAMING CONFIGURATION
# =============================================================================
# Configuration for data injection and streaming
STREAM_SOURCE_DATA_FILE: str = (
    "src/historian/sample_data.csv"  # Path to sample data file
)
STREAM_INTERVAL_MS: int = 1000  # Data streaming interval in milliseconds

# =============================================================================
# SECURITY NOTES
# =============================================================================
# IMPORTANT SECURITY CONSIDERATIONS:
#
# 1. NEVER commit this file with real credentials to version control
# 2. Use strong, unique passwords for all accounts
# 3. Prefer SSH key authentication over passwords when possible
# 4. Ensure target systems are isolated in a test environment
# 5. Regularly rotate credentials used in testing
# 6. Follow your organization's security policies for credential management
#
# For production deployments:
# - Use environment variables for sensitive configuration
# - Implement proper access controls on configuration files
# - Consider using encrypted credential stores
# - Audit and monitor access to attack simulation systems

# =============================================================================
# EXAMPLE CEEESA ENVIRONMENT CONFIGURATION
# =============================================================================
# Uncomment and modify the following section for CEEESA environment:
#
# # CEEESA-specific configuration
# TARGET_IP = "10.0.1.50"  # CEEESA inverter IP
# AGGREGATOR_IP_ADDRESS = "10.0.1.100"  # CEEESA AGX/historian IP
# TARGET_SSH_USER = "ceeesa_user"
# AGGREGATOR_SSH_USER = "agx_admin"
# MY_IP_ADDRESS = "10.0.1.200"  # Your system IP in CEEESA network
#
# # Use environment variables for sensitive data in CEEESA
# import os
# TARGET_SSH_PASSWORD = os.getenv("CEEESA_TARGET_PASSWORD")
# AGGREGATOR_SSH_PASSWORD = os.getenv("CEEESA_AGGREGATOR_PASSWORD")
# MSF_RPC_PASSWORD = os.getenv("MSF_RPC_PASSWORD", "default_password")
