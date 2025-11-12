# ADCyder Attack Simulator

A framework for simulating cyber attacks against industrial control systems and SCADA environments. The framework implements TCP-based protocol clients with UDP broadcast discovery capabilities for Modbus and DNP3 systems.

## Requirements

- Make
- Micromamba
- Metasploit

### Installation Instructions

#### Micromamba

```bash
"${SHELL}" <(curl -L micro.mamba.pm/install.sh)
```

Then `source ~/.bashrc` or re-login to update your shell.

#### Metasploit

NOTE: Many antivirus tools will block Metasploit from running, resulting in sigterm (137)-type errors. Make sure you've added any necessary exceptions and/or gotten your admin to do so.

NOTE: Many antivirus tools will block Metasploit from running, resulting in sigterm (137)-type errors. Make sure you've added any necessary exceptions and/or gotten your admin to do so.

```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
```

Then run `msfdb init` to set up the database.

## Project Configuration

Copy variables from [`src/controller/settings.py`](src/controller/settings.py ) to [`src/controller/settingslocal.py`](src/controller/settingslocal.py ) (which you'll need to create) and make any necessary changes.

## Project Structure

```
├── environment-dev.yml  # Development environment configuration
├── environment.yml      # Production environment configuration
├── Makefile            # Build automation and utilities
└── src/                # Source code
    ├── controller/     # Attack controller modules
    │   ├── Attack.py   # Base attack class
    │   ├── WateringHoleAttack.py
    │   ├── dnp3/       # DNP3 protocol attack modules
    │   │   ├── DNP3Attack.py
    │   │   └── dnp3_client.py  # TCP client with UDP discovery
    │   └── modbus/     # Modbus protocol attack modules
    │       ├── ModbusAttack.py
    │       ├── StreamAttack.py
    │       └── modbus_client.py  # TCP client with UDP discovery
    ├── standalone_modbus_attack.py  # Direct Modbus attack tool
    ├── standalone_dnp3_attack.py   # Direct DNP3 attack tool
    ├── historian/      # Data historian components
    │   ├── requirements.txt # Requirements for the historian server
    │   └── server.py   # gRPC server for data streaming
    └── injector/       # Data injector components
        ├── requirements.txt # Requirements for the injector client
        └── client.py   # gRPC client for data injection
```

## Protocol Implementation

### TCP-Based Communication
Both Modbus and DNP3 clients implement persistent TCP connections with proper connection lifecycle management, transaction handling, and error recovery mechanisms.

### UDP Broadcast Discovery
Device discovery functionality uses UDP broadcast to 255.255.255.255 for network-wide device identification:

- **Modbus Discovery**: Uses Read Device Identification (Function 0x2B/0x0E) to extract vendor, model, and device information
- **DNP3 Discovery**: Uses basic DNP3 read requests to identify responsive devices and protocol characteristics

### Standalone Attack Tools
Direct attack execution without infrastructure dependencies:

```bash
# Modbus attacks with device discovery
python3 src/standalone_modbus_attack.py --discover-only
python3 src/standalone_modbus_attack.py --discover --attack dos

# DNP3 attacks with device discovery
python3 src/standalone_dnp3_attack.py --discover-only --discovery-timeout 15.0
python3 src/standalone_dnp3_attack.py --target 192.168.1.100 --attack exfiltration
```

## Client Architecture

### ModbusClient Features
- **TCP Connection Management**: Persistent connections with automatic reconnection
- **Transaction ID Handling**: Proper MBAP header construction with sequential transaction IDs
- **Discovery Methods**: `discover_devices()` and `auto_connect()` for automated device targeting
- **Function Code Support**: Read/write operations for coils, discrete inputs, holding registers, and input registers
- **Context Manager Support**: Resource cleanup with `with` statement usage

### DNP3Client Features
- **TCP Stream Handling**: Reliable message framing and response parsing
- **Discovery Protocol**: UDP-based device identification using basic DNP3 read requests
- **Object Group Support**: Binary inputs, analog inputs, and control outputs
- **CRC Validation**: Message integrity checking for DNP3 frame structure
- **Connection Lifecycle**: Explicit connect/disconnect with error recovery

### Discovery Protocol Details
Device discovery operates independently from normal protocol communication:

1. **UDP Broadcast Phase**: Send identification requests to 255.255.255.255
2. **Response Collection**: Gather responses over configurable timeout period
3. **Device Parsing**: Extract vendor information, device capabilities, and network addresses
4. **TCP Connection**: Establish persistent connections to discovered targets for attack execution

## Attack Types

The simulator implements the following attack vectors:

1. **Watering Hole Attack** - Initial system compromise via SSH and malware execution
2. **Modbus Attacks** - Protocol-specific attacks for Modbus TCP systems:
   - Command injection sequences
   - Denial of service through resource exhaustion
   - False data injection to control registers
   - Information exfiltration from device memory
3. **DNP3 Attacks** - Protocol-specific attacks for DNP3 TCP systems:
   - Binary and analog point manipulation
   - Control sequence injection
   - Data exfiltration from multiple object groups
4. **Data Streaming Attacks** - Attacks targeting historian and data infrastructure

## Building and Testing

### Initialize Development Environment

```bash
make init
```

### Code Quality and Security Checks

```bash
make security-precheck
```

### Build and Check Production Environment

```bash
make build
make security-postcheck
```


### Running Tests

Run specific attack simulations using Make targets:

```bash
make test-wateringhole
make test-dnp
make test-modbus
```

## CI/CD

The project includes GitLab CI/CD configuration in [`.gitlab-ci.yml`](.gitlab-ci.yml) that automatically runs:

- Code formatting checks (`make lint`)
- Strict type checking (`make type-check`) 
- Security scans (`make security`)
- Production build validation (`make build`)

The pipeline runs on both merge requests and main branch pushes.