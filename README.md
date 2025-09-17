# ADCyder Attack Simulator

A framework for simulating various cyber attacks on industrial control systems and SCADA environments. You will need a remote system to use as the target, for which you have SSH access already configured with password or pubkey.

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
    │   │   └── dnp3_client.py
    │   └── modbus/     # Modbus protocol attack modules
    │       ├── ModbusAttack.py
    │       ├── StreamAttack.py
    │       └── modbus_client.py
    ├── historian/      # Data historian components
    │   ├── requirements.txt # Requirements for the historian server 
    │   └── server.py   # gRPC server for data streaming
    └── injector/       # Data injector components
        ├── requirements.txt # Requirements for the injector client 
        └── client.py   # gRPC client for data injection
```

## Attack Types

The simulator supports various attack types:

1. **Watering Hole Attack** - Initial system compromise via SSH and malware execution
2. **Modbus Attacks** - Protocol-specific attacks for Modbus systems:
   - Command injection
   - Denial of service
   - False data injection
   - Information exfiltration
3. **DNP3 Attacks** - Protocol-specific attacks for DNP3 systems
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