# OPAL-RT Compatibility Guide

## Overview

The DNP3 attack simulator has been updated to support configurable address ranges, enabling compatibility with both the test server and OPAL-RT systems that use different address ranges.

## Problem Background

The original bug report incorrectly claimed the code only supported unsolicited responses (function code 0x82). **This was false**. The code already:
- Sends active read requests (function code 0x01 READ)
- Accepts both solicited (0x81) and unsolicited (0x82) responses
- Implements proper DNP3 Class 0 integrity polling

**The real issue was address range mismatch:**
- Test server uses addresses: 1000-3000
- OPAL-RT uses addresses: 0-35

## Solution

Added configurable address ranges via CLI arguments while maintaining backward compatibility with the test server.

## Configuration Options

### Address Range Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--analog-start` | 1000 | Starting address for analog inputs/outputs |
| `--analog-count` | 2001 | Number of analog addresses available |
| `--binary-start` | 2000 | Starting address for binary inputs/outputs |
| `--binary-count` | 1000 | Number of binary addresses available |
| `--counter-start` | 3000 | Starting address for counter inputs |
| `--counter-count` | 1000 | Number of counter addresses available |

## Usage Examples

### Test Server (Default - No Changes Required)

The defaults match the original hardcoded values, so existing workflows continue to work:

```bash
# Works exactly as before with addresses 1000-3000
python3 src/standalone_dnp3_attack.py --target 192.168.1.100 --attack exfiltration

# Run all attacks against test server
python3 src/standalone_dnp3_attack.py --target 192.168.1.100 --attack all
```

### OPAL-RT (Addresses 0-35)

For OPAL-RT systems, specify the 0-35 address range:

```bash
# Single attack with OPAL-RT configuration
python3 src/standalone_dnp3_attack.py --target 10.1.0.71 --attack exfiltration \
    --analog-start 0 --analog-count 36 \
    --binary-start 0 --binary-count 36 \
    --counter-start 0 --counter-count 36

# All attacks against OPAL-RT
python3 src/standalone_dnp3_attack.py --target 10.1.0.71 --attack all \
    --analog-start 0 --analog-count 36 \
    --binary-start 0 --binary-count 36

# Command injection attack (uses only analog addresses)
python3 src/standalone_dnp3_attack.py --target 10.1.0.71 --attack command_injection \
    --analog-start 0 --analog-count 36

# DoS attack
python3 src/standalone_dnp3_attack.py --target 10.1.0.71 --attack dos \
    --analog-start 0 --analog-count 36 --binary-start 0 --binary-count 36

# False data injection
python3 src/standalone_dnp3_attack.py --target 10.1.0.71 --attack false_data \
    --analog-start 0 --analog-count 36 --binary-start 0 --binary-count 36
```

### Discovery with Custom Addresses

```bash
# Discover OPAL-RT devices then attack with correct address range
python3 src/standalone_dnp3_attack.py --discover --attack exfiltration \
    --analog-start 0 --analog-count 36 \
    --binary-start 0 --binary-count 36
```

## Attack-Specific Behavior

Each attack type uses addresses differently:

### Command Injection Attack
- **Addresses used:** Analog only
- **Original:** 2000, 3000
- **OPAL-RT:** 0, 3 (offset from analog_start)
- **Configuration:** Only requires `--analog-start` and `--analog-count`

### Denial of Service Attack
- **Addresses used:** Analog and Binary
- **Original:** 0 (analog), 0 (binary), 1000 (status)
- **OPAL-RT:** 0 (both)
- **Configuration:** Requires both `--analog-*` and `--binary-*` arguments

### False Data Injection Attack
- **Addresses used:** Analog (voltage) and Binary (tap)
- **Original:** 1000 (analog), 2000 (binary)
- **OPAL-RT:** 0 (both)
- **Configuration:** Requires both `--analog-*` and `--binary-*` arguments

### Information Exfiltration Attack
- **Addresses used:** Analog, Binary, and Counter
- **Original:** 1000 (analog), 2000 (binary), 3000 (counter)
- **OPAL-RT:** 0 (all)
- **Configuration:** Requires all address arguments

## Technical Implementation Details

### AddressConfig Class

The `AddressConfig` dataclass provides:
- Default values matching original hardcoded addresses
- Bounds-checked address retrieval methods
- Automatic clamping of out-of-range addresses with warnings

```python
@dataclass
class AddressConfig:
    analog_start: int = 1000      # Test server default
    analog_count: int = 2001       # Covers 1000-3000 range
    binary_start: int = 2000
    binary_count: int = 1000
    counter_start: int = 3000
    counter_count: int = 1000

    def get_analog_address(self, offset: int = 0) -> int:
        """Get analog address with bounds checking."""
        addr = self.analog_start + offset
        if addr >= self.analog_start + self.analog_count:
            logger.warning(f"Address exceeds range, using {self.analog_start}")
            return self.analog_start
        return addr
```

### Attack Method Updates

All attack methods now use configurable addresses:

```python
# Before (hardcoded)
address=2000

# After (configurable)
address=self.address_config.get_analog_address(0)
```

## OPAL-RT Specific Notes

Based on the OPAL-RT configuration from ISU testing:

1. **Address Range:** 0-35 (36 analog measurements)
2. **DNP3 Configuration:**
   - Object Group: 30 (analog inputs)
   - Variation: 6 (32-bit with flags)
   - Port: 20000 (default)
3. **Single-Master Limitation:** OPAL-RT DNP3 driver allows only one master per slave device
   - To run attack scripts alongside legitimate master, create a second slave device on a different port (e.g., 20001)

## Testing

Run the validation test suite:

```bash
python3 test_address_config.py
```

Expected output:
```
======================================================================
 ADDRESS CONFIGURATION VALIDATION TEST SUITE
======================================================================
✓ Default configuration matches original hardcoded values
✓ OPAL-RT configuration correct
✓ Bounds checking working correctly
✓ Both configuration scenarios work correctly

TEST RESULTS: 4 passed, 0 failed
```

## Migration Guide

### For Existing Test Server Users
**No changes required.** The defaults match the original behavior.

### For OPAL-RT Integration
Add address arguments to your commands:
```bash
--analog-start 0 --analog-count 36 \
--binary-start 0 --binary-count 36 \
--counter-start 0 --counter-count 36
```

### For Custom DNP3 Devices
Specify the address ranges your device uses. The tool will:
- Use specified addresses for all operations
- Warn if operations exceed configured ranges
- Clamp to valid ranges to prevent errors

## Troubleshooting

### "Address exceeds configured range" warnings
This means an attack tried to use an address outside your configured range. The tool automatically uses the start address instead. To fix:
- Increase `--analog-count`, `--binary-count`, or `--counter-count`
- Or adjust the attack to use fewer addresses

### No data returned from OPAL-RT
Verify:
1. Address range is correct (0-35 for OPAL-RT)
2. Port is correct (default 20000)
3. Network connectivity to OPAL-RT device
4. No other master is connected (single-master limitation)

### Connection refused
Check:
1. OPAL-RT is running and network-accessible
2. Port 20000 is not blocked by firewall
3. OPAL-RT DNP3 driver is configured and started

## References

- Original bug report: December 18, 2025 (ISU student analysis)
- OPAL-RT configuration: Souradeep's analysis, December 18, 2025
- DNP3 Protocol Documentation: IEEE 1815-2012
- Test validation: `test_address_config.py`
- OPAL-RT test script: `test_dnp3_opal.py`
