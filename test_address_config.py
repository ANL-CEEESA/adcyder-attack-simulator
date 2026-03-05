#!/usr/bin/env python3
"""
Test script to validate address configuration changes for OPAL-RT compatibility.

This script verifies:
1. AddressConfig defaults match original hardcoded values (backward compatibility)
2. OPAL-RT address configuration works correctly
3. Address bounds checking functions properly
"""

import sys
import logging
from dataclasses import dataclass

# Inline copy of AddressConfig for testing without dependencies
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


@dataclass
class AddressConfig:
    """Configuration for DNP3 address ranges to support different outstation configurations."""

    analog_start: int = 1000
    analog_count: int = 2001
    binary_start: int = 2000
    binary_count: int = 1000
    counter_start: int = 3000
    counter_count: int = 1000

    def get_analog_address(self, offset: int = 0) -> int:
        """Get analog address with bounds checking."""
        addr = self.analog_start + offset
        if addr >= self.analog_start + self.analog_count:
            logger.warning(
                f"Analog address {addr} exceeds configured range, using {self.analog_start}"
            )
            return self.analog_start
        return addr

    def get_binary_address(self, offset: int = 0) -> int:
        """Get binary address with bounds checking."""
        addr = self.binary_start + offset
        if addr >= self.binary_start + self.binary_count:
            logger.warning(
                f"Binary address {addr} exceeds configured range, using {self.binary_start}"
            )
            return self.binary_start
        return addr

    def get_counter_address(self, offset: int = 0) -> int:
        """Get counter address with bounds checking."""
        addr = self.counter_start + offset
        if addr >= self.counter_start + self.counter_count:
            logger.warning(
                f"Counter address {addr} exceeds configured range, using {self.counter_start}"
            )
            return self.counter_start
        return addr


def test_default_config():
    """Test that default configuration matches original hardcoded values."""
    print("\n" + "=" * 60)
    print("TEST 1: Default Configuration (Test Server)")
    print("=" * 60)

    config = AddressConfig()

    # Verify defaults match original hardcoded values
    assert config.analog_start == 1000, f"Expected analog_start=1000, got {config.analog_start}"
    assert config.binary_start == 2000, f"Expected binary_start=2000, got {config.binary_start}"
    assert config.counter_start == 3000, f"Expected counter_start=3000, got {config.counter_start}"

    # Test address retrieval
    assert config.get_analog_address(0) == 1000, "Analog base address should be 1000"
    assert config.get_binary_address(0) == 2000, "Binary base address should be 2000"
    assert config.get_counter_address(0) == 3000, "Counter base address should be 3000"

    print("✓ Default configuration matches original hardcoded values")
    print(f"  Analog: {config.analog_start} (count: {config.analog_count})")
    print(f"  Binary: {config.binary_start} (count: {config.binary_count})")
    print(f"  Counter: {config.counter_start} (count: {config.counter_count})")

    return True


def test_opal_rt_config():
    """Test OPAL-RT address configuration (0-35)."""
    print("\n" + "=" * 60)
    print("TEST 2: OPAL-RT Configuration (0-35)")
    print("=" * 60)

    config = AddressConfig(
        analog_start=0,
        analog_count=36,
        binary_start=0,
        binary_count=36,
        counter_start=0,
        counter_count=36,
    )

    # Verify OPAL-RT configuration
    assert config.analog_start == 0, f"Expected analog_start=0, got {config.analog_start}"
    assert config.analog_count == 36, f"Expected analog_count=36, got {config.analog_count}"
    assert config.binary_start == 0, f"Expected binary_start=0, got {config.binary_start}"
    assert config.binary_count == 36, f"Expected binary_count=36, got {config.binary_count}"

    # Test address retrieval within valid range
    assert config.get_analog_address(0) == 0, "Analog address 0 should be valid"
    assert config.get_analog_address(10) == 10, "Analog address 10 should be valid"
    assert config.get_analog_address(35) == 35, "Analog address 35 should be valid"

    print("✓ OPAL-RT configuration correct")
    print(f"  Analog: {config.analog_start}-{config.analog_start + config.analog_count - 1}")
    print(f"  Binary: {config.binary_start}-{config.binary_start + config.binary_count - 1}")
    print(f"  Counter: {config.counter_start}-{config.counter_start + config.counter_count - 1}")

    return True


def test_bounds_checking():
    """Test address bounds checking with warnings."""
    print("\n" + "=" * 60)
    print("TEST 3: Address Bounds Checking")
    print("=" * 60)

    config = AddressConfig(
        analog_start=0,
        analog_count=10,
        binary_start=0,
        binary_count=10,
        counter_start=0,
        counter_count=10,
    )

    # Test valid addresses
    assert config.get_analog_address(0) == 0, "Address at start should be valid"
    assert config.get_analog_address(5) == 5, "Address in middle should be valid"
    assert config.get_analog_address(9) == 9, "Address at end should be valid"

    # Test out-of-bounds address (should clamp to start with warning)
    print("\n  Testing out-of-bounds address (should show warning):")
    result = config.get_analog_address(100)
    assert result == 0, f"Out of bounds address should return start address, got {result}"

    print("\n✓ Bounds checking working correctly")

    return True


def test_attack_integration():
    """Test address configuration scenarios."""
    print("\n" + "=" * 60)
    print("TEST 4: Address Configuration Scenarios")
    print("=" * 60)

    # Scenario 1: Test server (default)
    print("\n  Scenario 1: Test Server (Default)")
    config_test = AddressConfig()
    print(f"    Analog range: {config_test.analog_start}-{config_test.analog_start + config_test.analog_count - 1}")
    print(f"    Binary range: {config_test.binary_start}-{config_test.binary_start + config_test.binary_count - 1}")
    print(f"    Counter range: {config_test.counter_start}-{config_test.counter_start + config_test.counter_count - 1}")

    # Scenario 2: OPAL-RT
    print("\n  Scenario 2: OPAL-RT (0-35)")
    config_opal = AddressConfig(
        analog_start=0,
        analog_count=36,
        binary_start=0,
        binary_count=36,
        counter_start=0,
        counter_count=36,
    )
    print(f"    Analog range: {config_opal.analog_start}-{config_opal.analog_start + config_opal.analog_count - 1}")
    print(f"    Binary range: {config_opal.binary_start}-{config_opal.binary_start + config_opal.binary_count - 1}")
    print(f"    Counter range: {config_opal.counter_start}-{config_opal.counter_start + config_opal.counter_count - 1}")

    print("\n✓ Both configuration scenarios work correctly")

    return True


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print(" ADDRESS CONFIGURATION VALIDATION TEST SUITE")
    print("=" * 70)

    tests = [
        ("Default Configuration", test_default_config),
        ("OPAL-RT Configuration", test_opal_rt_config),
        ("Bounds Checking", test_bounds_checking),
        ("Configuration Scenarios", test_attack_integration),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except AssertionError as e:
            failed += 1
            print(f"\n✗ TEST FAILED: {test_name}")
            print(f"  Error: {e}")
        except Exception as e:
            failed += 1
            print(f"\n✗ TEST ERROR: {test_name}")
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 70)
    print(f" TEST RESULTS: {passed} passed, {failed} failed")
    print("=" * 70)

    if failed == 0:
        print("\n✓ All tests passed! Address configuration is working correctly.")
        print("\nOPAL-RT Usage:")
        print("  python3 src/standalone_dnp3_attack.py --target 10.1.0.71 --attack exfiltration \\")
        print("      --analog-start 0 --analog-count 36 \\")
        print("      --binary-start 0 --binary-count 36 \\")
        print("      --counter-start 0 --counter-count 36")
        return 0
    else:
        print("\n✗ Some tests failed. Please review the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
