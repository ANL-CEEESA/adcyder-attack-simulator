#!/usr/bin/env python3
"""
Test script for DNP3 communication with OPAL-RT

Configuration from Kebei:
- Target IP: 10.1.0.71 (OPAL-RT)
- Port: 20000
- Object Group: 30 (analog)
- Variation: 6 (32-bit with flags)
- Address: starting from 0
- Count: 36 analog measurements
"""

import sys
import json
from controller.dnp3.dnp3_client import DNP3Client

def main():
    print("=" * 60)
    print("DNP3 OPAL-RT Test - Information Exfiltration Attack")
    print("=" * 60)
    
    # OPAL-RT configuration
    target_ip = "10.1.0.71"
    port = 20000
    
    print(f"\nTarget: {target_ip}:{port}")
    print("Reading 36 analog measurements (Group 30, Variation 6)")
    print("-" * 60)
    
    # Create client and connect
    client = DNP3Client(host=target_ip, port=port, timeout=5.0)
    
    try:
        print("\n[1] Connecting to OPAL-RT...")
        client.connect()
        print("✓ Connected successfully")
        
        print("\n[2] Sending DNP3 READ request...")
        print("    Function Code: 0x01 (READ)")
        print("    Group: 30 (Analog Inputs)")
        print("    Variation: 6 (32-bit with flags)")
        print("    Start Address: 0")
        print("    Count: 36")
        
        # Send READ_ANALOG command
        result_json = client.send_command(
            action="READ_ANALOG",
            address=0,
            number=36
        )
        
        result = json.loads(result_json)
        
        print("\n[3] Response received:")
        print("-" * 60)
        
        if "error" in result:
            print(f"✗ Error: {result['error']}")
            return 1
        
        # Display results
        print(f"Function Code: {result.get('function_code', 'N/A')}")
        print(f"IIN Flags: {result.get('iin_flags', 'N/A')}")
        
        if "values" in result:
            values = result["values"]
            count = len(values)
            print(f"\n✓ Successfully extracted {count} analog values:")
            print("-" * 60)
            
            # Display values in a formatted table
            for i, value in enumerate(values):
                print(f"  Point {i:2d}: {value:10d}")
                
            print("-" * 60)
            print(f"\nTotal measurements extracted: {count}")
            
            if count == 36:
                print("✓ All 36 measurements successfully retrieved!")
            else:
                print(f"⚠ Expected 36 measurements, got {count}")
        else:
            print("✗ No values in response")
            print(f"Full response: {json.dumps(result, indent=2)}")
        
        print("\n" + "=" * 60)
        print("Test completed successfully")
        print("=" * 60)
        
        return 0
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    finally:
        client.disconnect()
        print("\nDisconnected from OPAL-RT")

if __name__ == "__main__":
    sys.exit(main())