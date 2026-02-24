#!/usr/bin/env python3
from api_client import api

print("🌙 Testing Nightfall API Integration...")

# Test 1: Create target
print("\n1. Creating target...")
target = api.create_target("test-integration.com")
print(f"   ✅ Target created: {target}")

# Test 2: Create scan
print("\n2. Creating scan...")
scan = api.create_scan("test-integration.com")
print(f"   ✅ Scan created: {scan}")

# Test 3: Send mock finding
print("\n3. Sending mock finding...")
scan_id = scan.get('id', 1)
api.send_finding(scan_id, {
    'severity': 'High',
    'category': 'Headers',
    'finding': 'Missing Content-Security-Policy header',
    'remediation': 'Implement CSP header'
})

print("\n✅ Integration test complete!")
