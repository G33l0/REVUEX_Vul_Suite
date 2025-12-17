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
        print(f"[!] CAUTION: Testing price manipulation on {self.endpoint}")
        print(f"[!] Using {self.delay}s safety delay")
        
        vulnerabilities = []
        
        # Test 1: Negative prices
        print("→ Test 1: Negative price values")
        negative_result = self._test_negative_prices()
        if negative_result.get('vulnerable'):
            vuln = self._create_negative_price_vulnerability(negative_result)
            vulnerabilities.append(vuln)
        
        time.sleep(self.delay)
        
        # Test 2: Zero prices
        print("→ Test 2: Zero price values")
        zero_result = self._test_zero_prices()
        if zero_result.get('vulnerable'):
            vuln = self._create_zero_price_vulnerability(zero_result)
            vulnerabilities.append(vuln)
        
        time.sleep(self.delay)
        
        # Test 3: Decimal precision
        print("→ Test 3: Decimal precision abuse")
        decimal_result = self._test_decimal_precision()
        if decimal_result.get('vulnerable'):
            vuln = self._create_decimal_vulnerability(decimal_result)
            vulnerabilities.append(vuln)
        
        time.sleep(self.delay)
        
        # Test 4: Parameter tampering
        print("→ Test 4: Parameter tampering")
        tampering_result = self._test_parameter_tampering()
        if tampering_result.get('vulnerable'):
            vuln = self._create_tampering_vulnerability(tampering_result)
            vulnerabilities.append(vuln)
        
        time.sleep(self.delay)
        
        # Test 5: Currency manipulation
        print("→ Test 5: Currency manipulation")
        currency_result = self._test_currency_manipulation()
        if currency_result.get('vulnerable'):
            vuln = self._create_currency_vulnerability(currency_result)
            vulnerabilities.append(vuln)
        
        # Save results
        self._save_results(vulnerabilities)
        
        return vulnerabilities

    # ---------------- Vulnerability Report Methods ---------------- #

    def _create_negative_price_vulnerability(self, result):
        sample_test = result['tests'][0] if result['tests'] else {}
        
        return {
            'type': 'Price Manipulation - Negative Prices',
            'severity': 'critical',
            'endpoint': self.endpoint,
            'description': 'E-commerce endpoint accepts negative price values, allowing attackers to receive money instead of paying for products',
            'evidence': f'Negative price accepted: {result.get("evidence")}',
            'steps_to_reproduce': [
                f"Navigate to e-commerce checkout at {self.endpoint}",
                "Add product to cart",
                "Intercept request and modify price parameter to negative value",
                "Submit the modified request",
                "Observe order confirmed with negative total"
            ],
            'before_state': 'Customer pays normal price',
            'after_state': 'Customer receives money for "purchasing" product',
            'remediation': [
                'Server-side price validation',
                'Reject negative price values',
                'Recalculate totals server-side'
            ],
            'tags': ['ecommerce', 'critical', 'price_manipulation', 'financial_loss']
        }

    def _create_zero_price_vulnerability(self, result):
        return {
            'type': 'Price Manipulation - Zero Price',
            'severity': 'critical',
            'endpoint': self.endpoint,
            'description': 'Endpoint accepts zero-price orders, allowing free product acquisition',
            'evidence': f'Zero price accepted: {result.get("evidence")}',
            'before_state': 'Product costs > $0',
            'after_state': 'Product acquired for $0',
            'remediation': [
                'Reject zero prices for non-free items',
                'Validate price > 0 server-side'
            ],
            'tags': ['ecommerce', 'critical', 'price_manipulation']
        }

    def _create_decimal_vulnerability(self, result):
        return {
            'type': 'Price Manipulation - Decimal Precision',
            'severity': 'high',
            'endpoint': self.endpoint,
            'description': 'Endpoint accepts fractional cent prices causing rounding errors',
            'evidence': f'Tiny prices accepted: {result.get("evidence")}',
            'before_state': 'Proper rounding expected',
            'after_state': 'Fractional cents allowed, potential free items',
            'remediation': [
                'Enforce minimum price of $0.01',
                'Reject sub-cent pricing',
                'Use proper decimal types'
            ],
            'tags': ['ecommerce', 'price_manipulation', 'rounding']
        }

    def _create_tampering_vulnerability(self, result):
        return {
            'type': 'Price Manipulation - Parameter Tampering',
            'severity': 'critical',
            'endpoint': self.endpoint,
            'description': 'Server trusts client-supplied total instead of calculating server-side',
            'evidence': f'Tampering accepted: {result.get("evidence")}',
            'before_state': 'Client cannot manipulate total',
            'after_state': 'Client can modify total to arbitrary value',
            'remediation': [
                'Recalculate totals server-side',
                'Never trust client-supplied totals'
            ],
            'tags': ['ecommerce', 'critical', 'tampering']
        }

    def _create_currency_vulnerability(self, result):
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

    # ---------------- Test Methods ---------------- #

    def _test_negative_prices(self):
        results = {'vulnerable': False, 'method': 'negative_prices', 'tests': []}
        for price in self.test_cases['negative_price']['payloads']:
            try:
                payload = {'price': price, 'amount': price, 'total': price, 'item_id': 'test_item', 'quantity': 1}
                response = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=10, verify=False)
                accepted = response.status_code in [200, 201, 202]
                test_result = {'price': price, 'status_code': response.status_code, 'accepted': accepted}
                results['tests'].append(test_result)
                if accepted:
                    results['vulnerable'] = True
                    results['evidence'] = f'Negative price {price} was accepted'
                time.sleep(0.5)
            except Exception as e:
                results['tests'].append({'price': price, 'error': str(e)})
        return results

    def _test_zero_prices(self):
        results = {'vulnerable': False, 'method': 'zero_prices', 'tests': []}
        for price in self.test_cases['zero_price']['payloads']:
            try:
                payload = {'price': price, 'total': price, 'item_id': 'test_item', 'quantity': 1}
                response = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=10, verify=False)
                accepted = response.status_code in [200, 201, 202]
                results['tests'].append({'price': price, 'status_code': response.status_code, 'accepted': accepted})
                if accepted:
                    results['vulnerable'] = True
                    results['evidence'] = f'Zero price {price} was accepted'
                time.sleep(0.5)
            except Exception as e:
                results['tests'].append({'price': price, 'error': str(e)})
        return results

    def _test_decimal_precision(self):
        results = {'vulnerable': False, 'method': 'decimal_precision', 'tests': []}
        for price in self.test_cases['decimal_precision']['payloads']:
            try:
                payload = {'price': price, 'amount': price, 'item_id': 'test_item', 'quantity': 1000}
                response = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=10, verify=False)
                accepted = response.status_code in [200, 201, 202]
                results['tests'].append({'price': price, 'quantity': 1000, 'status_code': response.status_code, 'accepted': accepted})
                if accepted and price < 0.01:
                    results['vulnerable'] = True
                    results['evidence'] = f'Tiny price {price} accepted'
                time.sleep(0.5)
            except Exception as e:
                results['tests'].append({'price': price, 'error': str(e)})
        return results

    def _test_parameter_tampering(self):
        results = {'vulnerable': False, 'method': 'parameter_tampering', 'tests': []}
        tampering_tests = [
            {'name': 'Conflicting prices', 'payload': {'price': 1.00, 'unit_price': 1.00, 'total': 0.01, 'quantity': 1}},
            {'name': 'Quantity-price mismatch', 'payload': {'item_price': 50, 'quantity': 10, 'total': 1}}
        ]
        for test in tampering_tests:
            try:
                response = requests.post(self.endpoint, headers=self.headers, json=test['payload'], timeout=10, verify=False)
                accepted = response.status_code in [200, 201, 202]
                results['tests'].append({'test_name': test['name'], 'payload': test['payload'], 'status_code': response.status_code, 'accepted': accepted})
                if accepted:
                    results['vulnerable'] = True
                    results['evidence'] = f'{test["name"]} accepted'
                time.sleep(1)
            except Exception as e:
                results['tests'].append({'test_name': test['name'], 'error': str(e)})
        return results

    def _test_currency_manipulation(self):
        results = {'vulnerable': False, 'method': 'currency_manipulation', 'tests': []}
        for currency in self.test_cases['currency_manipulation']['payloads']:
            try:
                payload = {'price': 100, 'currency': currency, 'item_id': 'test_item'}
                response = requests.post(self.endpoint, headers=self.headers, json=payload, timeout=10, verify=False)
                accepted = response.status_code in [200, 201, 202]
                results['tests'].append({'currency': currency, 'status_code': response.status_code, 'accepted': accepted})
                if accepted and currency in ['XXX', '', 'null']:
                    results['vulnerable'] = True
                    results['evidence'] = f'Invalid currency "{currency}" accepted'
                time.sleep(0.5)
            except Exception as e:
                results['tests'].append({'currency': currency, 'error': str(e)})
        return results

    # ---------------- Utility Methods ---------------- #

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
            json.dump({'endpoint': self.endpoint, 'vulnerabilities': vulnerabilities}, f, indent=2)