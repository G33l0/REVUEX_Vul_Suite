#!/usr/bin/env python3
"""
REVUEX - Race Condition Tester
Advanced Race Condition Detection & Exploitation

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
Use extreme caution - race condition testing can cause unintended effects.
"""

import requests
import threading
import time
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue

class RaceConditionTester:
    """Race condition vulnerability testing"""
    
    def __init__(self, endpoint, workspace, delay=3):
        """
        Initialize Race Condition Tester
        
        Args:
            endpoint: Target endpoint URL
            workspace: Workspace directory
            delay: Extra safety delay between tests
        """
        self.endpoint = endpoint
        self.workspace = Path(workspace)
        self.delay = delay
        
        self.headers = {
            'User-Agent': 'REVUEX-RaceTester/1.0 (Security Research; +https://github.com/G33L0)'
        }
        
        # Results queue for thread-safe collection
        self.results_queue = queue.Queue()
    
    def test(self):
        """Test for race condition vulnerabilities"""
        print(f"            [!] CAUTION: Testing race conditions on {self.endpoint}")
        print(f"            [!] Using {self.delay}s safety delay")
        
        vulnerability = {
            'type': 'Race Condition',
            'severity': 'High',
            'endpoint': self.endpoint,
            'exploitable': False,
            'evidence': '',
            'test_results': {}
        }
        
        # Test 1: Parallel request race condition
        print(f"            → Test 1: Parallel request timing")
        parallel_result = self._test_parallel_requests()
        vulnerability['test_results']['parallel'] = parallel_result
        
        time.sleep(self.delay)
        
        # Test 2: Resource exhaustion race
        print(f"            → Test 2: Resource exhaustion")
        resource_result = self._test_resource_exhaustion()
        vulnerability['test_results']['resource_exhaustion'] = resource_result
        
        time.sleep(self.delay)
        
        # Test 3: State manipulation race
        print(f"            → Test 3: State manipulation")
        state_result = self._test_state_manipulation()
        vulnerability['test_results']['state_manipulation'] = state_result
        
        # Determine if exploitable
        if any([
            parallel_result.get('vulnerable'),
            resource_result.get('vulnerable'),
            state_result.get('vulnerable')
        ]):
            vulnerability['exploitable'] = True
            vulnerability['severity'] = 'Critical'
            vulnerability['evidence'] = 'Multiple concurrent requests produced inconsistent results'
            vulnerability['description'] = 'Endpoint is vulnerable to race condition attacks'
            vulnerability['attack_path'] = [
                'Send multiple simultaneous requests to the endpoint',
                'Exploit timing window in state checks',
                'Achieve unintended state (e.g., double spending, duplicate credits)',
                'Potential for financial loss or privilege escalation'
            ]
            vulnerability['remediation'] = [
                'Implement proper locking mechanisms (database locks, mutexes)',
                'Use atomic operations for critical state changes',
                'Implement idempotency keys for sensitive operations',
                'Add transaction isolation (SERIALIZABLE level)',
                'Implement request deduplication',
                'Use distributed locks for multi-server environments',
                'Add rate limiting per user/session'
            ]
        else:
            vulnerability['description'] = 'No race condition detected (endpoint appears safe)'
            vulnerability['evidence'] = 'Concurrent requests handled consistently'
            vulnerability['remediation'] = [
                'Continue monitoring for race conditions',
                'Regular security testing during updates',
                'Maintain current protective mechanisms'
            ]
        
        vulnerability['tags'] = ['race_condition', 'business_logic', 'timing']
        
        # Save results
        self._save_results(vulnerability)
        
        return vulnerability
    
    def _test_parallel_requests(self):
        """Test with parallel simultaneous requests"""
        num_threads = 10  # Number of simultaneous requests
        
        results = {
            'vulnerable': False,
            'method': 'parallel_requests',
            'responses': [],
            'timing': {}
        }
        
        # Synchronization barrier
        barrier = threading.Barrier(num_threads)
        start_times = []
        end_times = []
        
        def make_request(thread_id):
            """Make a single request with timing"""
            try:
                # Wait at barrier for simultaneous start
                barrier.wait()
                
                start = time.time()
                response = requests.get(
                    self.endpoint,
                    headers=self.headers,
                    timeout=10,
                    verify=False
                )
                end = time.time()
                
                self.results_queue.put({
                    'thread_id': thread_id,
                    'status_code': response.status_code,
                    'response_time': end - start,
                    'content_length': len(response.content),
                    'headers': dict(response.headers)
                })
                
            except Exception as e:
                self.results_queue.put({
                    'thread_id': thread_id,
                    'error': str(e)
                })
        
        # Launch threads
        threads = []
        for i in range(num_threads):
            thread = threading.Thread(target=make_request, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        # Collect results
        while not self.results_queue.empty():
            result = self.results_queue.get()
            results['responses'].append(result)
        
        # Analyze for inconsistencies
        status_codes = [r.get('status_code') for r in results['responses'] if 'status_code' in r]
        content_lengths = [r.get('content_length') for r in results['responses'] if 'content_length' in r]
        
        # Check for variations (potential race condition)
        if len(set(status_codes)) > 1:
            results['vulnerable'] = True
            results['evidence'] = f'Status codes varied: {set(status_codes)}'
        
        if len(set(content_lengths)) > 1:
            # Allow small variations (timestamps, etc)
            if max(content_lengths) - min(content_lengths) > 100:
                results['vulnerable'] = True
                results['evidence'] = f'Content lengths varied significantly: {min(content_lengths)} - {max(content_lengths)}'
        
        results['timing']['min_response'] = min([r.get('response_time', 0) for r in results['responses'] if 'response_time' in r] or [0])
        results['timing']['max_response'] = max([r.get('response_time', 0) for r in results['responses'] if 'response_time' in r] or [0])
        
        return results
    
    def _test_resource_exhaustion(self):
        """Test for resource exhaustion race conditions"""
        results = {
            'vulnerable': False,
            'method': 'resource_exhaustion',
            'attempts': []
        }
        
        # Test: Try to claim same resource multiple times simultaneously
        num_requests = 5
        
        def claim_resource(request_id):
            """Attempt to claim a resource"""
            try:
                response = requests.post(
                    self.endpoint,
                    headers=self.headers,
                    json={'action': 'claim', 'request_id': request_id},
                    timeout=10,
                    verify=False
                )
                
                return {
                    'request_id': request_id,
                    'status': response.status_code,
                    'success': response.status_code in [200, 201],
                    'response': response.text[:200]
                }
            except Exception as e:
                return {
                    'request_id': request_id,
                    'error': str(e)
                }
        
        # Use ThreadPoolExecutor for true concurrency
        with ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [executor.submit(claim_resource, i) for i in range(num_requests)]
            
            for future in as_completed(futures):
                result = future.result()
                results['attempts'].append(result)
        
        # Check if multiple succeeded (race condition)
        successes = [a for a in results['attempts'] if a.get('success')]
        
        if len(successes) > 1:
            results['vulnerable'] = True
            results['evidence'] = f'{len(successes)} simultaneous claims succeeded (expected 1)'
        
        return results
    
    def _test_state_manipulation(self):
        """Test for state manipulation race conditions"""
        results = {
            'vulnerable': False,
            'method': 'state_manipulation',
            'state_checks': []
        }
        
        # Test: Check if state changes are atomic
        num_operations = 10
        
        def modify_state(op_id):
            """Attempt to modify shared state"""
            try:
                # GET current state
                get_response = requests.get(
                    self.endpoint,
                    headers=self.headers,
                    timeout=5,
                    verify=False
                )
                
                initial_state = get_response.text[:100]
                
                # Small delay (race window)
                time.sleep(0.01)
                
                # POST modification
                post_response = requests.post(
                    self.endpoint,
                    headers=self.headers,
                    json={'operation': op_id},
                    timeout=5,
                    verify=False
                )
                
                return {
                    'op_id': op_id,
                    'initial_state': initial_state,
                    'post_status': post_response.status_code,
                    'success': post_response.status_code in [200, 201]
                }
            except Exception as e:
                return {
                    'op_id': op_id,
                    'error': str(e)
                }
        
        # Launch concurrent modifications
        with ThreadPoolExecutor(max_workers=num_operations) as executor:
            futures = [executor.submit(modify_state, i) for i in range(num_operations)]
            
            for future in as_completed(futures):
                result = future.result()
                results['state_checks'].append(result)
        
        # Check for anomalies
        successes = [s for s in results['state_checks'] if s.get('success')]
        
        # If all succeeded despite race window, might be vulnerable
        if len(successes) == num_operations:
            results['vulnerable'] = True
            results['evidence'] = 'All concurrent state modifications succeeded (potential TOCTOU)'
        
        return results
    
    def _save_results(self, vulnerability):
        """Save race condition test results"""
        race_dir = self.workspace / "race_condition_tests"
        race_dir.mkdir(exist_ok=True)
        
        # Safe filename from endpoint
        import re
        safe_name = re.sub(r'[^\w\-]', '_', self.endpoint)
        output_file = race_dir / f"{safe_name}_race_test.json"
        
        with open(output_file, 'w') as f:
            json.dump(vulnerability, f, indent=2)
