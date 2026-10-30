#!/usr/bin/env python3
"""
REVUEX - Business Logic Workflow Abuser
Business Logic Test Playbook Generator

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
Business logic testing can affect real transactions - use ONLY in test environments.
NEVER test on production payment systems without explicit authorization.

IMPORTANT (v2.1 false-positive fix):
Business logic flaws (price tampering, coupon stacking, checkout/step bypass,
refund abuse, etc.) depend entirely on an application's authenticated,
app-specific workflow. They CANNOT be confirmed by sending a payload to a base
URL and inspecting a generic response. The previous version of this module
*fabricated* a fixed set of CRITICAL/HIGH findings for every target, complete
with fake "request"/"response"/"evidence" fields describing attacks that were
never performed. That produced guaranteed false positives.

This module now emits a structured *manual test playbook*: candidate parameters,
scenarios to try, how to recognise a real issue, and remediation. These items
are returned as `manual_checks` with severity "info" and
`confidence: "manual-verification-required"`. They are deliberately NOT added to
the confirmed `vulnerabilities` list, so they never inflate a scan's finding
count or appear as proven bugs. A tester confirms each one by hand against the
live workflow and promotes it to a finding only with real evidence.
"""

import time
import json
import re
from pathlib import Path
from typing import List, Dict, Any
from urllib.parse import urlparse


class BusinessLogicAbuser:
    """
    Business Logic test-playbook generator.

    Produces manual-verification guidance for common business logic flaw
    classes. Does not assert any flaw exists without tester-supplied evidence.
    """

    def __init__(self, target: str, workspace: Path, delay: float = 5.0):
        self.target = target
        self.workspace = Path(workspace)
        self.delay = delay

        self.timeout = 10

        # Honesty note: production detection is a weak heuristic and must not be
        # relied on as a safety control. Keep the warning but do not hard-exit on
        # a guess, so the operator stays responsible for choosing a safe target.
        if self._looks_like_production():
            print("⚠️  WARNING: Target may be a production environment.")
            print("    Only run business logic tests against systems you are")
            print("    explicitly authorised to test (ideally sandbox/staging).")

        self.headers = {
            'User-Agent': 'REVUEX-WorkflowAbuser/1.0 (Security Research; +https://github.com/G33L0)',
            'Accept': 'application/json, text/html, */*'
        }

        # Confirmed findings only (populated by a tester promoting a manual check
        # with real evidence, or by future evidence-based probes). Empty by default.
        self.vulnerabilities: List[Dict[str, Any]] = []

        # Manual-verification guidance (NOT confirmed vulnerabilities).
        self.manual_checks: List[Dict[str, Any]] = []

        self.price_params = ['price', 'amount', 'total', 'subtotal', 'cost',
                             'value', 'payment', 'charge', 'fee', 'discount']
        self.quantity_params = ['quantity', 'qty', 'count', 'number', 'items']
        self.state_params = ['step', 'stage', 'state', 'status', 'phase', 'level']

    def _looks_like_production(self) -> bool:
        t = self.target.lower()
        test_indicators = ['test', 'staging', 'sandbox', 'dev', 'development',
                           'qa', 'demo', 'localhost', '127.0.0.1']
        if any(i in t for i in test_indicators):
            return False
        return True

    def scan(self) -> List[Dict[str, Any]]:
        print(f"\n{'='*60}")
        print(f"💼 REVUEX Business Logic Playbook")
        print(f"{'='*60}")
        print(f"Target: {self.target}")
        print(f"{'='*60}\n")
        print("ℹ️  This module generates a MANUAL test playbook.")
        print("    Nothing here is reported as a confirmed vulnerability.")
        print("    Confirm each item by hand against the live workflow and add")
        print("    real request/response evidence before treating it as a bug.\n")

        self._playbook_payment_manipulation()
        self._playbook_coupon_stacking()
        self._playbook_checkout_bypass()
        self._playbook_quantity_manipulation()
        self._playbook_state_manipulation()
        self._playbook_multistep_bypass()
        self._playbook_refund_abuse()
        self._playbook_subscription_abuse()

        self._save_results()

        print(f"\n{'='*60}")
        print(f"✅ Playbook generated")
        print(f"Confirmed vulnerabilities: {len(self.vulnerabilities)}")
        print(f"Manual checks to verify:   {len(self.manual_checks)}")
        print(f"{'='*60}\n")

        # Return only confirmed findings (empty unless real evidence was added),
        # keeping the suite's vulnerability count free of false positives.
        return self.vulnerabilities

    def _add_manual_check(self, check_type: str, scenarios: List[str],
                          how_to_confirm: str, remediation: List[str],
                          tags: List[str]):
        self.manual_checks.append({
            'type': check_type,
            'severity': 'info',
            'confidence': 'manual-verification-required',
            'url': self.target,
            'scenarios_to_try': scenarios,
            'how_to_confirm': how_to_confirm,
            'remediation': remediation,
            'tags': tags + ['manual', 'unconfirmed'],
        })
        print(f"   • Playbook item added: {check_type}")

    def _playbook_payment_manipulation(self):
        print("💰 Payment amount manipulation")
        self._add_manual_check(
            'Business Logic - Payment/Price Manipulation',
            [
                f"Candidate price params: {', '.join(self.price_params)}",
                "Set price to a negative value (e.g. -99.99) and check if a credit is issued",
                "Set price to 0.00 and check if the order completes free",
                "Set price to 0.01 on an expensive item",
                "Send a very large value (e.g. 99999999.99) to probe overflow handling",
            ],
            how_to_confirm=(
                "Place a legitimate order and record the server-calculated total. "
                "Replay the checkout with the price/total parameter modified. A real "
                "flaw exists ONLY if the server CHARGES the modified amount (confirm "
                "in the order record / payment processor), not merely if it returns "
                "HTTP 200. Capture both the original and tampered request/response."
            ),
            remediation=[
                "Recalculate all prices/totals server-side from authoritative data",
                "Never trust client-supplied price, total, or currency fields",
                "Reject negative and zero amounts; validate ranges",
            ],
            tags=['business_logic', 'payment', 'price_manipulation'],
        )

    def _playbook_coupon_stacking(self):
        print("🎟️  Coupon/discount stacking")
        self._add_manual_check(
            'Business Logic - Coupon/Discount Stacking',
            [
                "Apply multiple coupon codes in one order",
                "Re-apply the same single-use coupon repeatedly",
                "Combine exclusive promotions that should be mutually exclusive",
                "Check whether discounts can drive the total to <= 0",
            ],
            how_to_confirm=(
                "Confirm the server-side total actually reflects the stacked "
                "discounts and that the order is accepted at that total. A 200 "
                "response alone is not evidence."
            ),
            remediation=[
                "Enforce one coupon (or explicit compatibility rules) server-side",
                "Prevent negative totals; enforce minimum order amounts",
                "Track per-user coupon usage",
            ],
            tags=['business_logic', 'coupon', 'discount'],
        )

    def _playbook_checkout_bypass(self):
        print("🛒 Checkout flow bypass")
        self._add_manual_check(
            'Business Logic - Checkout Flow Bypass',
            [
                "Map the normal flow (cart → shipping → payment → confirm)",
                "POST directly to the confirmation/order-creation endpoint, skipping payment",
                "Replay a confirmation request without a valid payment token",
            ],
            how_to_confirm=(
                "A real flaw requires that an order is actually created in a paid "
                "state without a completed payment. Verify in the order/admin view, "
                "not from the HTTP status code alone."
            ),
            remediation=[
                "Validate that all required prior steps completed, server-side",
                "Verify payment status before creating/fulfilling an order",
                "Use server-managed session state for flow control",
            ],
            tags=['business_logic', 'checkout', 'bypass'],
        )

    def _playbook_quantity_manipulation(self):
        print("📦 Quantity/total manipulation")
        self._add_manual_check(
            'Business Logic - Quantity Manipulation',
            [
                f"Candidate quantity params: {', '.join(self.quantity_params)}",
                "Negative quantity (e.g. -10) to probe for credits",
                "Zero quantity to probe for free items",
                "Very large quantity (e.g. 999999999) to probe overflow / inventory checks",
            ],
            how_to_confirm=(
                "Confirm the final charged amount or inventory change reflects the "
                "manipulated quantity server-side."
            ),
            remediation=[
                "Validate quantity is a positive integer within sane limits",
                "Recalculate totals server-side; verify inventory availability",
            ],
            tags=['business_logic', 'quantity'],
        )

    def _playbook_state_manipulation(self):
        print("🔄 State transition manipulation")
        self._add_manual_check(
            'Business Logic - State Transition Manipulation',
            [
                f"Candidate state params: {', '.join(self.state_params)}",
                "Attempt to move an order from 'pending' to 'shipped'/'completed' directly",
                "Attempt unauthorized status changes via the update endpoint",
            ],
            how_to_confirm=(
                "Confirm the state actually changed server-side without the "
                "required authorization or payment, via the order record."
            ),
            remediation=[
                "Enforce a server-side state machine with valid transitions only",
                "Require authorization and payment checks before privileged states",
                "Audit all state modifications",
            ],
            tags=['business_logic', 'state', 'workflow'],
        )

    def _playbook_multistep_bypass(self):
        print("📋 Multi-step form bypass")
        self._add_manual_check(
            'Business Logic - Multi-Step Form Bypass',
            [
                "Skip intermediate steps of a multi-step form/registration",
                "Submit the final step directly with forged prior-step data",
            ],
            how_to_confirm=(
                "Confirm the final action succeeds despite skipped validation, "
                "server-side."
            ),
            remediation=[
                "Track completed steps server-side; enforce step dependencies",
                "Do not trust client-supplied step/stage indicators",
            ],
            tags=['business_logic', 'form', 'bypass'],
        )

    def _playbook_refund_abuse(self):
        print("💸 Refund/credit abuse")
        self._add_manual_check(
            'Business Logic - Refund Abuse',
            [
                "Request a refund twice for the same order",
                "Request a refund exceeding the original payment",
                "Probe for credits generated by refund of a zero/negative order",
            ],
            how_to_confirm=(
                "Confirm a duplicate or excess refund is actually issued (ledger / "
                "payment processor), not merely accepted at the HTTP layer."
            ),
            remediation=[
                "Track refund status per order; prevent duplicate refunds",
                "Cap refunds at the original captured amount",
                "Manual review for high-value refunds",
            ],
            tags=['business_logic', 'refund'],
        )

    def _playbook_subscription_abuse(self):
        print("📅 Subscription manipulation")
        self._add_manual_check(
            'Business Logic - Subscription Manipulation',
            [
                "Upgrade a subscription tier without a corresponding payment",
                "Extend a free trial by replaying/resetting trial state",
                "Pay a monthly price for an annual plan via parameter tampering",
            ],
            how_to_confirm=(
                "Confirm the account actually gains the higher tier / extended "
                "trial server-side without valid payment."
            ),
            remediation=[
                "Verify payment before any tier upgrade",
                "Server-side trial eligibility tracking; rate-limit plan changes",
            ],
            tags=['business_logic', 'subscription'],
        )

    def _save_results(self):
        output_dir = self.workspace / "business_logic_tests"
        output_dir.mkdir(exist_ok=True, parents=True)

        safe_target = re.sub(r'[^\w\-]', '_', self.target)
        output_file = output_dir / f"{safe_target}_business_logic.json"

        with open(output_file, 'w') as f:
            json.dump({
                'scanner': 'BusinessLogicAbuser',
                'target': self.target,
                'note': ('Business logic checks require manual verification; '
                         'items below are guidance, not confirmed findings.'),
                'vulnerabilities': self.vulnerabilities,
                'manual_checks': self.manual_checks,
            }, f, indent=2)

        print(f"\n💾 Saved: {output_file}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python business_logic_abuser.py <target_url>")
        print("Example: python business_logic_abuser.py https://sandbox.example.com")
        print("\n⚠️  WARNING: Use ONLY on test/sandbox environments you are authorised to test!")
        sys.exit(1)

    scanner = BusinessLogicAbuser(sys.argv[1], Path("revuex_workspace"), delay=5.0)
    scanner.scan()
