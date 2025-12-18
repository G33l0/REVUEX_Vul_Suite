# IDOR Hunter v2.0 - Two-Account Testing Guide

## Overview

The Enhanced IDOR Hunter uses **two-account access control verification** to find real IDOR vulnerabilities by:

1. Creating/accessing resources with Account A (legitimate owner)
1. Attempting unauthorized access with Account B (attacker)
1. Verifying actual data leakage (not just status codes)

This approach eliminates false positives and proves actual security impact.

## Why Two-Account Testing?

### Traditional IDOR Testing (Unreliable)

'''bash
# Only tests ID enumeration - lots of false positives
GET /api/user/1
GET /api/user/2
GET /api/user/3
# Getting 200 doesn't mean you accessed someone else's data!
'''

### Two-Account Testing (Reliable)

'''bash
# Account A creates resource → ID: 12345
POST /api/documents
Response: {"id": "12345", "content": "sensitive data"}

# Account B tries to access Account A's resource
GET /api/documents/12345
Response: {"id": "12345", "content": "sensitive data"}  ← CONFIRMED IDOR!
'''

## Setup Requirements

### 1. Two Valid Accounts

You need two legitimate accounts on the target application:

- **Account A**: “Victim” account (will own resources)
- **Account B**: “Attacker” account (will attempt unauthorized access)

### 2. Extract Authentication Tokens

#### Method 1: Browser DevTools

'''javascript
// In browser console on the target site
// Get Authorization header
document.cookie

// Get Bearer token from localStorage
localStorage.getItem('token')
// or
localStorage.getItem('auth_token')

// Get session cookies
document.cookie
'''

#### Method 2: Burp Suite

1. Intercept requests from authenticated session
1. Copy Authorization header
1. Copy Cookie header

#### Method 3: cURL with -v

'''bash
curl -v https://target.com/api/me -H "Authorization: Bearer YOUR_TOKEN"
# Look for Set-Cookie in response
'''

## Usage Examples

### Example 1: Basic Two-Account Testing

'''bash
python idor_hunter.py -u https://api.example.com \
  --account-a "Bearer eyJhbGc..." "session=abc123; user_id=user1" \
  --account-b "Bearer eyJzdW..." "session=xyz789; user_id=user2"
'''

**What this does:**

- Discovers user IDs for both accounts
- Tests if Account B can access Account A’s resources
- Tests 20+ common IDOR endpoint patterns

### Example 2: Testing Specific Resource IDs

If you know specific resource IDs:

'''bash
python idor_hunter.py -u https://api.example.com \
  --account-a "Bearer token_a" "session_a=value_a" \
  --account-b "Bearer token_b" "session_b=value_b" \
  --ids 12345 67890 11111 22222
'''

**When to use:**

- You’ve identified interesting resources in Account A
- Testing specific high-value targets (invoices, documents, etc.)
- Following up on reconnaissance findings

### Example 3: API Key Authentication

'''bash
python idor_hunter.py -u https://api.example.com \
  --account-a "X-API-Key: key_abc123" "" \
  --account-b "X-API-Key: key_xyz789" ""
'''

**Works with:**

- API key authentication
- Custom header-based auth
- Basic authentication

### Example 4: Session Cookie Only

'''bash
python idor_hunter.py -u https://api.example.com \
  --account-a "" "PHPSESSID=session_a_value; logged_in=true" \
  --account-b "" "PHPSESSID=session_b_value; logged_in=true"
'''

**Perfect for:**

- Traditional web applications
- PHP/ASP.NET applications
- Session-based authentication

### Example 5: Complete Bug Bounty Workflow

'''bash
# Step 1: Find the target's API endpoints
./subdomain_hunter.py -d example.com

# Step 2: Identify authentication mechanism
curl -v https://api.example.com/login -d '{"email":"test@test.com","password":"test"}'

# Step 3: Create two accounts and extract credentials
# (Manual step - create accounts on target site)

# Step 4: Run IDOR scan
python idor_hunter.py -u https://api.example.com \
  --account-a "Bearer $TOKEN_A" "$COOKIES_A" \
  --account-b "Bearer $TOKEN_B" "$COOKIES_B" \
  --delay 2.0 \
  -o idor_report.json

# Step 5: Review findings and create PoC
cat idor_report.json
'''

## Real-World Target Examples

### Testing TheFork/LaFourchette API

'''bash
# After logging in with two accounts:
python idor_hunter.py -u https://api.thefork.com \
  --account-a "Bearer eyJhbGciOiJIUzI1..." "datadome=f8Y7o..." \
  --account-b "Bearer eyJhbGciOiJIUzI1..." "datadome=g9Z8p..." \
  --ids restaurant_123 booking_456 \
  -o thefork_idor.json
'''

### Testing E-commerce Platform

'''bash
python idor_hunter.py -u https://shop.example.com \
  --account-a "Bearer customer_a_token" "cart_id=abc; session=xyz" \
  --account-b "Bearer customer_b_token" "cart_id=def; session=uvw" \
  --delay 1.5
'''

### Testing SaaS Application

'''bash
python idor_hunter.py -u https://app.saas.com \
  --account-a "Bearer workspace_a" "org_id=111" \
  --account-b "Bearer workspace_b" "org_id=222" \
  --ids project_789 document_456
'''

## Understanding the Output

### Vulnerability Severity Levels

**Critical:**

- Delete operations (can remove other users’ data)
- Access to passwords, payment info, SSN
- Multiple sensitive fields exposed

**High:**

- Write/modify operations
- Access to PII (email, phone, address)
- Financial data (balances, transactions)

**Medium:**

- Read-only access to personal data
- User preferences, settings
- Non-sensitive profile information

**Low:**

- Public information with weak access control
- Metadata only

### Sample Output

'''
[1] READ IDOR - High Severity
    Endpoint: /api/user/12345
    Method: GET
    Resource Owner: Account A
    Attacker Account: Account B
    Resource ID: 12345
    Response Code: 200
    Leaked Data Preview: {"id":12345,"email":"victim@example.com","phone":"+1234567890","address":"123 Main St"...}
'''

## Advanced Techniques

### 1. Testing Write IDORs (Careful!)

Uncomment this line in the code to test modification:

'''python
# Line 368 in idor_hunter.py
self.test_idor_write(pattern, resource_id, self.account_a, self.account_b)
'''

⚠️ **Warning:** This attempts to modify Account A’s data. Only use on targets where you have explicit permission!

### 2. Custom Endpoint Patterns

Add your own patterns to the `test_patterns` list:

'''python
self.test_patterns = [
    "/api/user/{id}",
    "/api/custom-endpoint/{id}",  # Add your discoveries
    "/v2/users/{id}/private",
    # etc.
]
'''

### 3. Rate Limiting

'''bash
# Increase delay for rate-limited targets
python idor_hunter.py -u https://api.example.com \
  --delay 3.0 \
  [other options]
'''

### 4. Combining with Other Tools

'''bash
# Use with subdomain scanner to find APIs
./subdomain_hunter.py -d example.com | grep api > api_targets.txt

# Test each API
while read api; do
  python idor_hunter.py -u "https://$api" \
    --account-a "$TOKEN_A" "$COOKIES_A" \
    --account-b "$TOKEN_B" "$COOKIES_B"
done < api_targets.txt
'''

## Bug Bounty Report Template

When you find a vulnerability:

'''markdown
**Title:** IDOR Allows Unauthorized Access to User Documents

**Severity:** High

**Description:**
The application's document API endpoint `/api/documents/{id}` does not properly 
validate authorization, allowing any authenticated user to access documents 
belonging to other users.

**Steps to Reproduce:**
1. Login as User A (victim@example.com)
2. Create a private document - note the ID (e.g., 12345)
3. Login as User B (attacker@example.com)
4. Send request: GET /api/documents/12345
5. Observe that User B receives User A's private document

**Proof of Concept:**
'''bash
# User A's document
curl -H "Authorization: Bearer USER_A_TOKEN" \
  https://api.example.com/api/documents/12345

# User B accessing User A's document (unauthorized)
curl -H "Authorization: Bearer USER_B_TOKEN" \
  https://api.example.com/api/documents/12345
# Returns same data - IDOR confirmed!
'''

**Impact:**

- Unauthorized access to private user documents
- Potential exposure of sensitive business information
- Privacy violation affecting all users

**Recommendation:**
Implement proper authorization checks to verify that the requesting
user owns or has permission to access the requested resource.

'''
## Troubleshooting

### "Could not auto-discover user ID"
**Solution:** Manually find your user ID and use `--ids` flag:
'''bash
curl -H "Authorization: Bearer YOUR_TOKEN" https://api.example.com/api/me
# Extract ID from response, then:
python idor_hunter.py ... --ids YOUR_USER_ID
'''

### “Owner cannot access resource”

**Cause:** Endpoint might not exist or require different authentication
**Solution:** Verify the endpoint manually first with curl/Burp

### No vulnerabilities found

**Possible reasons:**

1. Target has good access control ✓
1. Wrong endpoint patterns (add custom patterns)
1. Authentication expired (refresh tokens)
1. IDs don’t exist (try different IDs with –ids)

## Best Practices

1. **Always get permission** before testing production systems
1. **Use responsible disclosure** when reporting vulnerabilities
1. **Don’t test write/delete** unless explicitly authorized
1. **Respect rate limits** with appropriate –delay values
1. **Document everything** for your bug bounty report
1. **Clean up** test resources you create

## Legal Disclaimer

This tool is for authorized security testing only. Unauthorized access to
computer systems is illegal. Always:

- Get written permission before testing
- Follow the target’s responsible disclosure policy
- Respect bug bounty program rules
- Don’t access, modify, or delete data without authorization

-----

**Author:** G33L0 (@x0x0h33l0)
**Part of:** REVUEX Bug Bounty Automation Framework
**Contact:** Telegram @x0x0h33l0

'''

'''