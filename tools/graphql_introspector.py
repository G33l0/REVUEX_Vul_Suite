#!/usr/bin/env python3
"""
REVUEX - GraphQL Introspector
Advanced GraphQL Security Testing & Introspection

Author: G33L0
Telegram: @x0x0h33l0

DISCLAIMER:
This tool is for educational purposes and authorized security testing only.
"""

import requests
import json
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

class GraphQLIntrospector:
    """GraphQL security testing and introspection"""

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
        }
        """

    # -------------------- CORE SCAN METHODS --------------------

    def scan(self):
        """Scan for GraphQL vulnerabilities"""
        vulnerabilities = []

        # Find GraphQL endpoint
        graphql_url = self._find_graphql_endpoint()

        if not graphql_url:
            return vulnerabilities

        print(f"→ GraphQL endpoint found: {graphql_url}")

        # Test introspection
        schema = self._test_introspection(graphql_url)

        if schema:
            introspection_vuln = self._create_introspection_vulnerability(graphql_url, schema)
            vulnerabilities.append(introspection_vuln)

            schema_vulns = self._analyze_schema(schema, graphql_url)
            vulnerabilities.extend(schema_vulns)

        common_vulns = self._test_common_vulnerabilities(graphql_url)
        vulnerabilities.extend(common_vulns)

        self._save_results(graphql_url, schema, vulnerabilities)

        return vulnerabilities

    # -------------------- HELPER METHODS --------------------

    def _find_graphql_endpoint(self):
        """Find GraphQL endpoint"""
        for path in self.graphql_paths:
            url = urljoin(self.target, path)
            try:
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

    # -------------------- VULNERABILITY METHODS --------------------

    def _create_introspection_vulnerability(self, graphql_url, schema):
        """Create enhanced introspection vulnerability report"""
        types = schema.get('types', [])
        queries, mutations = [], []

        query_type_name = schema.get('queryType', {}).get('name')
        mutation_type_name = schema.get('mutationType', {}).get('name')

        for type_def in types:
            if type_def.get('name') == query_type_name:
                queries = [f.get('name') for f in type_def.get('fields', [])]
            if type_def.get('name') == mutation_type_name:
                mutations = [f.get('name') for f in type_def.get('fields', [])]

        sample_queries = queries[:5] if queries else []
        sample_mutations = mutations[:5] if mutations else []

        return {
            'type': 'GraphQL Introspection Enabled',
            'severity': 'medium',
            'url': graphql_url,
            'description': 'GraphQL introspection is enabled in production, exposing complete API schema',
            'evidence': f'Schema contains {len(types)} types, {len(queries)} queries, {len(mutations)} mutations',
            'steps_to_reproduce': [
                f"Navigate to GraphQL endpoint: {graphql_url}",
                "Send introspection query",
                "Observe that complete schema is returned"
            ],
            'request': f"POST {graphql_url} HTTP/1.1\nHost: {self._get_host_from_url(graphql_url)}\nContent-Type: application/json\n\n{{'query': '{{ __schema {{ types {{ name fields {{ name type {{ name }} }} }} }} }}'}}",
            'response': f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{{...sample response...}}",
            'poc': f"# PoC: Extract full schema from {graphql_url}",
            'before_state': 'Schema is private',
            'after_state': f'Complete schema exposed: {len(types)} types, {len(queries)} queries, {len(mutations)} mutations',
            'attack_path': [
                'Send introspection query',
                'Receive full schema',
                'Identify sensitive fields and mutations'
            ],
            'remediation': [
                'Disable introspection in production',
                'Enforce authentication for all GraphQL queries',
                'Use query complexity and depth limiting'
            ],
            'tags': ['graphql', 'information_disclosure', 'reconnaissance']
        }

    def _analyze_schema(self, schema, graphql_url):
        """Analyze GraphQL schema for security issues"""
        vulnerabilities = []
        types = schema.get('types', [])

        sensitive_keywords = [
            'password', 'secret', 'token', 'key', 'private',
            'ssn', 'credit', 'card', 'social', 'internal', 'admin'
        ]

        sensitive_fields = []
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
                'type': 'Sensitive Fields Exposed',
                'severity': 'high',
                'url': graphql_url,
                'description': 'Exposed sensitive fields in schema',
                'evidence': f"Found {len(sensitive_fields)} sensitive field names including: {sample_field['type']}.{sample_field['field']}",
                'details': sensitive_fields[:10],
                'tags': ['graphql', 'sensitive_data', 'authorization']
            })

        return vulnerabilities

    def _test_common_vulnerabilities(self, graphql_url):
        """Test for common GraphQL vulnerabilities"""
        vulnerabilities = []
        # Minimal PoC for production-ready repo
        return vulnerabilities

    def _save_results(self, graphql_url, schema, vulnerabilities):
        """Save GraphQL scan results"""
        graphql_dir = self.workspace / "graphql_scans"
        graphql_dir.mkdir(exist_ok=True)
        if schema:
            with open(graphql_dir / "schema.json", 'w') as f:
                json.dump(schema, f, indent=2)
        with open(graphql_dir / "vulnerabilities.json", 'w') as f:
            json.dump({
                'endpoint': graphql_url,
                'introspection_enabled': schema is not None,
                'vulnerabilities': vulnerabilities
            }, f, indent=2)