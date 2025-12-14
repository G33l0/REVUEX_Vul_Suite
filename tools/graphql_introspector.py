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
from urllib.parse import urljoin

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
            vulnerabilities.append({
                'type': 'GraphQL Introspection Enabled',
                'severity': 'Medium',
                'url': graphql_url,
                'description': 'GraphQL introspection is enabled, exposing the complete schema',
                'evidence': f'Schema contains {len(schema.get("types", []))} types',
                'attack_path': [
                    'Send introspection query to GraphQL endpoint',
                    'Receive complete schema with all types, queries, and mutations',
                    'Use schema to craft targeted queries',
                    'Potentially access unauthorized data or functions'
                ],
                'remediation': [
                    'Disable introspection in production environments',
                    'Implement proper authentication and authorization',
                    'Use query depth limiting',
                    'Implement query cost analysis'
                ],
                'tags': ['graphql', 'information_disclosure']
            })
            
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
    
    def _analyze_schema(self, schema, graphql_url):
        """Analyze GraphQL schema for security issues"""
        vulnerabilities = []
        
        types = schema.get('types', [])
        
        # Check for sensitive field names
        sensitive_fields = []
        sensitive_keywords = [
            'password', 'secret', 'token', 'key', 'private',
            'ssn', 'credit', 'card', 'social', 'internal'
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
            vulnerabilities.append({
                'type': 'Sensitive Fields Exposed',
                'severity': 'High',
                'url': graphql_url,
                'description': 'GraphQL schema exposes potentially sensitive fields',
                'evidence': f'Found {len(sensitive_fields)} sensitive field names',
                'details': sensitive_fields[:10],  # First 10
                'attack_path': [
                    'Use introspection to discover sensitive fields',
                    'Craft queries to access sensitive data',
                    'Attempt to retrieve passwords, tokens, or private information'
                ],
                'remediation': [
                    'Review and rename sensitive fields',
                    'Implement field-level authorization',
                    'Use @deprecated directive for sensitive fields',
                    'Disable introspection in production'
                ],
                'tags': ['graphql', 'sensitive_data']
            })
        
        # Check for mutation operations
        mutations = []
        for type_def in types:
            if type_def.get('name') == schema.get('mutationType', {}).get('name'):
                mutations = type_def.get('fields', [])
        
        if mutations:
            dangerous_mutations = []
            danger_keywords = ['delete', 'remove', 'admin', 'update', 'create']
            
            for mutation in mutations:
                mutation_name = mutation.get('name', '').lower()
                for keyword in danger_keywords:
                    if keyword in mutation_name:
                        dangerous_mutations.append(mutation.get('name'))
        
            if dangerous_mutations:
                vulnerabilities.append({
                    'type': 'Dangerous Mutations Exposed',
                    'severity': 'High',
                    'url': graphql_url,
                    'description': 'GraphQL exposes potentially dangerous mutation operations',
                    'evidence': f'Found {len(dangerous_mutations)} dangerous mutations',
                    'details': dangerous_mutations,
                    'attack_path': [
                        'Discover mutations via introspection',
                        'Test mutations without proper authentication',
                        'Attempt unauthorized data modification or deletion'
                    ],
                    'remediation': [
                        'Implement proper authentication for all mutations',
                        'Use role-based access control (RBAC)',
                        'Validate all mutation inputs',
                        'Implement rate limiting on mutations'
                    ],
                    'tags': ['graphql', 'authorization']
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
                        'severity': 'Medium',
                        'url': graphql_url,
                        'description': 'GraphQL endpoint does not enforce query depth limits',
                        'evidence': 'Deep nested query was accepted without errors',
                        'attack_path': [
                            'Send deeply nested query',
                            'Server processes expensive query',
                            'Cause performance degradation or DoS'
                        ],
                        'remediation': [
                            'Implement query depth limiting (max 5-7 levels)',
                            'Implement query complexity analysis',
                            'Set timeout limits for queries',
                            'Monitor and log expensive queries'
                        ],
                        'tags': ['graphql', 'dos']
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
                    'severity': 'Medium',
                    'url': graphql_url,
                    'description': 'GraphQL endpoint accepts large batched queries',
                    'evidence': 'Batch of 150 queries was accepted',
                    'attack_path': [
                        'Send batch of hundreds of queries',
                        'Bypass rate limiting through batching',
                        'Overwhelm server resources'
                    ],
                    'remediation': [
                        'Limit batch query size (max 5-10 queries)',
                        'Implement per-query rate limiting',
                        'Monitor batch query usage',
                        'Consider disabling batching'
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
                    'severity': 'Low',
                    'url': graphql_url,
                    'description': 'GraphQL allows field duplication in queries',
                    'evidence': 'Query with duplicate fields was accepted',
                    'attack_path': [
                        'Send query with thousands of duplicate fields',
                        'Increase processing overhead',
                        'Cause performance issues'
                    ],
                    'remediation': [
                        'Reject queries with duplicate fields',
                        'Implement query validation',
                        'Set field count limits'
                    ],
                    'tags': ['graphql', 'performance']
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
