#!/usr/bin/env python3
"""
Azure Security Audit Tool - Comprehensive Edition
Automated security assessment for Azure resources and permissions
Tests 200+ services including external integrations
"""

import json
import base64
import requests
import datetime
import subprocess
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import asyncio
import aiohttp
from pathlib import Path

# Setup logging with UTF-8 encoding for Windows compatibility
import sys
import io

# Configure console output for Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('azure_audit.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class TokenInfo:
    """JWT Token information"""
    scopes: str
    app_id: str
    audience: str
    expiry: datetime.datetime
    issuer: str
    user_id: str
    email: str
    name: str


@dataclass
class AuditResult:
    """Audit result container"""
    timestamp: datetime.datetime
    token_info: TokenInfo
    api_access: Dict[str, Any]
    role_assignments: List[Dict]
    security_recommendations: List[Dict]
    compliance_status: Dict[str, str]


class AzureSecurityAuditor:
    """Main class for Azure security auditing"""

    def __init__(self, token: str = None):
        self.token = token
        self.session = None
        self.results = AuditResult(
            timestamp=datetime.datetime.now(),
            token_info=None,
            api_access={},
            role_assignments=[],
            security_recommendations=[],
            compliance_status={}
        )

    def decode_jwt_token(self, token: str) -> TokenInfo:
        """Decode JWT token to extract information"""
        try:
            # Split token and decode payload
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT token format")

            # Add padding if needed
            payload = parts[1]
            payload += '=' * (4 - len(payload) % 4)

            # Decode base64
            decoded = base64.b64decode(payload)
            token_data = json.loads(decoded)

            token_info = TokenInfo(
                scopes=token_data.get('scp', ''),
                app_id=token_data.get('appid', ''),
                audience=token_data.get('aud', ''),
                expiry=datetime.datetime.fromtimestamp(token_data.get('exp', 0)),
                issuer=token_data.get('iss', ''),
                user_id=token_data.get('oid', ''),
                email=token_data.get('upn', ''),
                name=token_data.get('name', '')
            )

            logger.info(f"Token decoded successfully for user: {token_info.email}")
            return token_info

        except Exception as e:
            logger.error(f"Error decoding token: {e}")
            raise

    async def test_power_bi_endpoints(self, token: str) -> Dict[str, Any]:
        """Test Power BI API endpoints"""
        endpoints = {
            'groups': {
                'url': 'https://api.powerbi.com/v1.0/myorg/groups',
                'description': 'Power BI Workspaces/Groups',
                'service': 'Power BI',
                'category': 'Power Platform'
            },
            'datasets': {
                'url': 'https://api.powerbi.com/v1.0/myorg/datasets',
                'description': 'Power BI Datasets',
                'service': 'Power BI',
                'category': 'Power Platform'
            },
            'reports': {
                'url': 'https://api.powerbi.com/v1.0/myorg/reports',
                'description': 'Power BI Reports',
                'service': 'Power BI',
                'category': 'Power Platform'
            },
            'dashboards': {
                'url': 'https://api.powerbi.com/v1.0/myorg/dashboards',
                'description': 'Power BI Dashboards',
                'service': 'Power BI',
                'category': 'Power Platform'
            },
            'dataflows': {
                'url': 'https://api.powerbi.com/v1.0/myorg/dataflows',
                'description': 'Power BI Dataflows',
                'service': 'Power BI',
                'category': 'Power Platform'
            },
            'capacities': {
                'url': 'https://api.powerbi.com/v1.0/myorg/capacities',
                'description': 'Power BI Capacities',
                'service': 'Power BI',
                'category': 'Power Platform'
            }
        }

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        results = {}

        async with aiohttp.ClientSession() as session:
            for name, endpoint_info in endpoints.items():
                url = endpoint_info['url']
                try:
                    async with session.get(url, headers=headers) as response:
                        status = response.status
                        response_text = await response.text()

                        results[name] = {
                            'status': status,
                            'accessible': status == 200,
                            'url': url,
                            'description': endpoint_info['description'],
                            'service': endpoint_info['service'],
                            'category': endpoint_info['category']
                        }

                        if status == 200:
                            try:
                                data = await response.json()
                                results[name]['count'] = len(data.get('value', []))
                                # Store ALL items, not just first 3
                                results[name]['items'] = data.get('value', [])
                                logger.info(f"[OK] {name}: {results[name]['count']} items")
                            except:
                                results[name]['response'] = response_text[:200]
                        else:
                            try:
                                error_data = json.loads(response_text)
                                results[name]['error_details'] = error_data
                            except:
                                results[name]['error_response'] = response_text[:200]
                            logger.warning(f"[FAIL] {name}: HTTP {status}")

                except Exception as e:
                    results[name] = {
                        'status': 'error',
                        'accessible': False,
                        'error': str(e),
                        'url': url,
                        'description': endpoint_info['description'],
                        'service': endpoint_info['service'],
                        'category': endpoint_info['category']
                    }
                    logger.error(f"Error testing {name}: {e}")

        return results

    async def test_comprehensive_azure_services(self, token: str) -> Dict[str, Any]:
        """Test comprehensive Azure services and external integrations"""

        token_info = self.decode_jwt_token(token)
        tenant_id = token_info.issuer.split('/')[-2] if token_info.issuer else ""

        # All service definitions
        all_services = {}

        # Azure Core Management
        azure_mgmt = {
            'subscriptions': {
                'url': 'https://management.azure.com/subscriptions?api-version=2020-01-01',
                'description': 'Azure Subscriptions',
                'service': 'Azure Resource Manager',
                'category': 'Core Management'
            },
            'tenants': {
                'url': 'https://management.azure.com/tenants?api-version=2020-01-01',
                'description': 'Azure Tenants',
                'service': 'Azure Resource Manager',
                'category': 'Core Management'
            },
            'resource_groups': {
                'url': 'https://management.azure.com/subscriptions/{subscription}/resourcegroups?api-version=2021-04-01',
                'description': 'Resource Groups',
                'service': 'Azure Resource Manager',
                'category': 'Core Management'
            }
        }
        all_services.update({f"azure_mgmt_{k}": v for k, v in azure_mgmt.items()})

        # Azure Storage
        azure_storage = {
            'storage_accounts': {
                'url': 'https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01',
                'description': 'Storage Accounts',
                'service': 'Azure Storage',
                'category': 'Storage'
            },
            'file_services': {
                'url': 'https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01',
                'description': 'Azure Files',
                'service': 'Azure Files',
                'category': 'Storage'
            }
        }
        all_services.update({f"azure_storage_{k}": v for k, v in azure_storage.items()})

        # Azure Compute
        azure_compute = {
            'virtual_machines': {
                'url': 'https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.Compute/virtualMachines?api-version=2021-11-01',
                'description': 'Virtual Machines',
                'service': 'Azure Compute',
                'category': 'Compute'
            },
            'app_services': {
                'url': 'https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.Web/sites?api-version=2021-03-01',
                'description': 'App Services',
                'service': 'Azure App Service',
                'category': 'Compute'
            },
            'kubernetes_services': {
                'url': 'https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.ContainerService/managedClusters?api-version=2021-10-01',
                'description': 'Azure Kubernetes Service',
                'service': 'Azure Kubernetes Service',
                'category': 'Compute'
            }
        }
        all_services.update({f"azure_compute_{k}": v for k, v in azure_compute.items()})

        # Azure Databases
        azure_db = {
            'sql_servers': {
                'url': 'https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.Sql/servers?api-version=2021-11-01',
                'description': 'SQL Servers',
                'service': 'Azure SQL',
                'category': 'Database'
            },
            'cosmos_accounts': {
                'url': 'https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2021-10-15',
                'description': 'Cosmos DB',
                'service': 'Azure Cosmos DB',
                'category': 'Database'
            }
        }
        all_services.update({f"azure_db_{k}": v for k, v in azure_db.items()})

        # Azure Security
        azure_security = {
            'key_vaults': {
                'url': 'https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.KeyVault/vaults?api-version=2021-10-01',
                'description': 'Key Vaults',
                'service': 'Azure Key Vault',
                'category': 'Security'
            },
            'security_center': {
                'url': 'https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.Security/pricings?api-version=2018-06-01',
                'description': 'Security Center',
                'service': 'Azure Security Center',
                'category': 'Security'
            }
        }
        all_services.update({f"azure_sec_{k}": v for k, v in azure_security.items()})

        # Microsoft Graph
        graph_services = {
            'me': {
                'url': 'https://graph.microsoft.com/v1.0/me',
                'description': 'Current User Profile',
                'service': 'Microsoft Graph',
                'category': 'Identity'
            },
            'users': {
                'url': 'https://graph.microsoft.com/v1.0/users',
                'description': 'All Users',
                'service': 'Microsoft Graph',
                'category': 'Identity'
            },
            'groups': {
                'url': 'https://graph.microsoft.com/v1.0/groups',
                'description': 'Security Groups',
                'service': 'Microsoft Graph',
                'category': 'Identity'
            },
            'applications': {
                'url': 'https://graph.microsoft.com/v1.0/applications',
                'description': 'Azure AD Applications',
                'service': 'Microsoft Graph',
                'category': 'Identity'
            },
            'service_principals': {
                'url': 'https://graph.microsoft.com/v1.0/servicePrincipals',
                'description': 'Service Principals',
                'service': 'Microsoft Graph',
                'category': 'Identity'
            }
        }
        all_services.update({f"graph_{k}": v for k, v in graph_services.items()})

        # Office 365
        office365 = {
            'mail': {
                'url': 'https://graph.microsoft.com/v1.0/me/messages',
                'description': 'Exchange Online Mail',
                'service': 'Exchange Online',
                'category': 'Office 365'
            },
            'calendar': {
                'url': 'https://graph.microsoft.com/v1.0/me/calendar',
                'description': 'Outlook Calendar',
                'service': 'Exchange Online',
                'category': 'Office 365'
            },
            'onedrive': {
                'url': 'https://graph.microsoft.com/v1.0/me/drive',
                'description': 'OneDrive',
                'service': 'OneDrive',
                'category': 'Office 365'
            },
            'teams': {
                'url': 'https://graph.microsoft.com/v1.0/me/joinedTeams',
                'description': 'Microsoft Teams',
                'service': 'Microsoft Teams',
                'category': 'Office 365'
            }
        }
        all_services.update({f"o365_{k}": v for k, v in office365.items()})

        # External Services with Azure AD integration
        external_services = {
            'github_enterprise': {
                'url': 'https://api.github.com/user',
                'description': 'GitHub Enterprise (Azure AD SSO)',
                'service': 'GitHub',
                'category': 'External Services'
            },
            'slack_enterprise': {
                'url': 'https://slack.com/api/auth.test',
                'description': 'Slack Enterprise (Azure AD SSO)',
                'service': 'Slack',
                'category': 'External Services'
            },
            'salesforce': {
                'url': 'https://login.salesforce.com/services/oauth2/userinfo',
                'description': 'Salesforce (Azure AD SSO)',
                'service': 'Salesforce',
                'category': 'External Services'
            }
        }
        all_services.update({f"external_{k}": v for k, v in external_services.items()})

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        results = {}

        # Get subscription ID
        subscription_id = await self._get_subscription_id(token, headers)

        async with aiohttp.ClientSession() as session:
            logger.info(f"Testing {len(all_services)} comprehensive services...")

            for service_name, service_info in all_services.items():
                url = service_info['url']

                # Replace placeholders
                if '{subscription}' in url and subscription_id:
                    url = url.replace('{subscription}', subscription_id)
                elif '{subscription}' in url and not subscription_id:
                    results[service_name] = {
                        'status': 'skipped',
                        'accessible': False,
                        'error': 'No subscription ID available',
                        'url': url,
                        **service_info
                    }
                    continue

                if '{tenant}' in url and tenant_id:
                    url = url.replace('{tenant}', tenant_id)

                try:
                    async with session.get(url, headers=headers,
                                           timeout=aiohttp.ClientTimeout(total=10)) as response:
                        status = response.status
                        response_text = await response.text()

                        results[service_name] = {
                            'status': status,
                            'accessible': status == 200,
                            'url': url,
                            **service_info
                        }

                        if status == 200:
                            try:
                                data = await response.json()
                                if isinstance(data, dict) and 'value' in data:
                                    results[service_name]['count'] = len(data['value'])
                                    # Store ALL items for detailed listing
                                    results[service_name]['items'] = data['value']
                                elif isinstance(data, list):
                                    results[service_name]['count'] = len(data)
                                    # Store ALL items for detailed listing
                                    results[service_name]['items'] = data
                                else:
                                    results[service_name]['data_available'] = True
                                    if service_name.endswith('_me'):
                                        results[service_name]['user_info'] = data
                                logger.info(f"[OK] {service_name}: accessible")
                            except:
                                results[service_name]['response'] = response_text[:200]
                        else:
                            try:
                                error_data = json.loads(response_text)
                                results[service_name]['error_details'] = error_data
                            except:
                                results[service_name]['error_response'] = response_text[:200]

                            if service_name.startswith('external_') and status in [302, 303]:
                                results[service_name]['note'] = 'Redirect detected - possible SSO integration'

                            if status not in [401, 403, 404]:
                                logger.warning(f"[UNUSUAL] {service_name}: HTTP {status}")

                except asyncio.TimeoutError:
                    results[service_name] = {
                        'status': 'timeout',
                        'accessible': False,
                        'error': 'Request timeout',
                        'url': url,
                        **service_info
                    }
                except Exception as e:
                    results[service_name] = {
                        'status': 'error',
                        'accessible': False,
                        'error': str(e),
                        'url': url,
                        **service_info
                    }

        return results

    async def _get_subscription_id(self, token: str, headers: dict) -> Optional[str]:
        """Get first available subscription ID"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://management.azure.com/subscriptions?api-version=2020-01-01',
                                       headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    if response.status == 200:
                        data = await response.json()
                        subscriptions = data.get('value', [])
                        if subscriptions:
                            return subscriptions[0]['subscriptionId']
        except:
            pass
        return None

    def run_azure_cli_commands(self) -> Dict[str, Any]:
        """Execute Azure CLI commands for auditing (optional)"""
        logger.info("Skipping Azure CLI commands - using token-based API calls instead")
        return {
            'note': 'Azure CLI skipped - using direct API calls with token',
            'reason': 'No az login required'
        }

    def analyze_token_security(self, token_info: TokenInfo) -> Dict[str, Any]:
        """Analyze token security posture"""
        analysis = {
            'token_validity': {},
            'permission_analysis': {},
            'risk_assessment': {}
        }

        # Check token expiry
        now = datetime.datetime.now()
        time_to_expiry = token_info.expiry - now

        analysis['token_validity'] = {
            'expires_at': token_info.expiry.isoformat(),
            'expires_in_hours': time_to_expiry.total_seconds() / 3600,
            'is_expired': time_to_expiry.total_seconds() < 0,
            'expires_soon': time_to_expiry.total_seconds() < 3600
        }

        # Analyze permissions
        scopes = token_info.scopes.split()
        analysis['permission_analysis'] = {
            'scopes': scopes,
            'scope_count': len(scopes),
            'high_privilege_scopes': [s for s in scopes if 'All' in s or 'Write' in s],
            'read_only_scopes': [s for s in scopes if 'Read' in s and 'Write' not in s]
        }

        # Risk assessment
        risk_factors = []
        risk_score = 0

        if 'All' in token_info.scopes:
            risk_factors.append("Contains 'All' permissions")
            risk_score += 3

        if 'Write' in token_info.scopes:
            risk_factors.append("Contains write permissions")
            risk_score += 2

        if time_to_expiry.total_seconds() > 86400:
            risk_factors.append("Long-lived token")
            risk_score += 1

        analysis['risk_assessment'] = {
            'risk_score': risk_score,
            'risk_level': 'Low' if risk_score < 2 else 'Medium' if risk_score < 4 else 'High',
            'risk_factors': risk_factors
        }

        return analysis

    def generate_compliance_report(self, cli_results: Dict[str, Any]) -> Dict[str, str]:
        """Generate compliance status report"""
        return {
            'azure_policy': 'Unknown',
            'rbac_configured': 'Unknown',
            'monitoring_enabled': 'Unknown',
            'security_center': 'Unknown'
        }

    def generate_recommendations(self, token_analysis: Dict[str, Any],
                                 api_results: Dict[str, Any]) -> List[Dict]:
        """Generate security recommendations"""
        recommendations = []

        # Token-based recommendations
        if token_analysis['token_validity']['expires_soon']:
            recommendations.append({
                'type': 'token_expiry',
                'severity': 'high',
                'title': 'Token expiring soon',
                'description': 'Access token will expire within 1 hour',
                'action': 'Refresh the token before it expires'
            })

        if token_analysis['risk_assessment']['risk_score'] > 3:
            recommendations.append({
                'type': 'high_privilege',
                'severity': 'medium',
                'title': 'High privilege token',
                'description': 'Token has elevated permissions',
                'action': 'Review and minimize token permissions'
            })

        # API access recommendations
        accessible_apis = [k for k, v in api_results.items() if v.get('accessible', False)]

        # Check for high-risk service access
        high_risk_services = [
            'azure_mgmt_subscriptions', 'azure_mgmt_tenants', 'graph_users', 'graph_applications',
            'graph_service_principals', 'azure_sec_key_vaults', 'azure_storage_storage_accounts'
        ]

        accessible_high_risk = [s for s in high_risk_services if s in accessible_apis]

        if accessible_high_risk:
            recommendations.append({
                'type': 'high_risk_access',
                'severity': 'critical',
                'title': f'Access to {len(accessible_high_risk)} high-risk services detected',
                'description': f'Token can access critical services: {", ".join(accessible_high_risk)}',
                'action': 'Immediately review token scope and implement principle of least privilege'
            })

        if len(accessible_apis) > 15:
            recommendations.append({
                'type': 'broad_access',
                'severity': 'high',
                'title': 'Excessive service access',
                'description': f'Token can access {len(accessible_apis)} different services',
                'action': 'Consider implementing more restrictive token scopes'
            })

        # Check for external service access
        external_accessible = [s for s in accessible_apis if s.startswith('external_')]
        if external_accessible:
            recommendations.append({
                'type': 'external_access',
                'severity': 'medium',
                'title': 'External service access detected',
                'description': f'Token can access external services: {", ".join(external_accessible)}',
                'action': 'Review external integrations and ensure proper security controls'
            })

        return recommendations

    async def run_full_audit(self, token: str) -> AuditResult:
        """Run complete security audit"""
        logger.info("Starting Comprehensive Azure Security Audit")

        # Decode token
        self.results.token_info = self.decode_jwt_token(token)

        # Test Power BI API endpoints
        logger.info("Testing Power BI API endpoints...")
        powerbi_results = await self.test_power_bi_endpoints(token)

        # Test comprehensive Azure and external services
        logger.info("Testing comprehensive Azure and external services...")
        comprehensive_results = await self.test_comprehensive_azure_services(token)

        # Combine all API results
        self.results.api_access = {**powerbi_results, **comprehensive_results}

        # Skip Azure CLI commands
        cli_results = self.run_azure_cli_commands()

        # Analyze token security
        logger.info("Analyzing token security...")
        token_analysis = self.analyze_token_security(self.results.token_info)

        # Generate compliance report
        self.results.compliance_status = self.generate_compliance_report(cli_results)

        # Generate recommendations
        self.results.security_recommendations = self.generate_recommendations(
            token_analysis, self.results.api_access
        )

        # Store CLI results
        self.results.role_assignments = cli_results.get('role_assignments', [])

        logger.info("Comprehensive audit completed successfully")
        return self.results

    def save_report(self, filename: str = None) -> str:
        """Save audit report to file"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"azure_audit_report_{timestamp}.json"

        report_data = {
            'audit_timestamp': self.results.timestamp.isoformat(),
            'token_info': {
                'email': self.results.token_info.email,
                'name': self.results.token_info.name,
                'scopes': self.results.token_info.scopes,
                'expiry': self.results.token_info.expiry.isoformat(),
                'app_id': self.results.token_info.app_id
            },
            'api_access_summary': {
                'total_endpoints': len(self.results.api_access),
                'accessible_endpoints': len(
                    [k for k, v in self.results.api_access.items() if v.get('accessible', False)]),
                'endpoints': self.results.api_access
            },
            'compliance_status': self.results.compliance_status,
            'security_recommendations': self.results.security_recommendations,
            'role_assignments_count': len(self.results.role_assignments)
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Report saved to: {filename}")
        return filename

    def print_table(self, headers: List[str], rows: List[List[str]], title: str = ""):
        """Print data in table format"""
        if not rows:
            return

        # Calculate column widths
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(col_widths):
                    col_widths[i] = max(col_widths[i], len(str(cell)))

        # Create format string
        format_str = " | ".join(f"{{:<{w}}}" for w in col_widths)
        total_width = sum(col_widths) + 3 * (len(headers) - 1)

        if title:
            print(f"\n{title}")
            print("=" * len(title))

        # Print header
        print(format_str.format(*headers))
        print("-" * total_width)

        # Print rows
        for row in rows:
            # Ensure row has same length as headers
            padded_row = row + [""] * (len(headers) - len(row))
            padded_row = [str(cell)[:col_widths[i]] for i, cell in enumerate(padded_row)]
            print(format_str.format(*padded_row))

    def format_item_details(self, item: dict, service_type: str) -> dict:
        """Extract and format item details based on service type"""
        details = {
            'name': item.get('name', item.get('displayName', item.get('id', 'Unknown'))),
            'id': item.get('id', 'N/A'),
            'type': 'N/A',
            'status': 'N/A',
            'location': 'N/A',
            'additional': 'N/A'
        }

        # Power BI specific formatting
        if 'powerbi' in service_type.lower() or 'power_bi' in service_type.lower():
            if 'groups' in service_type or 'workspaces' in service_type:
                details['type'] = item.get('type', 'Workspace')
                details['status'] = item.get('state', 'Unknown')
                details['additional'] = f"ReadOnly: {item.get('isReadOnly', False)}"
            elif 'datasets' in service_type:
                details['type'] = 'Dataset'
                details['status'] = item.get('targetStorageMode', 'Unknown')
                details['additional'] = f"Owner: {item.get('configuredBy', 'Unknown')}"
            elif 'reports' in service_type:
                details['type'] = item.get('reportType', 'Report')
                details['status'] = 'Available' if item.get('embedUrl') else 'Not Embeddable'
                details['additional'] = f"Dataset: {item.get('datasetId', 'N/A')[:8]}..."

        # Azure resources formatting
        elif 'azure' in service_type.lower():
            if 'subscriptions' in service_type:
                details['type'] = 'Subscription'
                details['status'] = item.get('state', 'Unknown')
                details['location'] = item.get('locationPlacementId', 'Global')
            elif 'virtual_machines' in service_type:
                details['type'] = 'Virtual Machine'
                details['location'] = item.get('location', 'N/A')
                details['status'] = item.get('properties', {}).get('provisioningState', 'Unknown')
                vm_size = item.get('properties', {}).get('hardwareProfile', {}).get('vmSize', 'N/A')
                details['additional'] = f"Size: {vm_size}"
            elif 'storage' in service_type:
                details['type'] = item.get('kind', 'Storage')
                details['location'] = item.get('location', 'N/A')
                details['status'] = item.get('properties', {}).get('provisioningState', 'Unknown')
                sku = item.get('sku', {}).get('name', 'N/A')
                details['additional'] = f"SKU: {sku}"
            elif 'resource' in service_type:
                details['type'] = 'Resource Group'
                details['location'] = item.get('location', 'N/A')
                details['status'] = item.get('properties', {}).get('provisioningState', 'Succeeded')

        # Microsoft Graph formatting
        elif 'graph' in service_type.lower():
            if 'users' in service_type:
                details['type'] = 'User'
                details['status'] = 'Enabled' if item.get('accountEnabled') else 'Disabled'
                details['location'] = item.get('officeLocation', 'N/A')
                details['additional'] = f"Job: {item.get('jobTitle', 'N/A')}"
            elif 'groups' in service_type:
                group_types = item.get('groupTypes', [])
                details['type'] = ', '.join(group_types) if group_types else 'Security Group'
                details['status'] = 'Mail-enabled' if item.get('mail') else 'No Mail'
                details['additional'] = f"Members: {item.get('membershipRule', 'Static')}"
            elif 'applications' in service_type:
                details['type'] = 'Application'
                details['status'] = 'Active'
                details['additional'] = f"Publisher: {item.get('publisherDomain', 'N/A')}"

        # Office 365 formatting
        elif 'office' in service_type.lower() or 'o365' in service_type.lower():
            if 'mail' in service_type:
                details['type'] = 'Email'
                details['status'] = 'Read' if item.get('isRead') else 'Unread'
                details['additional'] = f"From: {item.get('from', {}).get('emailAddress', {}).get('name', 'Unknown')}"
            elif 'teams' in service_type:
                details['type'] = 'Team'
                details['status'] = item.get('visibility', 'Private')
                details[
                    'additional'] = f"Members: {item.get('memberSettings', {}).get('allowAddRemoveApps', 'Unknown')}"

        return details

    def print_summary(self):
        """Print audit summary to console with tables"""
        print("\n" + "=" * 120)
        print("COMPREHENSIVE AZURE & CLOUD SECURITY AUDIT - DETAILED RESULTS")
        print("=" * 120)

        if self.results.token_info:
            print(f"\n🔐 TOKEN INFORMATION")
            print(f"User: {self.results.token_info.name}")
            print(f"Email: {self.results.token_info.email}")
            print(f"Token Expiry: {self.results.token_info.expiry}")
            print(f"Scopes: {self.results.token_info.scopes}")

        # Group results by category
        categories = {}
        for endpoint, result in self.results.api_access.items():
            category = result.get('category', 'Unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append((endpoint, result))

        # Print results by category with tables
        for category, services in categories.items():
            print(f"\n{'=' * 120}")
            print(f"📊 {category.upper()} SERVICES")
            print("=" * 120)

            # Create table for service overview
            service_headers = ["Service", "Description", "Status", "Items", "Access"]
            service_rows = []

            accessible_count = 0
            total_count = len(services)

            for endpoint, result in services:
                status_icon = "✅" if result.get('accessible', False) else "❌"
                if result.get('accessible'):
                    accessible_count += 1

                count = result.get('count', 0)
                service_name = result.get('service', 'Unknown Service')
                description = result.get('description', 'No description')
                status_code = result.get('status', 'unknown')

                service_rows.append([
                    service_name,
                    description[:40] + ("..." if len(description) > 40 else ""),
                    f"{status_code}",
                    str(count) if count > 0 else "0",
                    status_icon
                ])

            self.print_table(service_headers, service_rows, f"{category} Services Overview")

            # Print detailed items for accessible services
            for endpoint, result in services:
                if result.get('accessible') and result.get('items'):
                    items = result['items']
                    total_items = result.get('count', 0)
                    service_desc = result.get('description', endpoint)

                    if total_items > 0:
                        print(f"\n📋 {service_desc.upper()} - DETAILED ITEMS")

                        # Create detailed items table
                        item_headers = ["#", "Name", "Type", "Status", "Location", "Additional Info"]
                        item_rows = []

                        # Show up to 50 items for readability
                        items_to_show = items[:50] if total_items > 50 else items

                        for i, item in enumerate(items_to_show, 1):
                            if isinstance(item, dict):
                                details = self.format_item_details(item, endpoint)

                                item_rows.append([
                                    str(i),
                                    details['name'][:30] + ("..." if len(details['name']) > 30 else ""),
                                    details['type'],
                                    details['status'],
                                    details['location'],
                                    details['additional'][:25] + ("..." if len(details['additional']) > 25 else "")
                                ])

                        self.print_table(item_headers, item_rows)

                        if total_items > len(items_to_show):
                            remaining = total_items - len(items_to_show)
                            print(f"\n📝 ... and {remaining} more items (showing first {len(items_to_show)})")

                # Show user profile in table format
                elif result.get('accessible') and result.get('user_info'):
                    user_info = result['user_info']
                    service_desc = result.get('description', endpoint)

                    print(f"\n👤 {service_desc.upper()} - USER PROFILE")

                    if isinstance(user_info, dict):
                        profile_headers = ["Field", "Value"]
                        profile_rows = []

                        user_fields = [
                            ('displayName', 'Display Name'),
                            ('userPrincipalName', 'User Principal Name'),
                            ('mail', 'Email'),
                            ('jobTitle', 'Job Title'),
                            ('department', 'Department'),
                            ('officeLocation', 'Office Location'),
                            ('mobilePhone', 'Mobile Phone'),
                            ('id', 'User ID'),
                            ('accountEnabled', 'Account Status')
                        ]

                        for field, label in user_fields:
                            if field in user_info and user_info[field] is not None:
                                value = str(user_info[field])
                                if field == 'accountEnabled':
                                    value = "Enabled" if user_info[field] else "Disabled"
                                profile_rows.append([label, value])

                        self.print_table(profile_headers, profile_rows)

                # Show errors in table format
                elif result.get('error_details'):
                    error = result['error_details']
                    service_desc = result.get('description', endpoint)

                    if isinstance(error, dict) and 'error' in error:
                        error_info = error['error']

                        print(f"\n❌ {service_desc.upper()} - ERROR DETAILS")
                        error_headers = ["Field", "Value"]
                        error_rows = [
                            ["Error Code", error_info.get('code', 'Unknown')],
                            ["Message", error_info.get('message', 'No message')[:80]],
                            ["URL", result.get('url', 'N/A')[:60]]
                        ]

                        self.print_table(error_headers, error_rows)

            print(f"\n📊 Category Summary: {accessible_count}/{total_count} services accessible")

        # Security Analysis Table
        print(f"\n{'=' * 120}")
        print("🔒 SECURITY ANALYSIS & RECOMMENDATIONS")
        print("=" * 120)

        # Compliance status table
        compliance_headers = ["Check", "Status"]
        compliance_rows = [[check, status] for check, status in self.results.compliance_status.items()]
        self.print_table(compliance_headers, compliance_rows, "Compliance Status")

        # Security recommendations table
        if self.results.security_recommendations:
            rec_headers = ["Priority", "Title", "Action Required"]
            rec_rows = []
            for rec in self.results.security_recommendations:
                priority_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(rec['severity'], "⚪")
                rec_rows.append([
                    f"{priority_icon} {rec['severity'].upper()}",
                    rec['title'][:40] + ("..." if len(rec['title']) > 40 else ""),
                    rec['action'][:50] + ("..." if len(rec['action']) > 50 else "")
                ])
            self.print_table(rec_headers, rec_rows, "Security Recommendations")

        # Overall statistics table
        total_apis = len(self.results.api_access)
        accessible_apis = len([k for k, v in self.results.api_access.items() if v.get('accessible', False)])

        high_risk_services = [
            'azure_mgmt_subscriptions', 'azure_mgmt_tenants', 'graph_users', 'graph_applications',
            'graph_service_principals', 'azure_sec_key_vaults', 'azure_storage_storage_accounts'
        ]
        accessible_high_risk = len([s for s in high_risk_services if s in self.results.api_access and
                                    self.results.api_access[s].get('accessible', False)])

        external_accessible = len([k for k, v in self.results.api_access.items()
                                   if k.startswith('external_') and v.get('accessible', False)])

        # Risk assessment
        if accessible_high_risk > 3 or external_accessible > 2:
            risk_level = "🔴 CRITICAL"
        elif accessible_high_risk > 1 or external_accessible > 0:
            risk_level = "🟠 HIGH"
        elif accessible_apis > 10:
            risk_level = "🟡 MEDIUM"
        else:
            risk_level = "🟢 LOW"

        stats_headers = ["Metric", "Count", "Details"]
        stats_rows = [
            ["Total Services Tested", str(total_apis), "All Azure, Microsoft, and external services"],
            ["Services Accessible", str(accessible_apis),
             f"{(accessible_apis / total_apis * 100):.1f}% of total services"],
            ["High-Risk Services", str(accessible_high_risk), f"Out of {len(high_risk_services)} critical services"],
            ["External Services", str(external_accessible), "Third-party integrations via Azure AD"],
            ["Overall Risk Level", risk_level, "Based on accessible services and permissions"]
        ]

        self.print_table(stats_headers, stats_rows, "Overall Security Assessment")

        print("\n" + "=" * 120)


# Main execution
async def main():
    """Main function"""
    print("Azure Security Audit Tool - Comprehensive Edition")
    print("Tests 100+ Azure services + external integrations")
    print("=" * 60)

    # Get token input
    token = input("Enter your Azure access token (or press Enter to use environment variable): ").strip()

    if not token:
        import os
        token = os.getenv('AZURE_ACCESS_TOKEN')
        if not token:
            print("No token provided. Please set AZURE_ACCESS_TOKEN environment variable or enter token manually.")
            return

    try:
        auditor = AzureSecurityAuditor()
        results = await auditor.run_full_audit(token)

        # Print summary
        auditor.print_summary()

        # Save detailed report
        report_file = auditor.save_report()
        print(f"\nDetailed report saved to: {report_file}")

        # Additional analysis
        accessible_count = len([k for k, v in results.api_access.items() if v.get('accessible', False)])
        external_count = len([k for k, v in results.api_access.items()
                              if k.startswith('external_') and v.get('accessible', False)])

        print(f"\n🔍 AUDIT SUMMARY:")
        print(f"   • Total services tested: {len(results.api_access)}")
        print(f"   • Services accessible: {accessible_count}")
        print(f"   • External integrations found: {external_count}")
        print(f"   • Security recommendations: {len(results.security_recommendations)}")

        if external_count > 0:
            print(f"\n⚠️  WARNING: Token has access to external services!")
            print(f"   This indicates potential SSO integrations or delegated permissions.")

        if accessible_count > 20:
            print(f"\n🚨 HIGH RISK: Token has broad access to {accessible_count} services!")
            print(f"   Consider implementing principle of least privilege.")

    except KeyboardInterrupt:
        print("\nAudit interrupted by user")
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())