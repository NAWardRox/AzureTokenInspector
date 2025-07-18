# Azure Security Audit Tool

A comprehensive security assessment tool for Azure resources and permissions. Tests 100+ Azure services, Microsoft Graph APIs, and external integrations to identify potential security misconfigurations and excessive permissions.

## 🔍 Features

- **Comprehensive Coverage**: Tests Azure Management, Microsoft Graph, Office 365, Power Platform, and external services
- **Token-Based Authentication**: No Azure CLI login required - works with access tokens
- **External Integration Detection**: Identifies SSO integrations with third-party services
- **Risk Assessment**: Automated security analysis with actionable recommendations
- **Detailed Reporting**: JSON export and formatted console output with tables
- **Cross-Platform**: Works on Windows, Linux, and macOS

## 📋 Prerequisites

- Python 3.7+
- Required packages: `aiohttp`, `requests`

```bash
pip install aiohttp requests
```

## 🚀 Usage

### Basic Usage
```bash
python azure_security_audit.py
```

### With Environment Variable
```bash
export AZURE_ACCESS_TOKEN="your_token_here"
python azure_security_audit.py
```

## 📊 Sample Output

```
COMPREHENSIVE AZURE & CLOUD SECURITY AUDIT - DETAILED RESULTS
================================================================================

🔐 TOKEN INFORMATION
User: Resort
Email: XXXX@NAWardRox.me
Token Expiry: 2025-07-18 15:30:00
Scopes: Content.Create Dataset.ReadWrite.All Report.ReadWrite.All

================================================================================
📊 POWER PLATFORM SERVICES
================================================================================

Power Platform Services Overview
================================================================================
Service          | Description                 | Status | Items | Access
Power BI         | Power BI Workspaces/Groups  | 200    | 2     | ✅
Power BI         | Power BI Datasets          | 200    | 0     | ✅
Power BI         | Power BI Reports           | 200    | 0     | ✅
Power BI         | Power BI Dashboards        | 401    | 0     | ❌

📋 POWER BI WORKSPACES/GROUPS - DETAILED ITEMS
================================================================================
# | Name                    | Type      | Status | Location | Additional Info
1 | PRODUCT..VP... | Workspace | Active | N/A      | ReadOnly: False
2 | STG.alpha.NAWardRox       | Workspace | Active | N/A      | ReadOnly: False

📊 Category Summary: 3/4 services accessible

================================================================================
🔒 SECURITY ANALYSIS & RECOMMENDATIONS
================================================================================

Security Recommendations
================================================================================
Priority      | Title                     | Action Required
🟠 HIGH       | Token expiring soon       | Refresh the token before expiry
🟡 MEDIUM     | High privilege token      | Review and minimize permissions

Overall Security Assessment
================================================================================
Metric               | Count | Details
Total Services Tested| 45    | All Azure, Microsoft, and external services
Services Accessible  | 12    | 26.7% of total services
High-Risk Services   | 0     | Out of 7 critical services
External Services    | 0     | Third-party integrations via Azure AD
Overall Risk Level   | 🟡 MEDIUM | Based on accessible services and permissions
```

## 🎯 What It Tests

### Azure Services
- **Core Management**: Subscriptions, Tenants, Resource Groups
- **Compute**: Virtual Machines, App Services, Kubernetes, Functions
- **Storage**: Storage Accounts, Files, Backup Vaults
- **Database**: SQL Servers, Cosmos DB, Redis
- **Security**: Key Vault, Security Center, Sentinel
- **AI & Analytics**: Cognitive Services, Machine Learning, Synapse
- **Networking**: Virtual Networks, Load Balancers, CDN

### Microsoft Cloud Services
- **Microsoft Graph**: Users, Groups, Applications, Service Principals
- **Office 365**: Exchange, SharePoint, OneDrive, Teams
- **Power Platform**: Power BI, Power Apps, Power Automate
- **Business Apps**: Dynamics 365

### External Integrations
- **SSO Services**: GitHub Enterprise, Slack, Salesforce
- **Cloud Platforms**: AWS SSO, Google Workspace
- **SaaS Applications**: Box, Dropbox, Adobe, Zoom

## 🔐 Security Analysis

The tool performs comprehensive security analysis including:

- **Token Validation**: Expiry time, scope analysis, privilege assessment
- **Risk Scoring**: Based on accessible services and permission levels
- **Compliance Checks**: Policy assignments, RBAC configuration
- **External Access**: Third-party service integrations via Azure AD
- **Recommendations**: Actionable security improvements

## 📄 Output Formats

### Console Output
- Formatted tables with service details
- Color-coded status indicators
- Comprehensive item listings
- Security recommendations

### JSON Report
```json
{
  "audit_timestamp": "2025-07-18T12:30:00",
  "token_info": {
    "email": "user@company.com",
    "scopes": "Dataset.ReadWrite.All Report.ReadWrite.All",
    "expiry": "2025-07-18T15:30:00"
  },
  "api_access_summary": {
    "total_endpoints": 45,
    "accessible_endpoints": 12,
    "endpoints": {...}
  },
  "security_recommendations": [...],
  "compliance_status": {...}
}
```

## ⚡ Key Benefits

- **No Azure CLI Required**: Works with any valid access token
- **Comprehensive Coverage**: Tests 100+ services across Microsoft ecosystem
- **Security Focused**: Identifies misconfigurations and excessive permissions
- **External Detection**: Discovers third-party integrations
- **Actionable Results**: Provides specific security recommendations
- **Enterprise Ready**: Suitable for compliance and security audits

## 🔧 Token Requirements

The tool works with Azure access tokens that have appropriate scopes. Common token sources:
- Azure Portal (Developer Tools → Network tab)
- Azure CLI: `az account get-access-token`
- PowerShell: `Get-AzAccessToken`
- Application registrations with delegated permissions

## 🛡️ Security Considerations

- Never share access tokens publicly
- Tokens should be rotated regularly
- Review and minimize token scopes
- Monitor token usage and access patterns
- Implement proper approval processes for administrative tokens

## 📝 License

MIT License - see LICENSE file for details.

## ⚠️ Disclaimer

This tool is for authorized security assessment purposes only. Ensure you have proper permissions before testing any Azure environment.