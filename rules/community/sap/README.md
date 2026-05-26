# SAP Detection Rules and Data Tables for Google SecOps

This repository contains a set of Chronicle YARAL detection rules and reference
data tables designed to monitor security-relevant events in SAP environments.
These rules leverage SAP Security Audit logs, Change Documents, and HANA
Database logs to detect potential threats, unauthorized access, and
configuration changes.

## Overview

SAP systems are critical infrastructure that require robust security monitoring.
These rules help security teams identify:

- Unauthorized logins and use of "break-glass" accounts.
- Assignment of sensitive roles and profiles.
- Direct access to sensitive database tables.
- Unauthorized execution of sensitive ABAP programs and function modules.
- Configuration changes to security logging and audit trails.
- Suspicious activities like data exfiltration or impossible travel.

## How to Use These Rules

1.  **Download the Rules**: Download the `.yaral` files from this directory.
2.  **Import into Google SecOps**:
    - Log in to your Google SecOps instance.
    - Navigate to **Detection** > **Rules Editor**.
    - Click **Import** and upload the `.yaral` files.
3.  **Enable Rules**: Review the logic and metadata, and then enable the rules
    you wish to monitor.

## Reference Data Tables

Several rules utilize **Data Tables** to maintain lists of sensitive entities
(e.g., roles, users, tables). Sample values are provided in the `data_tables/`
directory.

### Customizing Data Tables
The provided `.csv` files are for reference. Customers **must** modify these
tables with values appropriate for their specific SAP landscape before importing
them into Google SecOps as Data Tables.

1.  Navigate to **Detection** > **Data Tables**.
2.  Create a new Data Table and upload your customized CSV file.
3.  Ensure the Data Table name matches the one referenced in the YARAL rules
    (e.g., `sap_sensitive_roles`).

## List of Detection Rules

| Rule Name | Description |
| :--- | :--- |
| **SAP - Standard Login** | Alerts on default SAP admin logins. |
| **SAP - Brute Force RFC** | Detects multiple failed RFC logon attempts. |
| **SAP - Profile Assign** | Detects privileged profiles via Change Docs. |
| **SAP - Auth Assign** | Detects high-privilege roles via log correlation. |
| **SAP - Auth Change** | Detects changes to critical SAP auth values. |
| **SAP - Debug Change** | Detects data modification during ABAP debugging. |
| **SAP - Audit Log Disable** | Detects when the SAP Audit Log is deactivated. |
| **SAP - Sensitive ABAP** | Detects execution of sensitive ABAP programs. |
| **SAP - FM Testing** | Detects direct testing of SAP function modules. |
| **SAP - Gateway Bypass** | Detects attempts to bypass SAP Gateway ACLs. |
| **SAP - Gateway UFO** | Detects unauthorized access to Gateway UFO table. |
| **HANA DB - Admin Auth** | Detects HANA DB admin auth assignments. |
| **HANA DB - Audit Policy** | Detects HANA DB audit trail policy changes. |
| **HANA DB - Audit Disable** | Detects deactivation of HANA DB audit trail. |
| **HANA DB - User Admin** | Detects admin actions on HANA DB users. |
| **SAP - Impossible Travel** | Detects distant logins in short timeframes. |
| **SAP - Password Change** | Detects multiple password changes. |
| **SAP - Audit Config** | Detects SAP Audit Log configuration changes. |
| **SAP - User Lifecycle** | Detects user creation/deletion/unlock events. |
| **SAP - Sensitive RFC** | Detects execution of sensitive RFC modules. |
| **SAP - Role Correlation** | Correlates logs for sensitive role assignments. |
| **SAP - Role Auth Mod** | Detects auth changes in sensitive SAP roles. |
| **SAP - Table Access** | Direct access to sensitive tables via RFC. |
| **SAP - Exfiltration** | Detects activity patterns indicating exfiltration. |
| **SAP - System Config** | Detects SAP system/client config changes. |
| **SAP - User Creation** | Detects a user creating and then using an account. |

## Required Data Tables

The following six tables must be maintained within the SecOps environment. These
lists act as filters for identifying unauthorized activity versus standard
administrative tasks.

### 1. `sap_admin_users`
**Context:** Contains User IDs for authorized personnel,
such as Basis, Security, and System Administrators.

* **Column Name:** user
* **Rule Impact:** Suppresses false positives by excluding known-good administrative activity from critical alerts (e.g., User Creation, Password Resets).

### 2. `sap_sensitive_abap_programs`
**Context:** High-risk ABAP reports capable of bypassing standard transaction-
level security.

* **Column Name:** abap_program
* **Rule Impact:** Triggers the `sap_execution_of_sensitive_abap_program` rule when these programs are started directly.

### 3. `sap_sensitive_function_modules`
**Context:** RFC-enabled modules that allow remote system interaction, user
manipulation, or mass data calls.

* **Column Name:** module
* **Rule Impact:** Triggers the `sap_sensitive_rfc_function_module_execution` rule when these function modules are executed.

### 4. `sap_sensitive_profiles`
**Context:** Authorization profiles that grant wide-ranging system access or
require close monitoring.

* **Column Name:** profile
* **Rule Impact:** Monitors for the assignment of these profiles within the `IDENTITY` object class.

### 5. `sap_sensitive_roles`
**Context:** Security roles defined by the organization as having high business
impact or administrative power.

* **Column Name:** role
* **Rule Impact:** Monitors for role assignments to new accounts or unauthorized users in the `AGR_USERS` table.

### 6. `sap_sensitive_tables`
**Context:** Database tables containing sensitive technical configurations,
credentials, or PII.

* **Column Name:** name
* **Rule Impact:** Triggers alerts when these tables are queried directly via RFC calls .

## Implementation Standards

| Category | Requirement |
| :--- | :--- |
| **Case Sensitivity** | All entries must be in **UPPERCASE**. SAP logs store User IDs, Roles, and Programs in uppercase; lowercase entries will result in missed detections. |
| **Maintenance** | Lists should be reviewed quarterly or following any major SAP transport cycle where new `Z` programs or roles are introduced. |

[!WARNING]
 **Test Before Deploying:** These SAP community detection rules serve as
 foundational templates. Because every SAP environment is unique, you should
 thoroughly test all rules against historical data and modify their logic as
 needed to match your specific logging structures and security use cases.
