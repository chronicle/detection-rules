# SAP Detection Rules and Data Tables for Google SecOps

This repository contains a set of Chronicle YARA-L detection rules and reference
data tables designed to monitor security-relevant events in SAP environments.
These rules leverage SAP Security Audit logs, Change Documents, SAP Business
Technology Platform (BTP) Audit logs, and SAP HANA Database logs to detect
potential threats, unauthorized access, and configuration changes.

## Overview

SAP systems are critical infrastructure that require robust security monitoring.
These rules help security teams identify:

- Unauthorized logins, brute-force attempts, and use of "break-glass" or
  privileged accounts.
- Assignment and modification of sensitive roles, profiles, and authorizations.
- Direct or generic table browser access to sensitive database tables.
- Unauthorized execution of sensitive, deprecated, or dynamically generated ABAP
  programs and RFC function modules.
- Configuration changes to security logging, audit trails, system changeability,
  and SAP BTP subaccounts, trust configurations, and Work Zone roles.
- Suspicious activities such as ABAP debugging in production, credential resets
  from shared IPs, unapproved FTP sessions, and bulk data downloads.

## How to Use These Rules

1.  **Download the Rules**: Download the `.yaral` files from this directory.
2.  **Import into Google SecOps**:
    - Log in to your Google SecOps instance.
    - Navigate to **Detection** > **Rules & Detections** > **Rules Editor**.
    - Click **Import** and upload the `.yaral` files (or synchronize using the
      `content_manager` tool).
3.  **Enable Rules**: Review the logic and metadata, and then enable the rules
    you wish to monitor.

## Reference Data Tables

Several rules utilize **Data Tables** to maintain lists of sensitive or excluded
entities (e.g., roles, users, tables, programs, network ranges). Sample values
are provided in the `data_tables/` directory.

### Customizing Data Tables

The provided `.csv` files are for reference. Customers **must** modify these
tables with values appropriate for their specific SAP landscape before importing
them into Google SecOps as Data Tables.

1.  Navigate to **Detection** > **Data Tables** (or **Investigation** > **Data
    Tables**).
2.  Create a new Data Table and upload your customized CSV file (or synchronize
    using `content_manager data-tables`).
3.  Ensure the Data Table name matches the exact name referenced in the YARA-L
    rules (e.g., `sap_sensitive_roles`).

## List of Detection Rules

| Rule File | Description |
| :--- | :--- |
| `sap_abap_debugger_session_activity.yaral` | Detects when a user starts or interacts with the ABAP debugger on a production system. |
| `sap_account_unlocked_then_used_from_same_ip.yaral` | Detects when an account is unlocked and then authenticated from the same IP as the account that unlocked it. |
| `sap_audit_log_volume_monitor.yaral` | Detects when an SAP user generates audit records above the configured hourly threshold for their system. |
| `sap_audit_message_id_absent_from_monitoring_config.yaral` | Detects when an SAP audit message ID appears in logs but is absent from the monitoring configuration table. |
| `sap_break_glass_account_login.yaral` | Alerts whenever a default SAP administrative account (e.g., `SAP*`, `DDIC`, `TMSADM`, `EARLYWATCH`) logs into the system. |
| `sap_brute_force_rfc_logon.yaral` | Identifies brute-force RFC logon attempts from a single IP across multiple systems or clients within 1 hour. |
| `sap_btp_emergency_administrator_assignment.yaral` | Detects when a user is added to an SAP BTP role collection carrying subaccount, directory, or global account administrator rights. |
| `sap_btp_identity_provider_trust_manipulation.yaral` | Detects when an SAP BTP identity provider trust configuration is created, modified, or deleted. |
| `sap_btp_mass_user_creation_or_deletion.yaral` | Detects when a single actor creates or deletes SAP BTP subaccount users in bulk. |
| `sap_btp_service_manager_instance_or_binding_change.yaral` | Detects when an SAP BTP service instance or service binding is created, modified, or deleted through the Service Manager API. |
| `sap_btp_subaccount_deleted.yaral` | Detects when an SAP BTP subaccount entity is deleted from the global account. |
| `sap_btp_tenant_audit_log_silent.yaral` | Detects when a recently active SAP BTP tenant stops producing audit logs. |
| `sap_btp_workzone_role_collection_tampering.yaral` | Detects when a Build Work Zone role is added to or removed from an SAP BTP role collection. |
| `sap_btp_workzone_site_creation.yaral` | Detects when a Build Work Zone site is created or its content is modified. |
| `sap_bulk_download_following_restricted_object_access.yaral` | Detects when a user downloads a large volume of data shortly after accessing a restricted table, program, or transaction. |
| `sap_change_documents_sensitive_profile_assignment.yaral` | Detects the assignment of highly privileged SAP profiles via Change Documents (static list). |
| `sap_change_documents_sensitive_profile_assignment_data_table.yaral` | Detects the assignment of highly privileged SAP profiles via Change Documents using `sap_sensitive_profiles`. |
| `sap_change_documents_sensitive_role_assignment.yaral` | Detects the assignment of highly privileged SAP roles via Change Documents using `sap_sensitive_roles`. |
| `sap_credential_reset_followed_by_use_from_shared_ip.yaral` | Detects when a privileged account's credentials are reset and then used from an IP the resetting account also used. |
| `sap_critical_authorization_value_changed.yaral` | Detects the modification of sensitive authorization objects (`CD1251`) within a role via `PFCG`. |
| `sap_critical_role_assigned_to_new_user.yaral` | Detects the assignment of high-privilege roles by correlating Change Documents (`PFCG`) with Security Audit logs (`AUD`). |
| `sap_data_changed_during_debugging.yaral` | Detects in-memory data changes (`CUL`) during an ABAP debugging session. |
| `sap_deactivation_of_security_audit_log.yaral` | Detects the deactivation of the SAP Security Audit Log (`AUJ`). |
| `sap_deprecated_abap_program_started.yaral` | Detects when a user starts an ABAP program on the deprecated or unsafe program list (`sap_obsolete_programs`). |
| `sap_deprecated_function_module_invoked.yaral` | Detects when a user invokes a function module on the deprecated or unsafe module list (`sap_obsolete_function_modules`). |
| `sap_dialog_logon_from_unlisted_network_range.yaral` | Detects when a user authenticates to SAP from an IP address outside approved network ranges. |
| `sap_download_from_threat_intel_matched_ip.yaral` | Detects when a file is downloaded from an SAP system by a host matching a threat intelligence indicator. |
| `sap_dynamic_abap_program_observed.yaral` | Detects dynamic ABAP coding events (`BU4` Insert, Generate, or Delete) not excluded by transaction allowlists. |
| `sap_execution_of_sensitive_abap_program.yaral` | Detects the execution of high-risk ABAP programs (`AUW`) listed in `sap_sensitive_abap_programs`. |
| `sap_ftp_allowlist_empty_or_wildcarded.yaral` | Detects when the SAP FTP server allowlist (`SAPFTP_SERVERS`) is empty or populated with wildcard entries. |
| `sap_ftp_session_to_unapproved_host.yaral` | Detects when an SAP process opens an FTP session to a host absent from `sap_ftp_safe_servers`. |
| `sap_function_module_testing_detected.yaral` | Detects direct execution and testing of SAP Function Modules via the `SE37` test frame (`AU7` followed by `BU4`). |
| `sap_hanadb_assign_admin_authorizations.yaral` | Detects the assignment of administrative privileges or roles within SAP HANA DB. |
| `sap_hanadb_audit_trail_policy_changes.yaral` | Detects changes to SAP HANA audit policies (Create, Alter, Drop). |
| `sap_hanadb_deactivation_of_audit_trail.yaral` | Detects the deactivation of the global auditing state in SAP HANA. |
| `sap_hanadb_user_admin_actions.yaral` | Detects administrative user management (Create, Alter, Drop) and schema deletion within SAP HANA DB. |
| `sap_impossible_travel.yaral` | Identifies two successful logons for the same User ID from geographically distant locations within an impossible travel window. |
| `sap_kerberos_spnego_replay_attempt.yaral` | Detects when a SPNEGO authentication token is replayed against an SAP system. |
| `sap_logon_failed_invalid_client.yaral` | Detects failed internal SAP logon attempts (`AU2`) targeting an invalid or non-existent client. |
| `sap_multi_terminal_logon.yaral` | Identifies successful logons for the same User ID from multiple terminal IDs or client hostnames in a short timeframe. |
| `sap_multiple_password_changes.yaral` | Detects multiple password changes (`BU2`) by a single actor or targeting a single user across systems. |
| `sap_privileged_account_altered_another_account.yaral` | Detects when a privileged SAP account modifies the user record of a different account. |
| `sap_privileged_account_logon_activity.yaral` | Detects when a privileged SAP account succeeds or fails a logon on a production system. |
| `sap_privileged_account_logon_sweep_from_single_ip.yaral` | Detects when a privileged SAP account attempts logons across multiple systems or clients from one source IP. |
| `sap_privileged_account_master_record_modified.yaral` | Detects when a privileged SAP account's user record or authorizations are modified. |
| `sap_restricted_table_read_via_table_browser.yaral` | Detects when a dialog user reads a restricted table (`sap_sensitive_tables`) through a generic table browser transaction. |
| `sap_restricted_transaction_started.yaral` | Detects when a user starts a transaction code listed in `sap_sensitive_transactions`. |
| `sap_rfc_call_with_runtime_resolved_destination.yaral` | Detects when an ABAP program invokes a remote function call using a destination resolved at runtime (`FU2`). |
| `sap_security_audit_log_configuration_change.yaral` | Detects changes to the SAP Security Audit Log configuration (`AUE`, `AUF`, `AUI`, `AUJ`, `FU0`, `E05`). |
| `sap_security_audit_log_user_created_deleted_or_unlocked.yaral` | Detects when an SAP user is created, deleted, or unlocked by a non-administrative account. |
| `sap_sensitive_rfc_function_module_execution.yaral` | Detects the execution of sensitive function modules via RFC (`AUK`) listed in `sap_sensitive_function_modules`. |
| `sap_sensitive_role_assignment_correlation.yaral` | Correlates SAP Change Documents with Security Audit logs to detect sensitive role assignments and self-assignments. |
| `sap_sensitive_role_authorization_modification.yaral` | Detects changes to authorization objects within defined sensitive roles (`sap_sensitive_roles`). |
| `sap_sensitive_tables_direct_access_by_rfc_logon_data_table.yaral` | Detects direct access to sensitive SAP tables (`sap_sensitive_tables`) via RFC logon. |
| `sap_sensitive_tables_direct_access_by_rfc_logon_static_list.yaral` | Detects direct access to critical SAP tables (`USR02`, `PAYR`, `P0002`) via RFC logon using a static list. |
| `sap_shared_source_ip_across_multiple_users.yaral` | Detects when multiple distinct SAP users authenticate from a single source IP address. |
| `sap_suspected_data_exfiltration.yaral` | Detects high-volume data downloads (`AUY`) from SAP to a local frontend file. |
| `sap_system_or_client_configuration_change.yaral` | Detects changes to Global System Changeability (`EU1`) or Client-Specific Configuration (`EU2`/`SCC4`). |
| `sap_transaction_code_lock_removed.yaral` | Detects when a transaction code lock is removed (`AUQ`). |
| `sap_unauthorized_execution_of_se09.yaral` | Detects the execution of the SAP Transport Organizer transaction (`SE09`). |
| `sap_user_creates_and_uses_new_user.yaral` | Detects a user creating a new account (`AU7`) and subsequently logging into it (`AU1`, `AU5`) from the same terminal. |
| `sap_user_master_record_modified.yaral` | Detects the modification of a user account record via an administrative action within SAP. |

## Required Data Tables

The following 18 tables in `data_tables/` are referenced by the detection rules
to define sensitive SAP objects or exclude authorized administrative activity:

| Data Table Name | Columns | Purpose / Referenced By |
| :--- | :--- | :--- |
| `SAP_Audit_Log_Configuration` | `MessageID` | Expected SAP Security Audit Log message IDs monitored by `sap_audit_message_id_absent_from_monitoring_config`. |
| `SAP_ChangeUserMasterDataExcludedUsers` | `userid` | Authorized user provisioning accounts excluded from `sap_credential_reset_followed_by_use_from_shared_ip` and `sap_privileged_account_master_record_modified`. |
| `SAP_Dynamic_ABAP_Progam_Excluded_Transactions` | `transaction_code` | Standard transactions excluded from dynamic ABAP code generation alerts in `sap_dynamic_abap_program_observed`. |
| `SAP_PrivilegedUsers` | `userid` | Privileged SAP accounts monitored by `sap_privileged_account_altered_another_account`, `sap_privileged_account_logon_activity`, and `sap_privileged_account_master_record_modified`. |
| `SAP_Systems_Debug_Test` | `SystemID`, `SystemRole` | System IDs and roles (e.g., `Production`) monitored by `sap_abap_debugger_session_activity`. |
| `allowlist_networks` | `name`, `CIDR_range` | Approved corporate and VPN CIDR ranges permitted for interactive dialog logons in `sap_dialog_logon_from_unlisted_network_range`. |
| `internal_CIDR_RFC1918` | `CIDR_range` | Internal RFC 1918 CIDR ranges evaluated by `sap_dialog_logon_from_unlisted_network_range`. |
| `sap_admin_users` | `user` | Authorized Basis, Security, and System Administrator user IDs excluded from administrative change alerts across 11 rules. |
| `sap_excluded_users` | `userid` | Service, batch, and administrative accounts excluded from `sap_audit_log_volume_monitor`, `sap_restricted_transaction_started`, and `sap_shared_source_ip_across_multiple_users`. |
| `sap_ftp_safe_servers` | `Client`, `Description`, `FTP_Server_Name`, `FTP_Server_Port` | Approved FTP server destinations permitted in `sap_ftp_session_to_unapproved_host`. |
| `sap_obsolete_function_modules` | `function_module` | Deprecated or unsafe function modules monitored by `sap_deprecated_function_module_invoked`. |
| `sap_obsolete_programs` | `program` | Deprecated or unsafe ABAP programs monitored by `sap_deprecated_abap_program_started`. |
| `sap_sensitive_abap_programs` | `abap_program` | High-risk ABAP programs monitored by `sap_execution_of_sensitive_abap_program` and `sap_bulk_download_following_restricted_object_access`. |
| `sap_sensitive_function_modules` | `module` | Sensitive RFC-enabled function modules monitored by `sap_sensitive_rfc_function_module_execution`. |
| `sap_sensitive_profiles` | `profile` | High-privilege authorization profiles monitored by `sap_change_documents_sensitive_profile_assignment_data_table`. |
| `sap_sensitive_roles` | `role` | High-impact security roles monitored by `sap_change_documents_sensitive_role_assignment`, `sap_critical_role_assigned_to_new_user`, and `sap_sensitive_role_authorization_modification`. |
| `sap_sensitive_tables` | `name`, `id` | Security-critical database tables monitored by `sap_bulk_download_following_restricted_object_access`, `sap_restricted_table_read_via_table_browser`, and `sap_sensitive_tables_direct_access_by_rfc_logon_data_table`. |
| `sap_sensitive_transactions` | `transaction_code` | Restricted transaction codes monitored by `sap_bulk_download_following_restricted_object_access` and `sap_restricted_transaction_started`. |

## Implementation Standards

| Category | Requirement |
| :--- | :--- |
| **Case Sensitivity** | SAP logs typically store User IDs, Roles, Tables, and Programs in **UPPERCASE**; ensure data table entries match the casing in your UDM events. |
| **Maintenance** | Lists should be reviewed quarterly or following any major SAP transport cycle where new custom (`Z`/`Y`) programs, transactions, or roles are introduced. |

> [!WARNING]
> **Test Before Deploying:** These SAP community detection rules serve as
> foundational templates. Because every SAP environment is unique, you should
> thoroughly test all rules against historical data and modify their logic as
> needed to match your specific logging structures and security use cases.
