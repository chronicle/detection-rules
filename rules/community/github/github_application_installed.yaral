/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

rule github_application_installed {

  meta:
    author = "Google Cloud Security"
    description = "Detects when a GitHub application is installed within an organization. An untrusted application can be installed and granted permissions to access data within a GitHub organization."
    rule_id = "mr_d1c8d420-774f-4fab-af11-2e5cac2023b2"
    rule_name = "GitHub Application Installed"
    assumption = "Your GitHub enterprise audit log settings are configured to log the source IP address for events. Reference: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/displaying-ip-addresses-in-the-audit-log-for-your-organization"
    type = "alert"
    severity = "Low"
    priority = "Low"
    platform = "GitHub"
    data_source = "github"
    reference = "https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise"

  events:
    $github.metadata.vendor_name = "GITHUB" nocase
    $github.metadata.product_name = "GITHUB"
    $github.metadata.product_event_type = "integration_installation.create"

  outcome:
    $risk_score = max(35)
    $principal_ip = array_distinct($github.principal.ip)
    $principal_user_userid = array_distinct($github.principal.user.userid)
    $principal_ip_country = array_distinct($github.principal.ip_geo_artifact.location.country_or_region)
    $principal_ip_state = array_distinct($github.principal.ip_geo_artifact.location.state)
    $principal_ip_city = array_distinct($github.principal.location.city)
    $security_result_summary = array_distinct($github.security_result.summary)

  condition:
    $github
}
