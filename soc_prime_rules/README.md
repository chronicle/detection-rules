## SOC Prime Threat Detection Marketplace Rules for the Chronicle Security Repository

This directory tree contains unique YARA-L version 2 rules from SOC Prime Threat Detection Marketplace.

Resource: https://tdm.socprime.com

### General Info

All rules are sorted by the following categories:

1. Use case category

    * Proactive Exploit Detection. Rules with “CVE” or “exploit” within the content body or tagged accordingly.
    * Active Directory Security. Rules related to Azure Active Directory (AD).
    * Cloud Security. Rules with the IaaS, SaaS, or PaaS data source or which include Cloud products within the content name or body.
    * Threat Hunting. Rules related to Threat Hunting and tagged with “APT”.
    * Compliance. Rules that cover Compliance security controls.
    * IOC Sigma. Rules that belong to IOCs (Indicators of Compromise), including IOC Sigma rules or other IOC-based content.
    * Mixed / Other. Other rules that do not fall into any specific category.

2. Log sources

Within each use case category, rules are divided into subfolders based on the original Sigma rule log source. For example:

![Logsource example](.img/image1.png)
