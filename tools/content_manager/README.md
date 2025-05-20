[![Python 3.10](https://img.shields.io/badge/python-3.10-yellow.svg)](https://www.python.org/downloads/release/python-3100/)

# Content Manager for Google Security Operations (SecOps)

Content Manager is a command-line tool that can be used to manage content in
[Google SecOps](https://cloud.google.com/security/products/security-operations)
such as rules, data, tables, reference lists, and rule exclusions. Content
Manager can be utilized in a CI/CD pipeline to implement Detection-as-Code with
Google SecOps or ran locally using
[Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/application-default-credentials) for authentication.

If you're new to the concept of managing detection rules and other content using
CI/CD tools, we recommend reading our
[Getting Started with Detection-as-Code and Google Security Operations](https://www.googlecloudcommunity.com/gc/Community-Blog/Getting-Started-with-Detection-as-Code-and-Chronicle-Security/ba-p/702154)
blog series published in the Google Cloud Security Community.

<span style="color: red;">**Important**</span>: Content Manager can modify
rules and other content in Google SecOps. Please exercise caution and avoid
running it in production without first understanding the code, customizing it
for your specific use cases, and testing it.

Content Manager interacts with Google SecOps'
[API](https://cloud.google.com/chronicle/docs/reference/rest) and can be used
in a CI/CD pipeline (in GitHub, GitLab, CircleCI, etc) to do the following:

* Verify that a rule is a valid YARA-L rule without creating a new rule or evaluating it over data
* Retrieve the latest version of all detection rules from Google SecOps and write them to local `.yaral` files along with their current state/configuration
* Update detection rules in Google SecOps based on local rule files, e.g., create new rules, create a new rule version, or enable/disable/archive rules
* Retrieve the latest version of all data tables from Google SecOps and write them to local files along with their current state/configuration
* Create or update data tables in Google SecOps based on local files
* Retrieve the latest version of all reference lists from Google SecOps and write them to local files along with their current state/configuration
* Create or update reference lists in Google SecOps based on local files
* Manage [rule exclusions](https://cloud.google.com/chronicle/docs/detection/rule-exclusions) in Google SecOps based on a local config file

Sample detection rules can be found in the [Google SecOps Detection Rules](https://github.com/chronicle/detection-rules/tree/main) repo.

## Setup

Use Python 3.10 or above.

```
# Create and activate a Python virtual environment after cloning this directory into a location of your choosing
$ pip3 install virtualenv
$ python3 -m virtualenv venv
$ source venv/bin/activate

# Install the project's dependencies
(venv) $ pip install -r requirements.txt
```

Create a `.env` file in the root directory of the project and configure the
variables below. A detailed explanation of each variable is provided in the
following section.

```
# Example contents of .env file
LOGGING_LEVEL=INFO
GOOGLE_SECOPS_API_BASE_URL="https://us-chronicle.googleapis.com/v1alpha"
GOOGLE_SECOPS_API_UPLOAD_BASE_URL="https://us-chronicle.googleapis.com/upload/v1alpha"
GOOGLE_SECOPS_INSTANCE="projects/{google-cloud-project-id}/locations/{google-secops-instance-location}/instances/{google-secops-instance-id}"
AUTHORIZATION_SCOPES={"GOOGLE_SECOPS_API":["https://www.googleapis.com/auth/cloud-platform"]}
```

### Authentication to the Google SecOps API

By default, authentication to the Google SecOps API is attempted using [Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/application-default-credentials).

To run commands for Content Manager locally, you can run the following command
to authenticate to the Google Cloud project that's linked to your Google SecOps
tenant and acquire credentials to use Application Default Credentials:
`gcloud auth application-default login`

If you're running Content Manager in a CI/CD pipeline, to eliminate the security
risks and maintenance burden associated with long-lived credentials
(i.e. service account keys), it is recommended to configure your CI/CD pipeline
to authenticate using
[Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
and use short-lived credentials to access Google Cloud resources. Please refer
to Google Cloud's
[documentation](https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)
for configuring Workload Identity Federation or refer to the blog series,
[Securing Your CI/CD Pipeline: Eliminate Long-Lived Credentials with Workload Identity Federation](https://www.googlecloudcommunity.com/gc/Community-Blog/Securing-Your-CI-CD-Pipeline-Eliminate-Long-Lived-Credentials/ba-p/818736)

Google SecOps integrates with Google Cloud Identity and Access Management (IAM)
to provide Google SecOps-specific permissions and predefined roles. Google
SecOps administrators can control access to Google SecOps features by creating
IAM policies that bind users or groups to predefined roles or to IAM custom
roles. You can read more about configuring Google SecOps roles and permissions
in IAM
[here](https://cloud.google.com/chronicle/docs/onboard/configure-feature-access).

If you're using Workload Identity Federation, you can provide your CI/CD pipeline access to Google SecOps by [granting direct resource access to the principal](https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines#access).

The `Chronicle API Editor` IAM role includes the required permissions to manage
rules and reference lists via Google SecOps's API. If you prefer to assign more
granular permissions, you can grant the following permissions to the principal:

```
# Permissions required to manage rules
chronicle.ruleDeployments.get
chronicle.ruleDeployments.list
chronicle.ruleDeployments.update
chronicle.rules.create
chronicle.rules.get
chronicle.rules.list
chronicle.rules.listRevisions
chronicle.rules.update
chronicle.rules.verifyRuleText
# Permissions required to manage data tables
chronicle.dataTables.create
chronicle.dataTables.get
chronicle.dataTables.list
chronicle.dataTables.update
chronicle.dataTables.delete
chronicle.dataTableRows.create
chronicle.dataTableRows.get
chronicle.dataTableRows.list
chronicle.dataTableRows.update
chronicle.dataTableRows.delete
chronicle.dataTableRows.bulkCreate
chronicle.dataTableRows.bulkReplace
chronicle.dataTableRows.bulkUpdate
chronicle.dataTableRows.asyncBulkCreate
chronicle.dataTableRows.asyncBulkReplace
chronicle.dataTableRows.asyncBulkUpdate
# Permissions required to manage reference lists
chronicle.referenceLists.get
chronicle.referenceLists.list
chronicle.referenceLists.create
chronicle.referenceLists.update
# Permissions required to manage rule exclusions
chronicle.findingsRefinementDeployments.get
chronicle.findingsRefinementDeployments.list
chronicle.findingsRefinementDeployments.update
chronicle.findingsRefinements.create
chronicle.findingsRefinements.get
chronicle.findingsRefinements.list
chronicle.findingsRefinements.update
```

If you're unable to configure your CI/CD pipeline to authenticate using Workload
Identity Federation and would like to authenticate using a service account key
instead:

* Create a [service account](https://cloud.google.com/iam/docs/service-account-overview) in the Google Cloud project that's linked to your Google SecOps instance
* Create a service account key for the service account that has the required
Google SecOps IAM role or permissions assigned to it (the specific role and
permissions are specified earlier in this section of the readme)
* Set the `GOOGLE_AUTHENTICATION_TYPE` and `GOOGLE_SECOPS_SERVICE_ACCOUNT_KEY` environment variables in your `.env` file as follows.

```
GOOGLE_AUTHENTICATION_TYPE="SERVICE_ACCOUNT_KEY"
GOOGLE_SECOPS_SERVICE_ACCOUNT_KEY={"type":"service_account","project_id":"xxx","private_key_id":"xxx","private_key":"xxx","client_email":"xxx","client_id":"xxx","auth_uri":"xxx","token_uri":"xxx","auth_provider_x509_cert_url":"xxx","client_x509_cert_url":"xxx","universe_domain":"xxx"}
```

### Detailed Explanation of Environment Variables

This section provides a detailed explanation for each of the environment
variables you'll need to configure in the `.env` file.

Need help after reading this documentation? Please open an issue in this repo or reach out in the Google Cloud Security [community](https://secopscommunity.com). Please refrain from including any sensitive information such as service account keys or customer identifiers.

#### `LOGGING_LEVEL`

* Used to configure the [logging level](https://docs.python.org/3/library/logging.html#levels) for this project. The recommendation is to set this to `INFO` or `DEBUG` for more verbose logging.

#### `GOOGLE_SECOPS_API_BASE_URL`

* Set the `GOOGLE_SECOPS_API_BASE_URL` variable to your regional service endpoint for the Google SecOps API.
* For example, the base URL for the regional service endpoint in the US is
https://us-chronicle.googleapis.com/v1alpha and the base URL for the regional
service endpoint in Europe is https://eu-chronicle.googleapis.com/v1alpha

#### `GOOGLE_SECOPS_API_UPLOAD_BASE_URL`

* Set the `GOOGLE_SECOPS_API_UPLOAD_BASE_URL` variable to your regional service
endpoint for the Google SecOps upload API. This API endpoint is used to upload
files for Google SecOps such as csv files to create data tables.
* For example, the base URL for the regional service endpoint in the US is
https://us-chronicle.googleapis.com/upload/v1alpha and the base URL for the regional
service endpoint in Europe is https://eu-chronicle.googleapis.com/upload/v1alpha

#### `GOOGLE_SECOPS_INSTANCE`

* Set the `GOOGLE_SECOPS_INSTANCE` variable as follows: `projects/{google-cloud-project-id}/locations/{google-secops-instance-location}/instances/{google-secops-instance-id}`
  * Replace the `{google-cloud-project-id}` placeholder with your Google Cloud project ID that is linked to your Google SecOps instance.
  * Replace the `{google-secops-instance-location}` placeholder with the location where your Google SecOps instance is running (e.g. `us` for the United States).
  * Replace the `google-secops-instance-id` placeholder with the `Customer ID` for your Google SecOps instance. You can find this under `Settings` - `SIEM Settings` - `Profile` in Google SecOps's UI.

#### `AUTHORIZATION_SCOPES`

* Set the `AUTHORIZATION_SCOPES` variable to `AUTHORIZATION_SCOPES={"GOOGLE_SECOPS_API":["https://www.googleapis.com/auth/cloud-platform"]}`
* Refer to the [Authentication methods at Google](https://cloud.google.com/docs/authentication/) documentation for information on OAuth 2.0 scopes.

### Executing the Content Manager CLI

```
(venv) $ python -m content_manager --help
01-May-25 11:02:23 MDT | INFO | <module> | Content Manager started
Usage: python -m content_manager [OPTIONS] COMMAND [ARGS]...

  Content Manager - Manage content in Google SecOps such as rules, reference
  lists, and exclusions.

Options:
  --help  Show this message and exit.

Commands:
  data-tables      Manage data tables.
  reference-lists  Manage reference lists.
  rule-exclusions  Manage rule exclusions.
  rules            Manage rules.
```

A logical first step after reading the contents of this readme file and
understanding Content Manager's various commands is to run the `get` commands to
retrieve your existing content from Google SecOps and write it to local files
(e.g. `python -m content_manager rules get` or
`python -m content_manager data-tables get`).

### Running the tests

```
(venv) $ pip install -r requirements_dev.txt
(venv) $ pytest
```

## Example CI/CD Configuration Files

Example CI/CD configuration files are provided to assist with managing content
in Google SecOps via its REST API. You can customize these files to fit your
specific requirements.

* [GitHub Actions workflow files](https://github.com/chronicle/detection-rules/tree/main/tools/content_manager/content_manager/etc/github_actions_workflow_files)
* [GitLab CI/CD pipeline configuration file](https://github.com/chronicle/detection-rules/blob/main/tools/content_manager/content_manager/etc/.gitlab-ci.yml)

## Usage

Content Manager's commands can be run individually as shown below.

## Managing rules in Google SecOps

Execute the following command to display information about the rules subcommand:
`python -m content_manager rules --help`

### Retrieve rules from Google SecOps

The `rules get` command retrieves the latest version of all rules from your
Google SecOps tenant and writes them to `.yaral` files in the `rules` directory.

The configuration and metadata for rules is written to the `rule_config.yaml`
file. This file contains information about whether a rule is
enabled/disabled/archived, the rule ID, the rule's revision ID, etc.

Example output from `rules get` command:

```
(venv) $ python -m content_manager rules get
01-May-25 11:22:10 MDT | INFO | <module> | Content Manager started
01-May-25 11:22:10 MDT | INFO | get_rules | Attempting to pull latest version of all rules from Google SecOps and update local files
01-May-25 11:22:10 MDT | INFO | get_remote_rules | Attempting to retrieve all rules from Google SecOps
01-May-25 11:22:11 MDT | INFO | get_remote_rules | Retrieved a total of 82 rules
01-May-25 11:22:11 MDT | INFO | get_remote_rules | Attempting to retrieve deployment state for all rules in Google SecOps
01-May-25 11:22:11 MDT | INFO | get_remote_rules | Retrieved deployment state for a total of 82 rules
01-May-25 11:22:11 MDT | INFO | dump_rules | Writing 82 rule files to /Users/x/Documents/projects/detection-rules/tools/content_manager/rules
01-May-25 11:22:11 MDT | INFO | dump_rule_config | Writing rule config to /Users/x/Documents/projects/detection-rules/tools/content_manager/rule_config.yaml
```

### Verify rule(s)

The `rules verify` and `rules verify-all` commands use Google SecOps's API to
verify that rules are valid without creating a new rule or evaluating it over
data.

Example output from `rules verify` command:

```
(venv) $ python -m content_manager rules verify -f rules/adfs_db_suspicious_named_pipe_connection.yaral
01-May-25 11:27:13 MDT | INFO | <module> | Content Manager started
01-May-25 11:27:13 MDT | INFO | verify | Attempting to verify rule rules/adfs_db_suspicious_named_pipe_connection.yaral
01-May-25 11:27:14 MDT | INFO | verify | Rule verified successfully (rules/adfs_db_suspicious_named_pipe_connection.yaral). Response: {'success': True}
```

Example output from `rules verify-all` command:

```
(venv) $ python -m content_manager rules verify-all
01-May-25 11:28:57 MDT | INFO | <module> | Content Manager started
01-May-25 11:28:57 MDT | INFO | verify_all | Attempting to verify all local rules
01-May-25 11:30:07 MDT | INFO | verify_all | Rule verification succeeded for 81 rules
01-May-25 11:30:07 MDT | ERROR | verify_all | Rule verification failed for 1 rules
01-May-25 11:30:07 MDT | ERROR | verify_all | Rule verification failed for rule (/Users/x/Documents/projects/detection-rules/tools/content_manager/rules/adfs_db_suspicious_named_pipe_connection.yaral). Response: {
    "compilationDiagnostics": [
        {
            "message": "parsing: getting field descriptors: accessing field \"udm.metadata.event_typee\": field \"event_typee\" does not exist, valid fields are: \"id\", \"product_log_id\", \"event_timestamp\", \"collected_timestamp\", \"ingested_timestamp\", \"event_type\", \"vendor_name\", \"product_name\", \"product_version\", \"product_event_type\", \"product_deployment_id\", \"description\", \"url_back_to_product\", \"ingestion_labels\", \"tags\", \"enrichment_state\", \"log_type\", \"base_labels\", \"enrichment_labels\", \"structured_fields\"\nline: 14 \ncolumn: 5-33 ",
            "position": {
                "startLine": 14,
                "startColumn": 5,
                "endLine": 14,
                "endColumn": 33
            },
            "severity": "ERROR"
        }
    ]
}
...
```

### Update rules in Google SecOps

The `rules update` command updates detection rules in Google SecOps based
on local rule (`.yaral`) files and the `rule_config.yaml` file. Rule updates
include:

* Create a new rule
* Create a new version for a rule
* Enable/disable a rule (controlled by the `enabled: true/false` option for a rule in `rule_config.yaml`)
* Enable/disable alerting for a rule (controlled by the `alerting: true/false` option for a rule in`rule_config.yaml`)
* Archive/unarchive a rule (controlled by the `archived: true/false` option for a rule in `rule_config.yaml`)

Example output from update remote rules command.

```
(venv) $ python -m content_manager rules update
01-May-25 11:35:03 MDT | INFO | <module> | Content Manager started
01-May-25 11:35:03 MDT | INFO | update_remote_rules | Attempting to update rules in Google SecOps based on local rule files
01-May-25 11:35:03 MDT | INFO | update_remote_rules | Loading local files from /Users/x/Documents/projects/detection-rules/tools/content_manager/rules
01-May-25 11:35:03 MDT | INFO | load_rule_config | Loading rule config file from /Users/x/Documents/projects/detection-rules/tools/content_manager/rule_config.yaml
01-May-25 11:35:03 MDT | INFO | load_rules | Loaded 83 rules from /Users/x/Documents/projects/detection-rules/tools/content_manager/rules
01-May-25 11:35:03 MDT | INFO | update_remote_rules | Attempting to retrieve latest version of all rules from Google SecOps
01-May-25 11:35:04 MDT | INFO | get_remote_rules | Retrieved a total of 82 rules
01-May-25 11:35:04 MDT | INFO | get_remote_rules | Attempting to retrieve deployment state for all rules in Google SecOps
01-May-25 11:35:04 MDT | INFO | get_remote_rules | Retrieved deployment state for a total of 82 rules
01-May-25 11:35:04 MDT | INFO | update_remote_rules | Checking if any rule updates are required
01-May-25 11:35:04 MDT | INFO | update_remote_rules | Rule adfs_db_suspicious_named_pipe_connection (ru_677474e3-1c93-4874-8338-ac7e571236a6) - Rule text is different. Creating new rule version
01-May-25 11:35:05 MDT | INFO | update_remote_rules | Local rule name github_secret_scanning_disabled_or_bypassed not found in remote rules
01-May-25 11:35:05 MDT | INFO | update_remote_rules | Local rule github_secret_scanning_disabled_or_bypassed has no rule id value. Creating a new rule
01-May-25 11:35:06 MDT | INFO | update_remote_rules | Created new rule github_secret_scanning_disabled_or_bypassed (ru_65719ee3-0460-44c2-b053-a9c465722f0d)
01-May-25 11:35:06 MDT | INFO | update_remote_rule_state | Rule github_secret_scanning_disabled_or_bypassed (ru_65719ee3-0460-44c2-b053-a9c465722f0d) - Enabling rule
01-May-25 11:35:07 MDT | INFO | update_remote_rule_state | Rule github_secret_scanning_disabled_or_bypassed (ru_65719ee3-0460-44c2-b053-a9c465722f0d) - Enabling alerting for rule
01-May-25 11:35:07 MDT | INFO | update | Logging summary of rule changes...
01-May-25 11:35:07 MDT | INFO | update | Rules created: 1
01-May-25 11:35:07 MDT | INFO | update | created github_secret_scanning_disabled_or_bypassed (ru_65719ee3-0460-44c2-b053-a9c465722f0d)
01-May-25 11:35:07 MDT | INFO | update | Rules new_version_created: 1
01-May-25 11:35:07 MDT | INFO | update | new_version_created adfs_db_suspicious_named_pipe_connection (ru_677474e3-1c93-4874-8338-ac7e571236a6)
01-May-25 11:35:07 MDT | INFO | update | Rules enabled: 1
01-May-25 11:35:07 MDT | INFO | update | enabled github_secret_scanning_disabled_or_bypassed (ru_65719ee3-0460-44c2-b053-a9c465722f0d)
01-May-25 11:35:07 MDT | INFO | update | Rules disabled: 0
01-May-25 11:35:07 MDT | INFO | update | Rules alerting_enabled: 1
01-May-25 11:35:07 MDT | INFO | update | alerting_enabled github_secret_scanning_disabled_or_bypassed (ru_65719ee3-0460-44c2-b053-a9c465722f0d)
01-May-25 11:35:07 MDT | INFO | update | Rules alerting_disabled: 0
01-May-25 11:35:07 MDT | INFO | update | Rules archived: 0
01-May-25 11:35:07 MDT | INFO | update | Rules unarchived: 0
01-May-25 11:35:07 MDT | INFO | get_remote_rules | Attempting to retrieve all rules from Google SecOps
01-May-25 11:35:08 MDT | INFO | get_remote_rules | Retrieved a total of 83 rules
01-May-25 11:35:08 MDT | INFO | get_remote_rules | Attempting to retrieve deployment state for all rules in Google SecOps
01-May-25 11:35:08 MDT | INFO | get_remote_rules | Retrieved deployment state for a total of 83 rules
01-May-25 11:35:08 MDT | INFO | dump_rules | Writing 83 rule files to /Users/x/Documents/projects/detection-rules/tools/content_manager/rules
01-May-25 11:35:08 MDT | INFO | dump_rule_config | Writing rule config to /Users/x/Documents/projects/detection-rules/tools/content_manager/rule_config.yaml
```

### Testing a rule

The `rules test` command uses Google SecOps' REST API to run a YARA-L rule over
a given time range without persisting results in Google SecOps.

Results (detections) are logged to the console. This code can be customized to
write the results to a file for analysis or add logic to process any detections
that are returned.

Example output from `rules test` command:

```
(venv) $ python -m content_manager rules test -f rules/google_workspace_file_shared_from_google_drive_to_free_email_domain.yaral  --start-time 2025-04-30T05:30:00Z --end-time 2025-05-01T17:30:00Z
01-May-25 12:01:37 MDT | INFO | <module> | Content Manager started
01-May-25 12:01:37 MDT | INFO | test | Attempting to test rule rules/google_workspace_file_shared_from_google_drive_to_free_email_domain.yaral with event start time of 2025-04-30 05:30:00+00:00 and event end time of 2025-05-01 17:30:00+00:00 and scope None
01-May-25 12:01:38 MDT | INFO | stream_test_rule | Initiated connection to test rule stream
01-May-25 12:01:47 MDT | INFO | test_rule | Retrieved 4 detections and 0 rule execution errors
01-May-25 12:01:47 MDT | INFO | stream_test | Retrieved 4 detections for rule: rules/google_workspace_file_shared_from_google_drive_to_free_email_domain.yaral
01-May-25 12:01:47 MDT | DEBUG | stream_test_rule | Logging retrieved detections for rule: ...
```

## Managing data tables in Google SecOps

### Retrieve data tables from Google SecOps

The `data-tables get` command retrieves the latest version of all data tables
from Google SecOps and writes them to `.csv` files in the `data_tables`
directory.

The data table configuration & metadata is written to the
`data_table_config.yaml` file.

Example output from `data-tables get` command

```
(venv) $ python -m content_manager data-tables get
15-May-25 13:34:08 MDT | INFO | <module> | Content Manager started
15-May-25 13:34:08 MDT | INFO | get_data_tables | Attempting to pull latest version of all data tables from Google SecOps and update local files
15-May-25 13:34:09 MDT | INFO | get_remote_data_tables | Retrieved a total of 15 data tables
15-May-25 13:34:09 MDT | INFO | dump_data_table_config | Writing data table config to /Users/x/Documents/projects/detection-rules/tools/content_manager/data_table_config.yaml
15-May-25 13:34:09 MDT | INFO | get_remote_data_table_rows | Attempting to retrieve all rows for data table cisco_umbrella_top_1k_domains from Google SecOps and write them to local file /Users/x/Documents/projects/detection-rules/tools/content_manager/data_tables/cisco_umbrella_top_1k_domains.csv
...
```

### Update data tables in Google SecOps

The `data-tables update` command updates data tables in Google
SecOps based on local data table (`.csv`) files and the
`data_table_config.yaml` file.

Data table updates include:

* Create a new data table
* Replace the contents of an existing data table
* Update the description or row time-to-live value for a data table

Please refer to the example data table in the `data_tables` directory
and the example `data_table_config.yaml` file to understand the expected
format for these files.

Below is an example entry in the `data_table_config.yaml` file before running
the `data-tables update` command.

```yaml
cisco_umbrella_top_1k_domains:
  description: Cisco Umbrella top 1,000 domains
  columns:
  - column_index: 0
    original_column: rank
    column_type: STRING
  - column_index: 1
    original_column: domain
    column_type: STRING
```

And below are the first 3 lines of the `cisco_umbrella_top_1k_domains.csv` file
in the `data_tables` directory.

```
1,google.com
2,microsoft.com
3,www.google.com
```

Example output from the `data-tables update` command is shown below.

```
(venv) $ python -m content_manager data-tables update
15-May-25 14:03:04 MDT | INFO | <module> | Content Manager started
15-May-25 14:03:04 MDT | INFO | update_data_tables | Attempting to update data tables in Google SecOps based on local data table files
15-May-25 14:03:04 MDT | INFO | load_data_table_config | Loading data table config from file /Users/x/Documents/projects/detection-rules/tools/content_manager/data_table_config.yaml
15-May-25 14:03:04 MDT | INFO | load_data_table_config | Loaded metadata and config for 15 data tables from file /Users/x/Documents/projects/detection-rules/tools/content_manager/data_tables
15-May-25 14:03:04 MDT | INFO | update_remote_data_tables | Attempting to retrieve latest version of all data tables from Google SecOps
15-May-25 14:03:05 MDT | INFO | get_remote_data_tables | Retrieved a total of 14 data tables
15-May-25 14:03:12 MDT | INFO | update_remote_data_tables | Local data table name cisco_umbrella_top_1k_domains not found in remote data tables. Creating a new data table
15-May-25 14:03:13 MDT | INFO | update | Logging summary of data table changes...
15-May-25 14:03:13 MDT | INFO | update | Data tables created: 1
15-May-25 14:03:13 MDT | INFO | update | created Data table cisco_umbrella_top_1k_domains
15-May-25 14:03:13 MDT | INFO | update | Data tables config_updated: 0
15-May-25 14:03:13 MDT | INFO | update | Data tables content_updated: 0
```

### Deleting data tables in Google SecOps

The `data-tables delete` command deletes data tables in Google SecOps. Use the
`--scope` option to define which data tables should be deleted. The `all` scope
deletes all data tables in Google SecOps. The `unmanaged` scope deletes data
tables that are not present in the `data_table_config.yaml` file or
`data_tables` directory.

<span style="color: red;">**Warning**</span>: Deleting data tables is a
destructive action. It is not reversible, so please take a backup of your data
tables before running this command if needed.

Note: The deletion of a data table will fail if it is referenced by a rule.

```
(venv) $ python -m content_manager data-tables delete --help
python -m content_manager data-tables delete --help
15-May-25 14:08:23 MDT | INFO | <module> | Content Manager started
Usage: python -m content_manager data-tables delete [OPTIONS]

  Delete data tables in Google SecOps.

Options:
  --scope [all|unmanaged]  The scope of data tables to delete in Google
                           SecOps. 'all': Delete all data tables. 'unmanaged':
                           Delete data tables that are not present in the
                           local config file or data_tables directory.
                           [required]
  --help                   Show this message and exit.
```

## Managing reference lists in Google SecOps

### Retrieve reference lists from Google SecOps

The `reference-lists get` command retrieves the latest version of
reference lists from Google SecOps and writes them to `.txt` files in the
`reference_lists` directory.

The reference list configuration & metadata is written to the
`reference_list_config.yaml` file.

Example output from `reference-lists get` command:

```
(venv) $ python -m content_manager reference-lists get
01-May-25 12:06:01 MDT | INFO | <module> | Content Manager started
01-May-25 12:06:01 MDT | INFO | get_reference_lists | Attempting to pull latest version of all reference lists from Google SecOps and update local files
01-May-25 12:06:01 MDT | INFO | get_remote_ref_lists | Attempting to retrieve all reference lists from Google SecOps
01-May-25 12:06:02 MDT | INFO | get_remote_ref_lists | Retrieved 36 reference lists
01-May-25 12:06:02 MDT | INFO | get_remote_ref_lists | Retrieved a total of 36 reference lists
01-May-25 12:06:02 MDT | INFO | dump_ref_lists | Writing 36 reference list files to /Users/x/Documents/projects/detection-rules/tools/content_manager/reference_lists
01-May-25 12:06:02 MDT | INFO | dump_ref_list_config | Writing reference list config to /Users/x/Documents/projects/detection-rules/tools/content_manager/reference_list_config.yaml
```

### Update reference lists in Google SecOps

The `reference-lists update` command updates reference lists in Google
SecOps based on local reference list (`.txt`) files and the
`reference_list_config.yaml` file.

Reference list updates include:

* Create a new reference list
* Replace the contents of an existing reference list
* Update the description or syntax type for a reference list

Please refer to the example reference lists in the `reference_lists` directory
and the example `reference_list_config.yaml` file to understand the expected
format for these files.

A `description` for each reference list must be defined in
`reference_list_config.yaml`.

The `syntax_type` for each reference list must be defined in
`reference_list_config.yaml`. Valid reference list types are as follows:

* `REFERENCE_LIST_SYNTAX_TYPE_UNSPECIFIED`
* `REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING`,
* `REFERENCE_LIST_SYNTAX_TYPE_REGEX`
* `REFERENCE_LIST_SYNTAX_TYPE_CIDR`.

Example output from update remote reference lists command.

```
(venv) $ python -m content_manager reference-lists update
01-May-25 12:09:02 MDT | INFO | <module> | Content Manager started
01-May-25 12:09:02 MDT | INFO | update_remote_ref_lists | Attempting to update reference lists in Google SecOps based on local files
01-May-25 12:09:02 MDT | INFO | update_remote_ref_lists | Loading local reference lists from /Users/x/Documents/projects/detection-rules/tools/content_manager/reference_lists
01-May-25 12:09:02 MDT | INFO | load_ref_list_config | Loading reference list config file from /Users/x/Documents/projects/detection-rules/tools/content_manager/reference_list_config.yaml
01-May-25 12:09:02 MDT | INFO | load_ref_lists | Loaded 37 reference lists from /Users/x/Documents/projects/detection-rules/tools/content_manager/reference_lists
01-May-25 12:09:02 MDT | INFO | update_remote_ref_lists | Attempting to retrieve latest version of all reference lists from Google SecOps
01-May-25 12:09:02 MDT | INFO | get_remote_ref_lists | Retrieved a total of 36 reference lists
01-May-25 12:09:02 MDT | INFO | update_remote_ref_lists | Checking if any reference list updates are required
01-May-25 12:09:02 MDT | INFO | update_remote_ref_lists | Local reference list name example_list not found in remote reference list. Creating a new reference list
01-May-25 12:09:03 MDT | INFO | update | Logging summary of reference list changes...
01-May-25 12:09:03 MDT | INFO | update | Reference lists created: 1
01-May-25 12:09:03 MDT | INFO | update | created Reference list example_list
01-May-25 12:09:03 MDT | INFO | update | Reference lists updated: 0
01-May-25 12:09:03 MDT | INFO | get_remote_ref_lists | Attempting to retrieve all reference lists from Google SecOps
01-May-25 12:09:04 MDT | INFO | get_remote_ref_lists | Retrieved a total of 37 reference lists
01-May-25 12:09:04 MDT | INFO | dump_ref_lists | Writing 37 reference list files to /Users/x/Documents/projects/detection-rules/tools/content_manager/reference_lists
01-May-25 12:09:04 MDT | INFO | dump_ref_list_config | Writing reference list config to /Users/x/Documents/projects/detection-rules/tools/content_manager/reference_list_config.yaml
```

## Managing rule exclusions in Google SecOps

### Retrieve rule exclusions from Google SecOps

The `rule-exclusions get` command retrieves the latest version of all rule
exclusions from Google SecOps and writes them to a `rule_exclusions_config.yaml`
file.

Example output from `rule-exclusions get` command:

```
(venv) $ python -m content_manager rule-exclusions get
01-May-25 12:12:25 MDT | INFO | <module> | Content Manager started
01-May-25 12:12:25 MDT | INFO | get_remote_rule_exclusions | Attempting to retrieve all rule exclusions from Google SecOps
01-May-25 12:12:26 MDT | INFO | get_remote_rule_exclusions | Retrieved a total of 18 rule exclusions
01-May-25 12:12:26 MDT | INFO | get_remote_rule_exclusions | Retrieved deployment state for a total of 18 rule exclusions
01-May-25 12:12:26 MDT | INFO | dump_rule_exclusion_config | Writing rule exclusion config to /Users/x/Documents/projects/detection-rules/tools/content_manager/rule_exclusions_config.yaml
```

### Update rule exclusions in Google SecOps

The `rule-exclusions update` command updates rule exclusions in Google
SecOps based on the local config file (`rule_exclusions_config.yaml`).

Rule exclusion updates include:

* Create a new rule exclusion
* Update the display name for a rule exclusion
* Update the query for a rule exclusion
* Update a rule exclusion's deployment state (`enabled`: True/False, `archived`: True/False)
* Update the exclusion applications for a rule exclusion (i.e. the curated rule sets/rules that the exclusion applies to)

Please refer to the example rule exclusions in the `rule_exclusions_config.yaml`
file to understand the expected format for these files.

To create a new rule exclusion, add a new entry to the
`rule_exclusions_config.yaml` file and execute the update remote rule exclusions
command. Please see the example below.

```
Lab Hosts:
  enabled: true
  query: (principal.hostname = "lab-desktop-1234")
  type: DETECTION_EXCLUSION
  exclusion_applications:
    curated_rule_sets:
    - projects/123456789012/locations/us/instances/0f9c87b9-0203-43a3-a768-ba50663920c8/curatedRuleSetCategories/110fa43d-7165-2355-1985-a63b7cdf90e8/curatedRuleSets/07eab257-51fb-b9c5-2040-dd5d6f65ed79
    - projects/123456789012/locations/us/instances/0f9c87b9-0203-43a3-a768-ba50663920c8/curatedRuleSetCategories/110fa43d-7165-2355-1985-a63b7cdf90e8/curatedRuleSets/11c505d4-b424-65e3-d918-1a81232cc76b
    curated_rules:
    - projects/123456789012/locations/us/instances/0f9c87b9-0203-43a3-a768-ba50663920c8/curatedRules/ur_7f8204c2-0d54-4dab-b7fa-133f8b94a53b
```

Existing rule exclusions can be updated by modifying the
`rule_exclusions_config.yaml` file and executing the `rule-exclusions update`
command.

Example output from update remote rule exclusions command.

```
(venv) $ python -m content_manager rule-exclusions update
01-May-25 12:15:29 MDT | INFO | <module> | Content Manager started
01-May-25 12:15:29 MDT | INFO | update | Attempting to update rule exclusions in Google SecOps based on local config file
01-May-25 12:15:30 MDT | INFO | update_remote_rule_exclusions | Attempting to update rule exclusions in Google SecOps based on local config file /Users/x/Documents/projects/detection-rules/tools/content_manager/rule_exclusions_config.yaml
01-May-25 12:15:30 MDT | INFO | load_rule_exclusion_config | Loading rule exclusion config file from /Users/x/Documents/projects/detection-rules/tools/content_manager/rule_exclusions_config.yaml
01-May-25 12:15:30 MDT | INFO | load_rule_exclusion_config | Loaded 19 rule exclusion config entries from file /Users/x/Documents/projects/detection-rules/tools/content_manager/rule_exclusions_config.yaml
01-May-25 12:15:30 MDT | INFO | get_remote_rule_exclusions | Attempting to retrieve all rule exclusions from Google SecOps
01-May-25 12:15:30 MDT | INFO | get_remote_rule_exclusions | Retrieved 18 rule exclusions
01-May-25 12:15:30 MDT | INFO | get_remote_rule_exclusions | Retrieved a total of 18 rule exclusions
01-May-25 12:15:30 MDT | INFO | get_remote_rule_exclusions | Attempting to retrieve deployment state for all rule exclusions
01-May-25 12:15:31 MDT | INFO | get_remote_rule_exclusions | Retrieved deployment state for a total of 18 rule exclusions
01-May-25 12:15:31 MDT | INFO | update_remote_rule_exclusions | Checking if any rule exclusion updates are required
01-May-25 12:15:32 MDT | INFO | update_remote_rule_exclusions | Created new rule exclusion My New Rule Exclusion
01-May-25 12:15:32 MDT | INFO | update_remote_rule_exclusion_state | Rule exclusion My New Rule Exclusion - Enabling rule exclusion
01-May-25 12:15:33 MDT | INFO | update_remote_rule_exclusion_state | Rule exclusion My New Rule Exclusion - Updating detection exclusion applications
01-May-25 12:15:34 MDT | INFO | update | Logging summary of rule exclusion changes...
01-May-25 12:15:34 MDT | INFO | update | Rule exclusions created: 1
01-May-25 12:15:34 MDT | INFO | update | created rule exclusion ('My New Rule Exclusion')
01-May-25 12:15:34 MDT | INFO | update | Rule exclusions updated: 0
01-May-25 12:15:34 MDT | INFO | update | Rule exclusions enabled: 1
01-May-25 12:15:34 MDT | INFO | update | enabled rule exclusion ('My New Rule Exclusion')
01-May-25 12:15:34 MDT | INFO | update | Rule exclusions disabled: 0
01-May-25 12:15:34 MDT | INFO | update | Rule exclusions archived: 0
01-May-25 12:15:34 MDT | INFO | update | Rule exclusions unarchived: 0
01-May-25 12:15:34 MDT | INFO | update | Rule exclusions detection_exclusion_applications_updated: 1
01-May-25 12:15:34 MDT | INFO | update | detection_exclusion_applications_updated rule exclusion ('My New Rule Exclusion')
01-May-25 12:15:35 MDT | INFO | get_remote_rule_exclusions | Attempting to retrieve all rule exclusions from Google SecOps
01-May-25 12:15:35 MDT | INFO | get_remote_rule_exclusions | Retrieved a total of 19 rule exclusions
01-May-25 12:15:36 MDT | INFO | get_remote_rule_exclusions | Retrieved deployment state for a total of 19 rule exclusions
01-May-25 12:15:36 MDT | INFO | dump_rule_exclusion_config | Writing rule exclusion config to /Users/x/Documents/projects/detection-rules/tools/content_manager/rule_exclusions_config.yaml
```

## Need help?

Please open an issue in this repo or reach out in the Google Cloud Security [community](https://secopscommunity.com).
