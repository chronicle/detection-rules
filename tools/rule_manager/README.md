[![Python 3.10](https://img.shields.io/badge/python-3.10-yellow.svg)](https://www.python.org/downloads/release/python-3100/)

# Example Code for Managing Detection Rules in Chronicle Security Operations

This directory contains example code that can be used to build a Detection-as-Code CI/CD pipeline to manage rules in
[Chronicle Security Operations](https://cloud.google.com/chronicle-security-operations).

<span style="color: red;">**Important**</span>: This code can modify rules in Chronicle. Please exercise caution and 
avoid running it in production without first understanding the code, customizing it for your specific use cases, and 
testing it.

The example code interacts with Chronicle's [API](https://cloud.google.com/chronicle/docs/reference/rest) and can be 
used in a CI/CD pipeline (in GitHub, GitLab, CircleCI, etc) to do the following:

* Verify that a rule is a valid YARA-L 2.0 rule without creating a new rule or evaluating it over data
* Retrieve the latest version of all detection rules from Chronicle and write them to local `.yaral` files along with
their current state/configuration
* Update detection rules in Chronicle based on local rule files, e.g., create new rules, create a new rule version, or
enable/disable/archive rules.

Sample detection rules can be found in the [Chronicle Detection Rules](https://github.com/chronicle/detection-rules/tree/main)
repo.

## Setup

```console
# Create and activate a Python virtual environment after cloning this directory into a location of your choosing
$ python3.10 -m virtualenv venv
$ source venv/bin/activate

# Install the project's dependencies
(venv) $ pip install -r requirements.txt
```

Create a `.env` file in the root directory of the project and configure the variables below. A detailed 
explanation of each variable is provided in the following section.

```
# Example contents of .env file
LOGGING_LEVEL=INFO
CHRONICLE_API_BASE_URL="https://us-chronicle.googleapis.com/v1alpha"
CHRONICLE_INSTANCE="projects/{google-cloud-project-id}/locations/{chronicle-instance-location}/instances/{chronicle-instance-id}"
AUTHORIZATION_SCOPES={"CHRONICLE_API":["https://www.googleapis.com/auth/cloud-platform"]}
CHRONICLE_API_CREDENTIALS={"type":"service_account","project_id":"xxx","private_key_id":"xxx","private_key":"xxx","client_email":"xxx","client_id":"xxx","auth_uri":"xxx","token_uri":"xxx","auth_provider_x509_cert_url":"xxx","client_x509_cert_url":"xxx","universe_domain":"xxx"}
```

### Detailed explanation of environment variables

This section provides a detailed explanation for each of the environment variables you'll need to configure in the 
`.env` file.

Need help after reading this documentation? Please open an issue in this repo or reach out in the
Google Cloud Security [community](https://www.googlecloudcommunity.com/gc/Chronicle/ct-p/security-chronicle). Please 
refrain from including any sensitive information such as service account keys or customer identifiers.

#### `LOGGING_LEVEL`

* Used to configure the [logging level](https://docs.python.org/3/library/logging.html#levels) for this project. The 
  recommendation is to set this to `INFO` or `DEBUG` for more verbose logging.

### `CHRONICLE_BASE_URL`

* Set the `CHRONICLE_BASE_URL` variable to your regional service endpoint for the Chronicle API.
* For example, the base URL for the US regional service endpoint is https://us-chronicle.googleapis.com/v1alpha

### `CHRONICLE_INSTANCE`

* Set the `CHRONICLE_INSTANCE` variable as follows: `projects/{google-cloud-project-id}/locations/{chronicle-instance-location}/instances/{chronicle-instance-id}`
  * Replace the `{google-cloud-project-id}` placeholder with your Google Cloud project ID that is linked to your 
    Chronicle instance.
  * Replace the `{chronicle-instance-location}` placeholder with the location where your Chronicle instance is running 
    (e.g. `us` for the United States).
  * Replace the `chronicle-instance-id` placeholder with the `Customer ID` for your Chronicle instance. You can find 
    this under `Settings` - `SIEM Settings` - `Profile` in Chronicle's UI.

### `AUTHORIZATION_SCOPES`

* Set the `AUTHORIZATION_SCOPES` variable to `AUTHORIZATION_SCOPES={"CHRONICLE_API":["https://www.googleapis.com/auth/cloud-platform"]}`
* Refer to the [Authentication methods at Google](https://cloud.google.com/docs/authentication/) documentation for 
  information on OAuth 2.0 scopes.

### `CHRONICLE_API_CREDENTIALS`

* For the purposes of authenticating to and managing detection rules via Chronicle's API, you can create a [service account](https://cloud.google.com/iam/docs/service-account-overview)
  in the Google Cloud project that's linked to your Chronicle instance.
* Chronicle integrates with Google Cloud Identity and Access Management (IAM) to provide Chronicle-specific permissions
  and predefined roles. Chronicle administrators can control access to Chronicle features by creating IAM policies 
  that bind users or groups to predefined roles or to IAM custom roles. You can read more about configuring 
  Chronicle roles and permissions in IAM [here](https://cloud.google.com/chronicle/docs/onboard/configure-feature-access).
* Assign the Chronicle permissions required to run the code in this project to the service account. 
  * The `Chronicle API Editor` IAM role includes the required permissions to manage rules via Chronicle's API. If you 
    prefer to assign more granular permissions to the service account, you can grant the following permissions to the 
    service account or create a custom IAM role and assign that to the service account:

    ```
    chronicle.ruleDeployments.get
    chronicle.ruleDeployments.list
    chronicle.ruleDeployments.update
    chronicle.rules.create
    chronicle.rules.get
    chronicle.rules.list
    chronicle.rules.listRevisions
    chronicle.rules.update
    chronicle.rules.verifyRuleText
    ```

* Create a service account key for the service account that has the required permissions assigned and set it as the 
  value for the `CHRONICLE_API_CREDENTIALS` variable. Enter the variable's value in JSON format, on a single line as 
  shown in above example `.env` file).

```console
# Verify that the CLI executes successfully
(venv) $ python -m rule_cli -h
16-Jan-24 16:14:00 MST | INFO | <module> | Rule CLI started
usage: __main__.py [-h] [--pull-latest-rules] [--update-remote-rules] [--verify-rules] {verify-rule} ...

rule_cli

options:
  -h, --help            show this help message and exit
  --pull-latest-rules   Retrieves the latest version of all rules from Chronicle and writes them to local files.
  --update-remote-rules
                        Update rules in Chronicle based on local rule files.
  --verify-rules        Verify that all local rules are valid YARA-L 2.0 rules.

subcommands:
  {verify-rule}
    verify-rule         Verify that a rule is a valid YARA-L 2.0 rule.
```

To run the tests.

```console
(venv) $ pip install -r requirements_dev.txt
(venv) $ pytest
```

# Usage

As mentioned above, the example code in this POC can be customized to fit your needs. The CLI commands can be run
individually as shown below.

## Pull latest rules from Chronicle

The pull latest rules command retrieves the latest version of all rules from Chronicle and writes them to `.yaral`
files in the `rules` directory.

The rule state is written to the `rule_config.yaml` file. The rule state contains metadata about the state of each rule
such as whether it is live enabled/disabled, the rule ID, the rule version ID, etc.

Example output from pull latest rules command:

```console
(venv) $ python -m rule_cli --pull-latest-rules
16-Jan-24 16:17:38 MST | INFO | <module> | Rule CLI started
16-Jan-24 16:17:38 MST | INFO | <module> | Attempting to pull latest version of all Chronicle rules and update local files
16-Jan-24 16:17:39 MST | INFO | get_remote_rules | Retrieved a total of 36 rules
16-Jan-24 16:17:41 MST | INFO | dump_rules | Writing 36 rule files to /Users/x/Documents/projects/detection-engineering/rules
16-Jan-24 16:17:41 MST | INFO | dump_rule_config | Writing rule config to /Users/x/Documents/projects/detection-engineering/rule_config.yaml
```

## Verify rule(s)

The `--verify-rule` and `--verify-rules` commands use Chronicle's API to verify that YARA-L 2.0 rules are valid without
creating a new rule or evaluating it over data.

Example output from verify rule command:

```console
(venv) $ python -m rule_cli verify-rule -f rules/dns_query_to_recently_created_domain.yaral 
16-Jan-24 16:16:11 MST | INFO | <module> | Rule CLI started
16-Jan-24 16:16:11 MST | INFO | <module> | Attempting to verify rule rules/dns_query_to_recently_created_domain.yaral
16-Jan-24 16:16:11 MST | INFO | verify_rule_text | Rule verified successfully (rules/dns_query_to_recently_created_domain.yaral). Response: {'success': True}

python -m rule_cli --verify-rules
16-Jan-24 16:17:08 MST | INFO | <module> | Rule CLI started
16-Jan-24 16:17:08 MST | INFO | <module> | Attempting to verify all local rules
...
```

## Update remote rules

The update remote rules command updates detection rules in Chronicle based on local rule (`.yaral`) files and the
`rule_config.yaml` file. Rule updates include:

* Create a new rule
* Create a new version for a rule
* Enable/disable a rule (controlled by the `enabled: true/false` option for a rule in `rule_config.yaml`)
* Enable/disable alerting for a rule (controlled by the `alerting: true/false` option for a rule in`rule_config.yaml`)
* Archive/unarchive a rule (controlled by the `archived: true/false` option for a rule in `rule_config.yaml`)

Example output from update remote rules command.

```console
(venv) $ python -m rule_cli --update-remote-rules
16-Jan-24 16:23:08 MST | INFO | <module> | Attempting to update rules in Chronicle based on local rule files
16-Jan-24 16:23:08 MST | INFO | update_remote_rules | Attempting to update rules in Chronicle based on local rule files
16-Jan-24 16:23:08 MST | INFO | update_remote_rules | Loading local files from /Users/x/Documents/projects/detection-engineering/rules
16-Jan-24 16:23:08 MST | INFO | load_rule_config | Loading rule config file from /Users/x/Documents/projects/detection-engineering/rule_config.yaml
16-Jan-24 16:23:08 MST | INFO | load_rules | Loaded 37 rules from /Users/x/Documents/projects/detection-engineering/rules
16-Jan-24 16:23:08 MST | INFO | update_remote_rules | Attempting to retrieve latest version of all rules from Chronicle
16-Jan-24 16:23:08 MST | INFO | get_remote_rules | Attempting to retrieve all rules from Chronicle
16-Jan-24 16:23:08 MST | INFO | get_remote_rules | Retrieved a total of 36 rules
16-Jan-24 16:23:10 MST | INFO | update_remote_rules | Checking if any rule updates are required
16-Jan-24 16:23:10 MST | INFO | update_remote_rules | Rule dns_query_to_recently_created_domain (ru_12345678-1234-1234-1234-123456789123) - Rule text is different. Creating new rule version
16-Jan-24 16:23:10 MST | INFO | update_remote_rule_state | Rule okta_new_api_token_created (ru_12345678-1234-1234-1234-123456789123) - Enabling rule
16-Jan-24 16:23:10 MST | INFO | update_remote_rule_state | Rule okta_new_api_token_created (ru_12345678-1234-1234-1234-123456789123) - Enabling alerting for rule
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Local rule name google_workspace_mfa_disabled not found in remote rules
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Local rule google_workspace_mfa_disabled has no rule id value. Creating a new rule
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Created new rule google_workspace_mfa_disabled (ru_12345678-1234-1234-1234-123456789123)
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Logging summary of rule changes...
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Rules created: 1
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | created google_workspace_mfa_disabled (ru_12345678-1234-1234-1234-123456789123)
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Rules new_version_created: 1
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | new_version_created dns_query_to_recently_created_domain (ru_12345678-1234-1234-1234-123456789123)
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Rules enabled: 1
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | enabled okta_new_api_token_created (ru_12345678-1234-1234-1234-123456789123)
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Rules disabled: 0
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Rules alerting_enabled: 1
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | alerting_enabled okta_new_api_token_created (ru_12345678-1234-1234-1234-123456789123)
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Rules alerting_disabled: 0
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Rules archived: 0
16-Jan-24 16:23:11 MST | INFO | update_remote_rules | Rules unarchived: 0
16-Jan-24 16:23:11 MST | INFO | get_remote_rules | Attempting to retrieve all rules from Chronicle
16-Jan-24 16:23:11 MST | INFO | get_remote_rules | Retrieved a total of 37 rules
16-Jan-24 16:23:13 MST | INFO | dump_rules | Writing 37 rule files to /Users/x/Documents/projects/detection-engineering/rules
16-Jan-24 16:23:13 MST | INFO | dump_rule_config | Writing rule config to /Users/x/Documents/projects/detection-engineering/rule_config.yaml
```

## Need help?

Please open an issue in this repo or reach out in the Google Cloud Security [community](https://www.googlecloudcommunity.com/gc/Chronicle/ct-p/security-chronicle).
