[![Python 3.10](https://img.shields.io/badge/python-3.10-yellow.svg)](https://www.python.org/downloads/release/python-3100/)

# Example Code for Managing Detection Rules in Chronicle Security Operations

This directory contains example code that can be used to build a Detection-as-Code CI/CD pipeline to manage rules in
[Chronicle Security Operations](https://cloud.google.com/chronicle-security-operations). The code can also be used 
to manage reference lists in Chronicle.

If you're new to the concept of managing detection content with CI/CD tools, we recommend reading our [Getting Started with Detection-as-Code and Chronicle Security Operations](https://www.googlecloudcommunity.com/gc/Community-Blog/Getting-Started-with-Detection-as-Code-and-Chronicle-Security/ba-p/702154) blog series published in the Google Cloud Security Community.

<span style="color: red;">**Important**</span>: This code can modify rules and reference lists in Chronicle. Please 
exercise caution and avoid running it in production without first understanding the code, customizing it for your 
specific use cases, and testing it.

The example code interacts with Chronicle's [API](https://cloud.google.com/chronicle/docs/reference/rest) and can be 
used in a CI/CD pipeline (in GitHub, GitLab, CircleCI, etc) to do the following:

* Verify that a rule is a valid YARA-L 2.0 rule without creating a new rule or evaluating it over data
* Retrieve the latest version of all detection rules from Chronicle and write them to local `.yaral` files along with
their current state/configuration
* Update detection rules in Chronicle based on local rule files, e.g., create new rules, create a new rule version, or
enable/disable/archive rules
* Test a YARA-L rule by running it over a given time range without persisting results in Chronicle
* Retrieve the latest version of all reference lists from Chronicle and write them to local files along with their 
  current state/configuration
* Create or update reference lists in Chronicle based on local files

Sample detection rules can be found in the [Chronicle Detection Rules](https://github.com/chronicle/detection-rules/tree/main)
repo.

## Setup

Use Python 3.10 or above.

```console
# Create and activate a Python virtual environment after cloning this directory into a location of your choosing
$ pip3 install virtualenv
$ python3 -m virtualenv venv
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

#### `CHRONICLE_BASE_URL`

* Set the `CHRONICLE_BASE_URL` variable to your regional service endpoint for the Chronicle API.
* For example, the base URL for the regional service endpoint in the US is https://us-chronicle.googleapis.com/v1alpha 
  and the base URL for the regional service endpoint in Europe is https://eu-chronicle.googleapis.com/v1alpha

#### `CHRONICLE_INSTANCE`

* Set the `CHRONICLE_INSTANCE` variable as follows: `projects/{google-cloud-project-id}/locations/{chronicle-instance-location}/instances/{chronicle-instance-id}`
  * Replace the `{google-cloud-project-id}` placeholder with your Google Cloud project ID that is linked to your 
    Chronicle instance.
  * Replace the `{chronicle-instance-location}` placeholder with the location where your Chronicle instance is running 
    (e.g. `us` for the United States).
  * Replace the `chronicle-instance-id` placeholder with the `Customer ID` for your Chronicle instance. You can find 
    this under `Settings` - `SIEM Settings` - `Profile` in Chronicle's UI.

#### `AUTHORIZATION_SCOPES`

* Set the `AUTHORIZATION_SCOPES` variable to `AUTHORIZATION_SCOPES={"CHRONICLE_API":["https://www.googleapis.com/auth/cloud-platform"]}`
* Refer to the [Authentication methods at Google](https://cloud.google.com/docs/authentication/) documentation for 
  information on OAuth 2.0 scopes.

#### `CHRONICLE_API_CREDENTIALS`

* For the purposes of authenticating to and managing detection rules via Chronicle's API, you can create a [service account](https://cloud.google.com/iam/docs/service-account-overview)
  in the Google Cloud project that's linked to your Chronicle instance.
* Chronicle integrates with Google Cloud Identity and Access Management (IAM) to provide Chronicle-specific permissions
  and predefined roles. Chronicle administrators can control access to Chronicle features by creating IAM policies 
  that bind users or groups to predefined roles or to IAM custom roles. You can read more about configuring 
  Chronicle roles and permissions in IAM [here](https://cloud.google.com/chronicle/docs/onboard/configure-feature-access).
* Assign the Chronicle permissions required to run the code in this project to the service account. 
  * The `Chronicle API Editor` IAM role includes the required permissions to manage rules and reference lists via 
    Chronicle's API. If you prefer to assign more granular permissions to the service account, you can grant the 
    following permissions to the service account or create a custom IAM role and assign that to the service account:

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
    # Permissions required to manage reference lists
    chronicle.referenceLists.get
    chronicle.referenceLists.list
    chronicle.referenceLists.create
    chronicle.referenceLists.update
    # Permissions required to test rules
    chronicle.legacies.legacyTestRuleStreaming
    ```

* Create a service account key for the service account that has the required permissions assigned and set it as the 
  value for the `CHRONICLE_API_CREDENTIALS` variable. Enter the variable's value in JSON format, on a single line as 
  shown in above example `.env` file).
* To follow [best practices](https://cloud.google.com/secret-manager/docs/best-practices) for storing and handling
service account keys, you can customize this code to instead store the key in [Secrets Manager](https://cloud.google.com/secret-manager/docs/overview)
and retrieve it via the [Secrets Manager API](https://cloud.google.com/secret-manager/docs/reference/libraries#client-libraries-install-python).

### Executing the CLI

```console
python -m rule_cli -h
02-Apr-24 10:47:39 MDT | INFO | <module> | Rule CLI started
usage: __main__.py [-h] [--pull-latest-rules] [--update-remote-rules] [--pull-latest-reference-lists] [--update-remote-reference-lists] [--verify-rules] {verify-rule,test-rule} ...

rule_cli

options:
  -h, --help            show this help message and exit
  --pull-latest-rules   Retrieve the latest version of all rules from Chronicle and write them to local files.
  --update-remote-rules
                        Update rules in Chronicle based on local rule files and config.
  --pull-latest-reference-lists
                        Retrieve the latest version of all reference lists from Chronicle and write them to local files.
  --update-remote-reference-lists
                        Update reference lists in Chronicle based on local reference list files and config.
  --verify-rules        Verify that all local rules are valid YARA-L 2.0 rules.

subcommands:
  {verify-rule,test-rule}
    verify-rule         Verify that a rule is a valid YARA-L 2.0 rule.
    test-rule           Runs a YARA-L rule over the given time range without persisting results in Chronicle. Results (detections) are logged to the console.
```

### Running the tests

```console
(venv) $ pip install -r requirements_dev.txt
(venv) $ pytest
```

# Example CI/CD Configuration Files

Example CI/CD configuration files are provided to assist with managing content in Google SecOps via its REST API. You can customize these files to fit your specific requirements.

* [GitLab CI/CD pipeline configuration file](https://github.com/chronicle/detection-rules/blob/main/tools/rule_manager/.gitlab-ci.yml)
* [GitHub Actions workflow files](https://github.com/chronicle/detection-rules/tree/main/tools/rule_manager/rule_cli/etc/github_actions_workflow_files)

# Usage

As mentioned above, the example code in this POC can be customized to fit your needs. The CLI commands can be run
individually as shown below.

## Managing rules in Chronicle

### Pull latest rules from Chronicle

The pull latest rules command retrieves the latest version of all rules from Chronicle and writes them to `.yaral`
files in the `rules` directory.

The rule state is written to the `rule_config.yaml` file. The rule state contains metadata about the state of each rule
such as whether it is enabled/disabled/archived, the rule ID, the rule's revision ID, etc.

Example output from pull latest rules command:

```console
(venv) $ python -m rule_cli --pull-latest-rules
16-Jan-24 16:17:38 MST | INFO | <module> | Rule CLI started
16-Jan-24 16:17:38 MST | INFO | <module> | Attempting to pull latest version of all Chronicle rules and update local files
16-Jan-24 16:17:39 MST | INFO | get_remote_rules | Retrieved a total of 36 rules
16-Jan-24 16:17:41 MST | INFO | dump_rules | Writing 36 rule files to /Users/x/Documents/projects/detection-engineering/rules
16-Jan-24 16:17:41 MST | INFO | dump_rule_config | Writing rule config to /Users/x/Documents/projects/detection-engineering/rule_config.yaml
```

### Verify rule(s)

The `verify-rule` and `--verify-rules` commands use Chronicle's API to verify that YARA-L 2.0 rules are valid without
creating a new rule or evaluating it over data.

Example output from verify rule command:

```console
(venv) $ python -m rule_cli verify-rule -f rules/dns_query_to_recently_created_domain.yaral 
16-Jan-24 16:16:11 MST | INFO | <module> | Rule CLI started
16-Jan-24 16:16:11 MST | INFO | <module> | Attempting to verify rule rules/dns_query_to_recently_created_domain.yaral
16-Jan-24 16:16:11 MST | INFO | verify_rule_text | Rule verified successfully (rules/dns_query_to_recently_created_domain.yaral). Response: {'success': True}

python -m rule_cli --verify-rules
19-Jan-24 11:13:06 MST | INFO | <module> | Rule CLI started
19-Jan-24 11:13:06 MST | INFO | <module> | Attempting to verify all local rules
19-Jan-24 11:13:07 MST | INFO | verify_rules | Rule verification succeeded for rule (/Users/x/Documents/projects/detection-engineering/rules/google_workspace_multiple_files_sent_as_email_attachment_from_google_drive.yaral). Response: {'success': True}
...
19-Jan-24 11:13:10 MST | INFO | verify_rules | Rule verification succeeded for 36 rules
19-Jan-24 11:17:32 MST | ERROR | verify_rules | Rule verification failed for 2 rules
19-Jan-24 11:13:10 MST | ERROR | verify_rules | Rule verification failed for rule (/Users/x/Documents/projects/detection-engineering/rules/okta_new_api_token_created.yaral). Response: {...}
...
```

### Update remote rules

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

### Testing a rule

The `test-rule` command uses Chronicle's REST API to run a YARA-L rule over a given time range without persisting 
results in Chronicle.

Results (detections) are logged to the console. This code can be customized to write the results to a file for 
analysis or add logic to process any detections that are returned.

Example output from `test-rule` command:

```console
python -m rule_cli test-rule -f "/Users/x/Documents/projects/detection-engineering/rules/okta_new_api_token_created.yaral" --start-time 2024-03-12T05:30:00Z --end-time 2024-03-12T07:30:00Z
02-Apr-24 10:57:50 MDT | INFO | <module> | Rule CLI started
02-Apr-24 10:57:50 MDT | INFO | <module> | Attempting to test rule /Users/x/Documents/projects/detection-engineering/rules/okta_new_api_token_created.yaral with event start time of 2024-03-12 05:30:00+00:00 and event end time of 2024-03-12 07:30:00+00:00 and scope None
02-Apr-24 10:57:57 MDT | INFO | stream_test_rule | Initiated connection to test rule stream
02-Apr-24 10:57:57 MDT | DEBUG | stream_test_rule | Retrieved detection
02-Apr-24 10:57:57 MDT | INFO | test_rule | Retrieved 1 detections and 0 rule execution errors
02-Apr-24 10:57:57 MDT | INFO | stream_test_rule | Retrieved 1 detections for rule: /Users/x/Documents/projects/detection-engineering/rules/okta_new_api_token_created.yaral
02-Apr-24 10:57:57 MDT | DEBUG | stream_test_rule | Logging retrieved detections for rule: ...
```

## Managing reference lists in Chronicle

### Pull latest reference lists from Chronicle

The pull latest reference lists command retrieves the latest version of reference lists from Chronicle and writes 
them to `.txt` files in the `reference_lists` directory.

The reference list configuration & metadata is written to the `reference_list_config.yaml` file.

Example output from pull latest reference lists command:

```console
(venv) $ python -m rule_cli --pull-latest-reference-lists
21-Feb-24 15:34:36 MST | INFO | <module> | Rule CLI started
21-Feb-24 15:34:36 MST | INFO | <module> | Attempting to pull latest version of all reference lists from Chronicle and update local files
21-Feb-24 15:34:37 MST | INFO | get_remote_ref_lists | Retrieved a total of 11 reference lists
21-Feb-24 15:34:37 MST | INFO | dump_ref_lists | Writing 11 reference list files to /Users/x/Documents/projects/detection-engineering/reference_lists
21-Feb-24 15:34:37 MST | INFO | dump_ref_list_config | Writing reference list config to /Users/x/Documents/projects/detection-engineering/reference_list_config.yaml
```

### Update remote reference lists

The update remote reference lists command updates reference lists in Chronicle based on local reference list (`.txt`) 
files and the `reference_list_config.yaml` file.

Reference list updates include:

* Create a new reference list
* Replace the contents of an existing reference list
* Update the description or syntax type for a reference list

Please refer to the example reference lists in the `reference_lists` directory and the example
`reference_list_config.yaml` file to understand the expected format for these files.

A `description` for each reference list must be defined in `reference_list_config.yaml`.

The `syntax_type` for each reference list must be defined in `reference_list_config.yaml`. Valid reference list 
types are as follows:

* `REFERENCE_LIST_SYNTAX_TYPE_UNSPECIFIED`
* `REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING`,
* `REFERENCE_LIST_SYNTAX_TYPE_REGEX`
* `REFERENCE_LIST_SYNTAX_TYPE_CIDR`.

Example output from update remote reference lists command.

```console
(venv) $ python -m rule_cli --update-remote-reference-lists
26-Feb-24 11:28:48 MST | INFO | <module> | Rule CLI started
26-Feb-24 11:28:48 MST | INFO | update_remote_ref_lists | Attempting to update reference lists in Chronicle based on local files
26-Feb-24 11:28:48 MST | INFO | update_remote_ref_lists | Loading local reference lists from /Users/x/Documents/projects/detection-engineering/reference_lists
26-Feb-24 11:28:48 MST | INFO | load_ref_list_config | Loading reference list config file from /Users/x/Documents/projects/detection-engineering/reference_list_config.yaml
26-Feb-24 11:28:48 MST | INFO | load_ref_lists | Loaded 12 reference lists from /Users/x/Documents/projects/detection-engineering/reference_lists
26-Feb-24 11:28:48 MST | INFO | get_remote_ref_lists | Attempting to retrieve all reference lists from Chronicle
26-Feb-24 11:28:49 MST | INFO | get_remote_ref_lists | Retrieved 11 reference lists
26-Feb-24 11:28:49 MST | INFO | get_remote_ref_lists | Retrieved a total of 11 reference lists
26-Feb-24 11:28:49 MST | INFO | update_remote_ref_lists | Checking if any reference list updates are required
26-Feb-24 11:28:49 MST | INFO | update_remote_ref_lists | Local reference list name example_list_1 not found in remote reference lists. Creating a new reference list
26-Feb-24 11:28:50 MST | INFO | update_remote_ref_lists | Logging summary of reference list changes...
26-Feb-24 11:28:50 MST | INFO | update_remote_ref_lists | Reference lists created: 1
26-Feb-24 11:28:50 MST | INFO | update_remote_ref_lists | created Reference list example_list_1
26-Feb-24 11:28:50 MST | INFO | update_remote_ref_lists | Reference lists updated: 0
26-Feb-24 11:28:50 MST | INFO | get_remote_ref_lists | Attempting to retrieve all reference lists from Chronicle
26-Feb-24 11:28:51 MST | INFO | get_remote_ref_lists | Retrieved a total of 12 reference lists
26-Feb-24 11:28:51 MST | INFO | dump_ref_lists | Writing 12 reference list files to /Users/x/Documents/projects/detection-engineering/reference_lists
26-Feb-24 11:28:51 MST | INFO | dump_ref_list_config | Writing reference list config to /Users/x/Documents/projects/detection-engineering/reference_list_config.yaml
```

## Need help?

Please open an issue in this repo or reach out in the Google Cloud Security [community](https://www.googlecloudcommunity.com/gc/Chronicle/ct-p/security-chronicle).
