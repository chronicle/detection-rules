# Style Guide for YARA-L Detection Rules

Detection Rules for Chronicle Security Operations are written in the
[YARA-L 2.0](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-overview) language.

This style guide establishes baseline standards of quality, completeness, readability, and extensibility for
community-published rules. This guide also sets an example for what high quality rules look like and what components
detection engineers should include in their own rules.

## Characteristics of quality community detection rules

Detection rules in this project should:

- Provide value out of the box, even if users must tweak them to provide the most value. A rule should solve a real
problem, meet a specific use case, or address a contemporary threat.
- Serve as a jumping off point or inspiration for detection engineers to create their own detections.
- Highlight capabilities that exist within Chronicle's detection engine.
- Be optimized for performance wherever possible.

## Rule file format

Each rule file should have a `.yaral` extension.

The following license must be included at the beginning of each rule file.

```
/*
 * Copyright 2023 Google LLC
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
```

Ensure that there are no tabs or trailing whitespaces in your rule.

## YARA-L 2.0 rule sections

### `meta` section

Guidance on the `meta` section of a rule.

#### General information

All rules should have:

- An author of `Google Cloud Security`. 
- A description that provides a base level of understanding of the detection itself. 
- A severity defined (`Info`, `Low`, `Medium`, `High`, or `Critical`).
- A priority defined (`Info`, `Low`, `Medium`, `High`, or `Critical`).

Values that would be helpful in providing additional context around the rule include the following and are considered
optional:

- `platform` - The platform(s) that this rule focuses on.
  - It is possible to specify multiple platforms. For example, a Windows based EDR event that is correlated with events 
    from Google Cloud.
  - Not all rules will have this field/value, as some rules can be platform-agnostic.
  - Example: `platform = "Windows, GCP"`


- `type` - The rule type. Examples include `alert` or `hunt`.
  - `alert` is used for higher fidelity rules that are candidates for deployment while `hunt` might cause false
    positives but provide results that could be used as part of a threat hunt.
  - Example: `type = "hunt"`


- `data_source` - What data sources were used for testing the rule, i.e., what logs should the rule run against.
  - While it may not be possible to validate every data source, by providing representative data source(s), authors can
    provide some level of understanding on the approach being taken in the rule.
  - Example: `data_source = "microsoft sysmon, custom misp parser"`


- `assumptions` - What are the things that the author took into account when writing the rule that someone deploying
  the rule should be aware of.
    - Example: `assumption = "While it should work for any EDR systems and ingested threat intel, the
      metadata.product_name for MISP should be modified or commented out based upon event source."`


- `reference` - If a website has a write-up on this attack technique or the rule is ported from another platform's
reference site, it should be cited here.
  - Example: `reference = "https://mysource.for.this.rule/if-applicable"`


- `tags` - Used to denote ways to group rules using specific functionality. Example: `tags = “whois, vt”`. Additional
  example values include: 
  - `asset enrichment`
  - `threat indicators`
  - `asset entity`
  - `safe browsing`
  - `user enrichment`
  - `prevalence`
  - `resource entity`
  - `benign binaries`
  - `vt enrichment`
  - `first last seen`
  - `user entity`
  - `tor`
  - `geoip enrichment`
  - `list`
  - `vt`
  - `whois`
  - `rat`

#### MITRE ATT&CK mapping

All rules that map to [MITRE ATT&CK](https://attack.mitre.org/matrices/enterprise/) should include the following fields
in the meta section:
- Tactic
- Technique: Sub-Technique (if applicable)
- URL
- Framework [Version](https://attack.mitre.org/resources/versions/) (e.g. `v13.1`, `v12`, `v11`)
  - The purpose of this field is to "future-proof" a rule so if a technique is deprecated or evolves, a user can
    reference the specific version of ATT&CK to understand the rationale of the rule based on the point of time it was
    created. An example of this would be a rule for the technique `Common Port` which was deprecated. If the rule was
    labeled correctly as `v6`, this technique could be seen in that version of the matrix.

Example MITRE ATT&CK mapping in the `meta` section of a rule:

```
meta:
  author = "Google Cloud Security"
  description = "Detect the use of net use for SMB/Windows admin shares"
  mitre_attack_tactic = "Lateral Movement"
  mitre_attack_technique = "Remote Services: SMB/Windows Admin Shares"
  mitre_attack_url = "https://attack.mitre.org/techniques/T1021/002/"
  mitre_attack_version = "v13.1"
  type = "alert"
  data_source = "microsoft sysmon, microsoft windows events"
  severity = "Low"
  priority = "Low"
```

### `events` section

Guidance on the `events` section of a rule.

#### Variables

All event variables should be descriptive to ensure readability, preferably not `$event` and definitely not `$e1`.

All placeholder variables should be descriptive enough to understand and if it concatenates multiple words together
should be separated with underscores, i.e., `$my_variable_for_hostname`.

- A placeholder like `$hostname` is perfectly fine particularly when joining disparate nouns together.
- Using the same variable name with a different capitalization should be avoided if possible, i.e., `$Host` and `$host`.

Joins between events and entities should be represented with a placeholder variable in each line where possible to
ensure readability and ease of understanding

Joins on full field names are possible and will work, but using placeholder variables is preferred and can be used in
outcomes fields as well.

Additional fields and values that improve the performance of the rules should be used whenever possible. Examples of
this include:

- Adding a `<hash> != "hash_value"` to narrow down process launch or file creation events except if the field is being
  used as a match variable (see the `match` section of this guide below).
- Using `metadata.entity_type` for all entity based rules.
- Using `metadata.source_type` for all entity based rules.
- Using `metadata.event_type` where possible for UDM events.

### `match` section

Guidance on the `match` section of a rule.

Most rules should have a `match` section, so that related alerts are grouped together into a single detection.

Match variables automatically exclude `NULL` values (`""` and `0` for strings and integers, respectively), unless the
[`allow_zero_values`](https://cloud.google.com/chronicle/docs/detection/yara-l-2-0-syntax#options_section_syntax) option
is set. Unless that option is set, do not add conditions in the events section that duplicate this logic. The following
is NOT correct:

```
events:
  $e.target.ip = "1.1.1.1"
  $hostname = $e.principal.hostname
  $e.principal.hostname != "" // unnecessary
  
match:
  $hostname
```

### `outcome` section

Guidance on the `outcome` section of a rule.

The `outcome` section can contain up to 20 outcome variables and should be populated with the below fields where
possible.

Outcome variables and associated names may find their way into 3rd party integrations, so descriptive names including
the noun are preferred and should be separated with underscores, i.e., `$target_process_command_line`.

- `risk_score`
  - In the absence of a specific risk score, applying a value that aligns with the rule's severity (specified in the
    `meta` section) is reasonable.

    | severity | risk_score |
    |----------|------------|
    | Info     | 10         |
    | Low      | 35         |
    | Medium   | 65         |
    | High     | 85         |
    | Critical | 95         |

    - Specific criteria do not need to be applied unless the rule author has something in mind. Organizations have
      different risk scoring metrics and Chronicle continues to evolve with the introduction of new capabilities.


- `event_count` - for single-event variable rules.
  - Example: `$event_count = count_distinct($e.metadata.id)`
- Any hardcoded values in the condition section, greater than 1.
  - Given a condition of `#failed_logons > 100`, define a variable of `$failed_logon_threshold = max(100)`


- MITRE ATT&CK tactic and technique:sub-technique should be added in the outcome section where applicable.
  - This is in addition to values being displayed in the meta section. 
  - Including this data in the outcome provides values that can be used in SOAR platforms or other reporting as it will
    appear in the detection generated by the rule.
  - If a technique is listed in multiple tactics, add all applicable tactics to the outcome variable as shown below. By
    separating with a comma and space, additional parsing should be predictable.
    - `$mitre_attack_tactic = array_distinct("Lateral Movement, Execution")`
  - For techniques with a single tactic, the following format should be used.
    - `$mitre_attack_tactic = array_distinct("Lateral Movement")`
  - Techniques with sub-techniques will be delimited by a colon and space.
    - `$mitre_attack_technique = array_distinct("Remote Services: SMB/Windows Admin Shares")`
  - Technique ids should be represented in the following format.
    - `$mitre_attack_technique_id = array_distinct("T1021.002")`


- Consider adding the following fields, as they are utilized in the alert graph: `principal`, `target`, and `src`. 
  - Within these families, the following fields can be used in the alert graph (preview, subject to change, fields in
    bold will be visualized, all will provide active links to search). 
    - **hostname**
    - process.command_line
    - **user.email_addresses**
    - **ip**
    - **process.file.md5**
    - **file.md5**
    - **mac**
    - **process.file.sha1**
    - **file.sha1**
    - **asset_id**
    - **process.file.sha256**
    - **file.sha256**
    - **asset.hostname**
    - process.file.full_path
    - file.full_path
    - **asset.ip**
    - process.product_specific_process_id
    - **resource.name**
    - **asset.mac**
    - process.parent_process.product_specific_process_id
    - **url**
    - **asset.asset_id**
    - **user.userid**
    - **artifact.ip**
    - asset.product_object_id 
    - **user.windows_sid**
    - **domain.name**
    - process.pid 
    - user.product_object_id 
    - resource.product_object_id 
    - user.employee_id
  - The syntax for these fields should be in the form of:
    `$principal_hostname = array_distinct($event.principal.hostname)`


- Any additional summary values or fields of interest based upon the rule should also be included in the outcome section. 

## Appendix

### Example outcome variables for use with the alert graph

These are based on a limited set of data sources during testing. These serve as a reference set of fields that will
populate the alert graph for additional context based upon the `metadata.event_type` in the rule.

#### Example outcome variables for event type `NETWORK_CONNECTION`

````
$principal_ip = array_distinct($network.principal.ip)
$target_ip = array_distinct($network.target.ip)
$principal_process_pid = array_distinct($network.principal.process.pid)
$principal_process_command_line = array_distinct($network.principal.process.command_line)
$principal_process_file_sha256 = array_distinct($network.principal.process.file.sha256)
$principal_process_file_full_path = array_distinct($network.principal.process.file.full_path)
$principal_process_product_specfic_process_id = array_distinct($network.principal.process.product_specific_process_id)
$principal_process_parent_process_product_specfic_process_id = array_distinct($network.principal.process.parent_process.product_specific_process_id)
$target_process_pid = array_distinct($network.target.process.pid)
$target_process_command_line = array_distinct($network.target.process.command_line)
$target_process_file_sha256 = array_distinct($network.target.process.file.sha256)
$target_process_file_full_path = array_distinct($network.target.process.file.full_path)
$target_process_product_specfic_process_id = array_distinct($network.target.process.product_specific_process_id)
$target_process_parent_process_product_specfic_process_id = array_distinct($network.target.process.parent_process.product_specific_process_id)
$principal_user_userid = array_distinct($network.principal.user.userid)
$target_user_userid = array_distinct($network.target.user.userid)
````

#### Example outcome variables for event type `NETWORK_HTTP`

```
$principal_hostname = array_distinct($network.principal.hostname)
$target_hostname = array_distinct($network.target.hostname)
$principal_user_userid = array_distinct($network.principal.user.userid)
$target_url = array_distinct($network.target.url)
```

#### Example outcome variables for event type `USER_LOGIN`

```
$principal_hostname = array_distinct($login.principal.hostname)
$principal_ip = array_distinct($login.principal.ip)
$target_hostname = array_distinct($login.target.hostname)
$target_ip = array_distinct($login.target.ip)
$principal_user_userid = array_distinct($login.principal.user.userid)
$target_user_userid = array_distinct($login.target.user.userid)
$principal_resource_name = array_distinct($login.principal.resource.name)
$target_resource_name = array_distinct($login.target.resource.name)
$target_url = array_distinct($login.target.url)
```

#### Example outcome variables for event type `PROCESS_LAUNCH`

```
$principal_hostname = array_distinct($execution.principal.hostname)
$principal_process_pid = array_distinct($execution.principal.process.pid)
$principal_process_command_line = array_distinct($execution.principal.process.command_line)
$principal_process_file_sha256 = array_distinct($execution.principal.process.file.sha256)
$principal_process_file_full_path = array_distinct($execution.principal.process.file.full_path)
$principal_process_product_specfic_process_id = array_distinct($execution.principal.process.product_specific_process_id)
$principal_process_parent_process_product_specfic_process_id = array_distinct($execution.principal.process.parent_process.product_specific_process_id)
$target_process_pid = array_distinct($execution.target.process.pid)
$target_process_command_line = array_distinct($execution.target.process.command_line)
$target_process_file_sha256 = array_distinct($execution.target.process.file.sha256)
$target_process_file_full_path = array_distinct($execution.target.process.file.full_path)
$target_process_product_specfic_process_id = array_distinct($execution.target.process.product_specific_process_id)
$principal_user_userid = array_distinct($execution.principal.user.userid)
```

#### Example outcome variables for event type `FILE_CREATION`

```
$principal_hostname = array_distinct($execution.principal.hostname)
$principal_process_pid = array_distinct($execution.principal.process.pid)
$principal_process_command_line = array_distinct($execution.principal.process.command_line)
$principal_process_file_sha256 = array_distinct($execution.principal.process.file.sha256)
$principal_process_file_full_path = array_distinct($execution.principal.process.file.full_path)
$principal_process_product_specfic_process_id = array_distinct($execution.principal.process.product_specific_process_id)
$principal_process_parent_process_product_specfic_process_id = array_distinct($execution.principal.process.parent_process.product_specific_process_id)
$target_process_pid = array_distinct($execution.target.process.pid)
$target_process_command_line = array_distinct($execution.target.process.command_line)
$target_process_file_sha256 = array_distinct($execution.target.process.file.sha256)
$target_process_file_full_path = array_distinct($execution.target.process.file.full_path)
$target_process_product_specfic_process_id = array_distinct($execution.target.process.product_specific_process_id)
$principal_user_userid = array_distinct($execution.principal.user.userid)
$target_file_sha256 = array_distinct($execution.target.file.sha256)
$target_file_full_path = array_distinct($execution.target.file.full_path)
```

#### Example outcome variables for event type `NETWORK_DNS`

```
$principal_ip = array_distinct($dns.principal.ip)
$target_ip = array_distinct($dns.target.ip)
$principal_process_pid = array_distinct($dns.principal.process.pid)
$principal_process_file_full_path = array_distinct($dns.principal.process.file.full_path)
$principal_process_product_specfic_process_id = array_distinct($dns.principal.process.product_specific_process_id)
$principal_user_userid = array_distinct($dns.principal.user.userid)
$principal_process_command_line = array_distinct($dns.principal.process.command_line)
$principal_process_file_sha256 = array_distinct($dns.principal.process.file.sha256)
$principal_process_parent_process_product_specfic_process_id = array_distinct($dns.principal.process.parent_process.product_specific_process_id)
$network_dns_questions_name = array_distinct($dns.network.dns.questions.name)
$network_dns_answers_data = array_distinct($dns.network.dns.answers.data)
```
