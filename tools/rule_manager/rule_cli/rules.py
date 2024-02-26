# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Manage rules in Chronicle."""

# pylint: disable="g-bool-id-comparison","g-explicit-length-test"

import collections
import dataclasses
import hashlib
import logging
import pathlib
import re
import time
from typing import Any, List, Mapping, Optional, Sequence, Tuple

from chronicle_api.rules.create_rule import create_rule
from chronicle_api.rules.get_rule_deployment import get_rule_deployment
from chronicle_api.rules.list_rules import list_rules
from chronicle_api.rules.update_rule import update_rule
from chronicle_api.rules.update_rule_deployment import update_rule_deployment
from google.auth.transport import requests
import ruamel.yaml
from rule_cli.common import DuplicateRuleIdError
from rule_cli.common import DuplicateRuleNameError
from rule_cli.common import RuleConfigError
from rule_cli.common import RuleError
import yaml

LOGGER = logging.getLogger()

ROOT_DIR = pathlib.Path(__file__).parent.parent
RULES_DIR = ROOT_DIR / "rules"
RULE_CONFIG_FILE = ROOT_DIR / "rule_config.yaml"

# Use ruamel.yaml to raise an exception if a YAML file contains duplicate keys
# (i.e. duplicate rule names)
ruamel_yaml = ruamel.yaml.YAML(typ="safe")


@dataclasses.dataclass
class Rule:
  """Class for a YARA-L rule."""

  name: str
  id: Optional[str]
  resource_name: Optional[str]
  create_time: Optional[str]
  revision_id: Optional[str]
  revision_create_time: Optional[str]
  enabled: bool
  alerting: bool
  archived: Optional[bool]
  archive_time: Optional[str]
  run_frequency: Optional[str]
  type: Optional[str]
  text: str


class Rules:
  """Class used to manage rules."""

  def __init__(self, rules: List[Rule]):
    self.rules: List[Rule] = rules

  @classmethod
  def parse_rule(cls, rule: Mapping[str, Any]) -> Rule:
    """Parse a rule into a Rule object."""
    # Set enabled, alerting, and archived options based on the rule's current
    # state in Chronicle.
    if rule["deployment_state"].get("enabled") is True:
      pass
    else:
      rule["deployment_state"]["enabled"] = False

    if rule["deployment_state"].get("alerting") is True:
      pass
    else:
      rule["deployment_state"]["alerting"] = False

    if rule["deployment_state"].get("archived") is True:
      pass
    else:
      rule["deployment_state"]["archived"] = False

    # Extract the rule ID from the resource_name value
    rule_id_match = re.search(
        pattern=r"\/(ru_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$)",
        string=rule["name"],
    )
    rule_id = rule_id_match.group(1)

    parsed_rule = Rule(
        name=rule["displayName"],
        id=rule_id,
        resource_name=rule["name"],
        create_time=rule["createTime"],
        revision_id=rule["revisionId"],
        revision_create_time=rule["revisionCreateTime"],
        enabled=rule["deployment_state"]["enabled"],
        alerting=rule["deployment_state"]["alerting"],
        archived=rule["deployment_state"]["archived"],
        archive_time=rule["deployment_state"].get("archiveTime"),
        run_frequency=rule["deployment_state"].get("runFrequency"),
        type=rule["type"],
        text=rule["text"],
    )

    return parsed_rule

  @classmethod
  def parse_rules(cls, rules: Sequence[Mapping[str, Any]], skip_archived: bool = False) -> List[Rule]:
    """Parse a list of rules into a list of Rule objects."""
    parsed_rules = []

    for rule in rules:
        if skip_archived is True and rule["deployment_state"].get("archived") is True:
            LOGGER.debug("Skipping parsing for archived rule %s", rule["displayName"])
        else:
            parsed_rules.append(Rules.parse_rule(rule))

    return parsed_rules

  @classmethod
  def load_rules(
      cls,
      rules_dir: pathlib.Path = RULES_DIR,
      rule_config_file: pathlib.Path = RULE_CONFIG_FILE,
  ) -> "Rules":
    """Load rule files and config from disk."""
    rule_config = Rules.load_rule_config(rule_config_file)

    rule_files = list(rules_dir.glob("*.yaral"))
    non_rule_files = [
        file_path
        for file_path in rules_dir.glob("*")
        if not file_path.name.endswith(".yaral")
    ]

    if len(non_rule_files) > 0:
      LOGGER.warning(
          "%s files found in rules directory without .yaral extension. These"
          " files will not be processed",
          len(non_rule_files),
      )

    rules = []

    for rule_file_path in rule_files:
      with open(rule_file_path, "r", encoding="utf-8") as f:
        rule_text = f.read()

      rule_name = Rules.extract_rule_name(
          rule_file_path=rule_file_path, rule_text=rule_text
      )

      if rule_config.get(rule_name) is None:
        raise RuleConfigError(
            f"{rule_name} not found in rule config file {rule_config_file}"
        )

      rule = Rule(
          name=rule_name,
          id=rule_config[rule_name].get("id"),
          resource_name=rule_config[rule_name].get("resource_name"),
          create_time=rule_config[rule_name].get("create_time"),
          revision_id=rule_config[rule_name].get("revision_id"),
          revision_create_time=rule_config[rule_name].get(
              "revision_create_time"
          ),
          enabled=rule_config[rule_name]["enabled"],
          alerting=rule_config[rule_name]["alerting"],
          archived=rule_config[rule_name].get("archived"),
          archive_time=rule_config[rule_name].get("archive_time"),
          run_frequency=rule_config[rule_name].get("run_frequency"),
          type=rule_config[rule_name].get("rule_type"),
          text=rule_text,
      )

      Rules.check_rule_settings(rule)

      rules.append(rule)

    LOGGER.info("Loaded %s rules from %s", len(rules), rules_dir)

    Rules.check_for_duplicate_rule_names(rules)

    Rules.check_for_duplicate_rule_ids(rules)

    return Rules(rules=rules)

  @classmethod
  def load_rule_config(
      cls, rule_config_file: pathlib.Path = RULE_CONFIG_FILE
  ) -> Mapping[str, Any]:
    """Load rule config from file."""
    LOGGER.info("Loading rule config file from %s", rule_config_file)
    with open(rule_config_file, "r", encoding="utf-8") as f:
      rule_config = ruamel_yaml.load(f)

    Rules.check_rule_config(rule_config)

    return rule_config

  def dump_rules(self, rules_dir: pathlib.Path = RULES_DIR):
    """Dump a list of rules to local files."""
    # Write rules out to .yaral files
    LOGGER.info("Writing %s rule files to %s", len(self.rules), rules_dir)
    for rule in self.rules:
      # Use the rule name for the file name.
      rule_file_path = f"{rules_dir}/{rule.name}.yaral"

      # Dump the rule to a file.
      with open(rule_file_path, "w", encoding="utf-8") as rule_file:
        rule_file.write(rule.text)

  def dump_rule_config(self):
    """Dump the config/state for a collection of rules."""
    rule_config = {}

    for rule in self.rules:
      rule_name = rule.name
      rule_dict = dataclasses.asdict(rule)
      # rule text not needed in rule config file.
      del rule_dict["text"]
      # rule name not required in config entry. The key for the config entry is
      # set to the rule name.
      del rule_dict["name"]
      rule_config[rule_name] = rule_dict

    rule_config_file_path = ROOT_DIR / "rule_config.yaml"

    LOGGER.info("Writing rule config to %s", rule_config_file_path)
    with open(rule_config_file_path, "w", encoding="utf-8") as rule_config_file:
      yaml.dump(rule_config, rule_config_file, sort_keys=True)

  @classmethod
  def get_remote_rules(
      cls, http_session: requests.AuthorizedSession, skip_archived: bool = False
  ) -> "Rules":
    """Retrieve the latest version of all rules from Chronicle."""
    raw_rules = []
    next_page_token = None

    LOGGER.info("Attempting to retrieve all rules from Chronicle")
    while True:
      retrieved_rules, next_page_token = list_rules(
          http_session=http_session,
          page_size=None,
          page_token=next_page_token,
          view="FULL",
      )
      time.sleep(0.6)  # Sleep to avoid exceeding API rate limit

      if retrieved_rules is not None:
        LOGGER.info("Retrieved %s rules", len(retrieved_rules))
        raw_rules.extend(retrieved_rules)

      if next_page_token:
        LOGGER.info(
            "Attempting to retrieve rules with page token %s", next_page_token
        )
      else:
        # Break if there are no more pages of rules to retrieve
        break

    raw_rules_count = len(raw_rules)

    LOGGER.info("Retrieved a total of %s rules", raw_rules_count)

    LOGGER.info(
        "Attempting to retrieve rule deployment state for %s rules",
        raw_rules_count,
    )
    for rule in raw_rules:
      rule["deployment_state"] = get_rule_deployment(
          http_session=http_session, resource_name=rule["name"]
      )
      time.sleep(0.6)  # Sleep to avoid exceeding API rate limit

    parsed_rules = Rules.parse_rules(rules=raw_rules, skip_archived=skip_archived)

    Rules.check_for_duplicate_rule_names(rules=parsed_rules)

    return Rules(rules=parsed_rules)

  @classmethod
  def compare_rule_text(cls, rule_text_1: str, rule_text_2: str) -> bool:
    """Compare the rulet ext value of two rules."""
    # Compute MD5 hash for each rule's ruleText value.
    rule_1_hash = hashlib.md5(rule_text_1.encode(encoding="utf-8")).hexdigest()
    rule_2_hash = hashlib.md5(rule_text_2.encode(encoding="utf-8")).hexdigest()

    if rule_1_hash == rule_2_hash:
      return False
    else:
      # Return True if the rule text values are different.
      return True

  @classmethod
  def check_for_duplicate_rule_names(cls, rules: List[Rule]):
    """Check for duplicate rule names in a list of rules."""
    rule_name_counts = collections.Counter([rule.name for rule in rules])
    duplicate_rule_names = [
        rule_name_count
        for rule_name_count in rule_name_counts.items()
        if rule_name_count[1] > 1
    ]
    if len(duplicate_rule_names) > 0:
      for rule_name, count in duplicate_rule_names:
        LOGGER.info("%s rules found with the same name %s", count, rule_name)
      raise DuplicateRuleNameError(
          f"Duplicate rule names found {duplicate_rule_names}."
      )

  @classmethod
  def check_for_duplicate_rule_ids(cls, rules: List[Rule]):
    """Check for duplicate rule ID values in a list of rules."""
    rule_id_counts = collections.Counter([rule.id for rule in rules])
    del rule_id_counts[
        None
    ]  # Delete the count for new rules that don't have an ID yet.
    duplicate_rule_ids = [
        rule_id_count
        for rule_id_count in rule_id_counts.items()
        if rule_id_count[1] > 1
    ]
    if len(duplicate_rule_ids) > 0:
      for rule_id, count in duplicate_rule_ids:
        LOGGER.info("%s rules found with the same name %s", count, rule_id)
      raise DuplicateRuleIdError(
          f"Duplicate rule IDs found {duplicate_rule_ids}."
      )

  @classmethod
  def extract_rule_name(
      cls, rule_file_path: pathlib.Path, rule_text: str
  ) -> str:
    """Extract the rule name from the YARA-L rule."""
    rule_name_match = re.search(
        pattern=r"rule(\s+)([A-Za-z0-9_]+)[\r\n\s]*", string=rule_text
    )

    if rule_name_match:
      rule_name = rule_name_match.group(2)
    else:
      raise RuleError(
          f"Unable to extract rule name from YARA-L rule in {rule_file_path}"
      )

    # For this project, the rule name will be used as the unique identifier for
    # a rule. Check that the rule's file name matches the rule name in the
    # YARA-L rule (in the ruleText) field.
    if rule_file_path.stem != rule_name:
      raise RuleError(
          f"Rule name in YARA-L rule ({rule_name}) does not match file name"
          f" ({rule_file_path})"
      )

    return rule_name

  @classmethod
  def check_rule_config(cls, config: Mapping[str, Any]):
    """Check rule config file for invalid keys."""
    required_keys = ["alerting", "enabled"]
    allowed_keys = [
        "alerting",
        "archive_time",
        "archived",
        "create_time",
        "enabled",
        "id",
        "resource_name",
        "revision_create_time",
        "revision_id",
        "run_frequency",
        "type",
    ]
    invalid_keys = []

    for rule_name, rule_config in config.items():
      for key in list(rule_config.keys()):
        if key not in allowed_keys:
          invalid_keys.append(key)

      if len(invalid_keys) > 0:
        raise RuleConfigError(
            f"Invalid keys ({invalid_keys}) found for rule - {rule_name}"
        )

      for key in required_keys:
        if key not in list(rule_config.keys()):
          raise RuleConfigError(
              f"Required key ({key}) not found for rule - {rule_name}"
          )

  @classmethod
  def check_rule_settings(cls, rule: Rule):
    """Check a rule for invalid setting combinations."""
    # Check that the enabled and alerting options are set.
    if rule.enabled is None:
      raise RuleConfigError(
          f"{rule.name} - enabled (true/false) option is missing."
      )
    if rule.alerting is None:
      raise RuleConfigError(
          f"{rule.name} - alerting (true/false) option is missing."
      )

    # Check that enabled or alerting are not set to True if archived is set to
    # True.
    if rule.archived is True and (
        rule.enabled is True or rule.alerting is True
    ):
      raise RuleConfigError(
          f"Rule {rule.name} - Invalid rule settings. An archived rule cannot"
          " be enabled or have alerting enabled."
      )

  @classmethod
  def update_remote_rules(
      cls,
      http_session: requests.AuthorizedSession,
      rules_dir: pathlib.Path = RULES_DIR,
      rule_config_file: pathlib.Path = RULE_CONFIG_FILE,
      skip_archived: bool = False
  ) -> Mapping[str, Sequence[Tuple[str, str]]] | None:
    """Attempting to update rules in Chronicle based on local rule files."""
    LOGGER.info(
        "Attempting to update rules in Chronicle based on local rule files"
    )

    LOGGER.info("Loading local files from %s", rules_dir)
    local_rules = Rules.load_rules(
        rules_dir=rules_dir, rule_config_file=rule_config_file
    )

    if len(local_rules.rules) == 0:
      LOGGER.info("No local rule files found")
      return

    LOGGER.info(
        "Attempting to retrieve latest version of all rules from Chronicle"
    )
    remote_rules = Rules.get_remote_rules(http_session=http_session, skip_archived=skip_archived)

    # Create a dictionary containing the remote rules using the rule name as the
    # key for each item.
    remote_rules_dict = {}

    if len(remote_rules.rules) > 0:
      for remote_rule in remote_rules.rules:
        remote_rules_dict[remote_rule.name] = remote_rule

    # Keep track of rule updates to log a final summary of changes made.
    update_summary = {
        "created": [],
        "new_version_created": [],
        "enabled": [],
        "disabled": [],
        "alerting_enabled": [],
        "alerting_disabled": [],
        "archived": [],
        "unarchived": [],
    }

    LOGGER.info("Checking if any rule updates are required")
    for local_rule in local_rules.rules:
      rule_name = local_rule.name

      if rule_name in remote_rules_dict.keys():
        # Rule exists in Chronicle with same rule name as local rule.
        rule_id = local_rule.id
        remote_rule = remote_rules_dict[rule_name]

        # Create a new version of the rule if the rule text in the local rule is
        # different from the remote rule
        LOGGER.debug(
            "Rule %s (%s) - Comparing rule text in local and remote rule",
            rule_name,
            rule_id,
        )
        if (
            Rules.compare_rule_text(
                rule_text_1=local_rule.text, rule_text_2=remote_rule.text
            )
            is True
        ):
          LOGGER.info(
              "Rule %s (%s) - Rule text is different. Creating new rule"
              " version",
              rule_name,
              rule_id,
          )
          update_rule(
              http_session=http_session,
              resource_name=local_rule.resource_name,
              update_mask=["text"],
              updates={"text": local_rule.text},
          )
          time.sleep(0.6)  # Sleep to avoid exceeding API rate limit
          update_summary["new_version_created"].append((rule_id, rule_name))
        LOGGER.debug(
            "Rule %s (%s) - No changes found in rule text", rule_name, rule_id
        )

      else:
        # Rule does not exist in Chronicle with same rule name as local rule
        LOGGER.info("Local rule name %s not found in remote rules", rule_name)

        # A new rule will be created if a remote rule doesn't exist with the
        # same name as the local rule and there's no rule id value for the rule
        # in the local rule config file.
        if local_rule.id is None:
          LOGGER.info(
              "Local rule %s has no rule id value. Creating a new rule",
              rule_name,
          )
          new_rule = create_rule(
              http_session=http_session, rule_text=local_rule.text
          )
          time.sleep(0.6)  # Sleep to avoid exceeding API rate limit
          new_rule["deployment_state"] = get_rule_deployment(
              http_session=http_session, resource_name=new_rule["name"]
          )
          time.sleep(0.6)  # Sleep to avoid exceeding API rate limit
          remote_rule = Rules.parse_rule(new_rule)
          LOGGER.info(
              "Created new rule %s (%s)", remote_rule.name, remote_rule.id
          )
          rule_id = remote_rule.id
          local_rule.rule_id = rule_id
          local_rule.resource_name = remote_rule.resource_name
          update_summary["created"].append((rule_id, rule_name))

        # If a remote rule doesn't exist with the same name as the local rule,
        # but there's a rule id for the local rule, the local rule has been
        # renamed. Create a new version of the existing rule in Chronicle.
        else:
          rule_id = local_rule.rule_id
          LOGGER.info(
              "Rule %s (%s) - Creating new rule version for existing rule",
              rule_name,
              rule_id,
          )
          new_rule_version = update_rule(
              http_session=http_session,
              resource_name=local_rule.resource_name,
              update_mask=["text"],
              updates={"text": local_rule.text},
          )
          time.sleep(0.6)  # Sleep to avoid exceeding API rate limit
          remote_rule = Rules.parse_rule(new_rule_version)
          update_summary["new_version_created"].append((rule_id, rule_name))

      rule_state_updates = Rules.update_remote_rule_state(
          http_session=http_session,
          local_rule=local_rule,
          remote_rule=remote_rule,
      )

      # Update change summary dictionary with any rule changes that were made.
      if rule_state_updates.get("enabled") is True:
        update_summary["enabled"].append((rule_id, rule_name))
      if rule_state_updates.get("disabled") is True:
        update_summary["disabled"].append((rule_id, rule_name))
      if rule_state_updates.get("alerting_enabled") is True:
        update_summary["alerting_enabled"].append((rule_id, rule_name))
      if rule_state_updates.get("alerting_disabled") is True:
        update_summary.get("alerting_disabled").append((rule_id, rule_name))
      if rule_state_updates.get("archived") is True:
        update_summary["archived"].append((rule_id, rule_name))
      if rule_state_updates.get("unarchived") is True:
        update_summary["unarchived"].append((rule_id, rule_name))

    return update_summary

  @classmethod
  def update_remote_rule_state(
      cls,
      http_session: requests.AuthorizedSession,
      local_rule: Rule,
      remote_rule: Rule,
  ) -> Mapping[str, Any]:
    """Update the deployment state for a rule based on the configuration of a local rule and a remote rule."""
    rule_updates = {}
    rule_name = local_rule.name
    rule_id = local_rule.id
    log_msg_prefix = f"Rule {rule_name} ({rule_id})"

    LOGGER.debug(
        "%s - Checking if the rule should be unarchived", log_msg_prefix
    )
    # Unarchive the rule if required.
    if local_rule.archived is False and remote_rule.archived is True:
      LOGGER.info("%s - Unarchiving rule", log_msg_prefix)
      update_rule_deployment(
          http_session=http_session,
          resource_name=local_rule.resource_name,
          update_mask=["archived"],
          updates={"archived": False},
      )
      time.sleep(0.6)  # Sleep to avoid exceeding API rate limit
      rule_updates["unarchived"] = True

    LOGGER.debug(
        "%s - Checking if the rule should be enabled/disabled.", log_msg_prefix
    )
    # Enable the rule if required.
    if local_rule.enabled is True and remote_rule.enabled is False:
      LOGGER.info("%s - Enabling rule", log_msg_prefix)
      update_rule_deployment(
          http_session=http_session,
          resource_name=local_rule.resource_name,
          update_mask=["enabled"],
          updates={"enabled": True},
      )
      time.sleep(0.6)  # Sleep to avoid exceeding API rate limit
      rule_updates["enabled"] = True

    # Disable the rule if required.
    elif local_rule.enabled is False and remote_rule.enabled is True:
      LOGGER.info("%s - Disabling rule", log_msg_prefix)
      update_rule_deployment(
          http_session=http_session,
          resource_name=local_rule.resource_name,
          update_mask=["enabled"],
          updates={"enabled": False},
      )
      time.sleep(0.6)  # Sleep to avoid exceeding API rate limit
      rule_updates["disabled"] = True

    LOGGER.debug(
        "%s - Checking if alerting should be enabled/disabled", log_msg_prefix
    )
    # Enable alerting for the rule if required.
    if local_rule.alerting is True and remote_rule.alerting is False:
      LOGGER.info("%s - Enabling alerting for rule", log_msg_prefix)
      update_rule_deployment(
          http_session=http_session,
          resource_name=local_rule.resource_name,
          update_mask=["alerting"],
          updates={"alerting": True},
      )
      time.sleep(0.6)  # Sleep to avoid exceeding API rate limit
      rule_updates["alerting_enabled"] = True

    # Disable alerting for the rule if required.
    elif local_rule.alerting is False and remote_rule.alerting is True:
      LOGGER.info("%s - Disabling alerting for rule", log_msg_prefix)
      update_rule_deployment(
          http_session=http_session,
          resource_name=local_rule.resource_name,
          update_mask=["alerting"],
          updates={"alerting": False},
      )
      time.sleep(0.6)  # Sleep to avoid exceeding API rate limit
      rule_updates["alerting_disabled"] = True

    LOGGER.debug("%s - Checking if the rule should be archived", log_msg_prefix)
    # Archive the rule if required.
    if local_rule.archived is True and remote_rule.archived is False:
      LOGGER.info("%s - Archiving rule", log_msg_prefix)
      update_rule_deployment(
          http_session=http_session,
          resource_name=local_rule.resource_name,
          update_mask=["archived"],
          updates={"archived": True},
      )
      time.sleep(0.6)  # Sleep to avoid exceeding API rate limit
      rule_updates["archived"] = True

    return rule_updates
