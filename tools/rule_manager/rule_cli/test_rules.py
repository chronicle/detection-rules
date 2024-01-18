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
"""Tests for rule_cli.rules."""

# pylint: disable="g-bool-id-comparison"

import copy
import json
import pathlib
from typing import Any, Mapping, Sequence

import pytest
import ruamel.yaml.constructor
from rule_cli.common import DuplicateRuleIdError
from rule_cli.common import DuplicateRuleNameError
from rule_cli.common import RuleConfigError
from rule_cli.common import RuleError
from rule_cli.rules import Rules

ROOT_DIR = pathlib.Path(__file__).parent.parent
RULES_DIR = ROOT_DIR / "rules"
TEST_DATA_DIR = pathlib.Path(__file__).parent / "test_data"
TEST_RULES_DIR = TEST_DATA_DIR / "rules"
TEST_RULE_CONFIG_FILE = TEST_DATA_DIR / "test_rule_config.yaml"


@pytest.fixture(name="parsed_test_rules")
def parsed_test_rules_fixture() -> Rules:
  """Load and parse test rules."""
  return Rules.load_rules(
      rules_dir=TEST_RULES_DIR, rule_config_file=TEST_RULE_CONFIG_FILE
  )


@pytest.fixture(name="raw_test_rules")
def raw_test_rules_fixture() -> Sequence[Mapping[str, Any]]:
  """Return a list of raw (unparsed) test rules."""
  test_rules_file = TEST_DATA_DIR / "test_rules.json"
  with open(test_rules_file, "r", encoding="utf-8") as f:
    return json.load(f)


def test_load_local_rules():
  """Test that all local rules can be loaded."""
  rule_files_count = len(list(RULES_DIR.glob("*.yaral")))
  rules = Rules.load_rules()
  assert rule_files_count == len(rules.rules)


def test_parse_invalid_rule(raw_test_rules: Sequence[Mapping[str, Any]]):
  """Test that exceptions occur when attempting to parse an invalid rule."""
  raw_rules = copy.deepcopy(raw_test_rules)

  del raw_rules[0]["name"]

  with pytest.raises(expected_exception=KeyError, match=r"name"):
    Rules.parse_rules(raw_rules)


def test_rule_settings(parsed_test_rules: Rules):
  """Test that an exception occurs when a rule has invalid setting combinations."""
  rule = copy.deepcopy(parsed_test_rules.rules[0])

  # Ensure an exception occurs when archived is True and enabled is True.
  rule.enabled = True
  rule.alerting = False
  rule.archived = True

  with pytest.raises(
      expected_exception=RuleConfigError,
      match=(
          r"Rule .* - Invalid rule settings\. An archived rule cannot be"
          r" enabled or have alerting enabled\."
      ),
  ):
    Rules.check_rule_settings(rule)

  # Ensure an exception occurs when archived is True and alerting is True.
  rule.enabled = False
  rule.alerting = True
  rule.archived = True

  with pytest.raises(
      expected_exception=RuleConfigError,
      match=(
          r"Invalid rule settings\. An archived rule cannot be enabled or have"
          r" alerting enabled\."
      ),
  ):
    Rules.check_rule_settings(rule)

  # Ensure an exception occurs when enabled option is None.
  rule = copy.deepcopy(parsed_test_rules.rules[0])
  rule.enabled = None

  with pytest.raises(
      expected_exception=RuleConfigError,
      match=r" - enabled \(true\/false\) option is missing\.",
  ):
    Rules.check_rule_settings(rule)

  # Ensure exception occurs when alerting_enabled flag is None.
  rule = copy.deepcopy(parsed_test_rules.rules[0])
  rule.alerting = None

  with pytest.raises(
      expected_exception=RuleConfigError,
      match=r" - alerting \(true\/false\) option is missing.",
  ):
    Rules.check_rule_settings(rule)


def test_compare_rule_text():
  """Test that the expected result is returned when the rule text of two rules is compared."""
  result = Rules.compare_rule_text(rule_text_1="rule1", rule_text_2="rule1")
  assert result is False

  result = Rules.compare_rule_text(rule_text_1="rule1", rule_text_2="rule2")
  assert result is True


def test_check_for_duplicate_rule_names(parsed_test_rules):
  """Test that an exception occurs when duplicate rule names are found in a list of rules."""
  rules = copy.deepcopy(parsed_test_rules.rules)
  rules[0].name = rules[1].name

  with pytest.raises(
      expected_exception=DuplicateRuleNameError,
      match=r"Duplicate rule names found",
  ):
    Rules.check_for_duplicate_rule_names(rules)


def test_check_for_duplicate_rule_ids(parsed_test_rules):
  """Test that an exception occurs when duplicate rule IDs are found in a list of rules."""
  rules = copy.deepcopy(parsed_test_rules.rules)
  rules[0].id = rules[1].id

  with pytest.raises(DuplicateRuleIdError) as excinfo:
    Rules.check_for_duplicate_rule_ids(rules)
  assert "Duplicate rule IDs found" in str(excinfo.value)


def test_extract_rule_name(parsed_test_rules: Rules):
  """Test that an exception occurs when the rule name can't be extracted from a YARA-L rule."""
  rule = copy.deepcopy(parsed_test_rules.rules[0])
  rule_file_path = pathlib.Path(TEST_RULES_DIR / f"{rule.name}.yaral")

  # Ensure an exception occurs when the rule name can't be extracted from the
  # ruleText field.
  rule.text = ""
  with pytest.raises(RuleError) as excinfo:
    Rules.extract_rule_name(rule_file_path=rule_file_path, rule_text=rule.text)
  assert "Unable to extract rule name from YARA-L rule in" in str(excinfo.value)

  # Ensure an exception occurs when the rule name in the YARA-L rule doesn't
  # match the rule's file name.
  rule = copy.deepcopy(parsed_test_rules.rules[0])
  rule_file_path = pathlib.Path(TEST_RULES_DIR / "test.yaral")
  with pytest.raises(
      RuleError,
      match=r"Rule name in YARA-L rule \(.*\) does not match file name .*",
  ):
    Rules.extract_rule_name(rule_file_path=rule_file_path, rule_text=rule.text)


def test_load_rule_config():
  """Test that an exception occurs when the rule config file is malformed."""
  # Ensure an exception occurs when a rule config file contains duplicate keys
  # (rule names).
  with pytest.raises(ruamel.yaml.constructor.DuplicateKeyError):
    Rules.load_rule_config(
        rule_config_file=TEST_DATA_DIR / "test_rule_config_duplicate_keys.yaml"
    )

  rule_config = Rules.load_rule_config(rule_config_file=TEST_RULE_CONFIG_FILE)

  rule_config["rule_1"]["invalid_key"] = "invalid"

  # Ensure an exception occurs when the rule config entry contains an invalid
  # key.
  with pytest.raises(
      RuleConfigError, match=r"Invalid keys .* found for rule - "
  ):
    Rules.check_rule_config(config=rule_config)

  del rule_config["rule_1"]["invalid_key"]
  del rule_config["rule_1"]["alerting"]
  # Ensure an exception occurs when the rule config entry is missing a required
  # key.
  with pytest.raises(
      RuleConfigError,
      match=r"Required key \(alerting\) not found for rule - ",
  ):
    Rules.check_rule_config(config=rule_config)
