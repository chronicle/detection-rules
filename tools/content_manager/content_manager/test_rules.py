# Copyright 2024 Google LLC
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
"""Tests for content_manager.rules."""

# pylint: disable="g-bool-id-comparison"

import copy
import json
import pathlib
from typing import Any, Mapping, Sequence

from content_manager.common.custom_exceptions import DuplicateRuleIdError
from content_manager.common.custom_exceptions import DuplicateRuleNameError
from content_manager.common.custom_exceptions import RuleConfigError
from content_manager.common.custom_exceptions import RuleError
from content_manager.rules import Rule
from content_manager.rules import RuleConfigEntry
from content_manager.rules import Rules
import pydantic
import pytest
import ruamel.yaml.constructor

ROOT_DIR = pathlib.Path(__file__).parent.parent
RULES_DIR = ROOT_DIR / "rules"
RULE_CONFIG_FILE = ROOT_DIR / "rule_config.yaml"
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


def test_load_rules():
  """Tests for rules.Rules.load_rules."""
  RULES_DIR.mkdir(exist_ok=True)
  RULE_CONFIG_FILE.touch(exist_ok=True)

  # Test that all local rules can be loaded
  rule_files_count = len(list(RULES_DIR.glob("*.yaral")))
  rules = Rules.load_rules()
  assert rule_files_count == len(rules.rules)

  # Ensure an exception occurs if a rule config entry is found that doesn't
  # have a corresponding .yaral file in the rules directory
  with pytest.raises(
      RuleConfigError,
      match=(
          r"Rule file not found in .*\/rules with same name as rule config"
          r" entry "
      ),
  ):
    Rules.load_rule_config(
        rule_config_file=TEST_DATA_DIR
        / "test_rule_config_missing_rule_file.yaml",
        rules_dir=TEST_RULES_DIR,
    )


def test_parse_rules(raw_test_rules: Sequence[Mapping[str, Any]]):
  """Tests for rules.Rules.parse_rules."""
  raw_rules = copy.deepcopy(raw_test_rules)

  # Ensure an exception occurs when attempting to parse a rule that's missing a
  # required value
  del raw_rules[0]["name"]

  with pytest.raises(expected_exception=KeyError, match=r"name"):
    Rules.parse_rules(raw_rules)

  raw_rules = copy.deepcopy(raw_test_rules)

  # Ensure an exception occurs when attempting to extract the rule ID from the
  # resource name value
  raw_rules[0][
      "name"
  ] = "projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/rules/invalid_rule_name"
  with pytest.raises(
      expected_exception=AttributeError,
      match=r"'NoneType' object has no attribute 'group'",
  ):
    Rules.parse_rules(raw_rules)


def test_rule():
  """Tests for rules.Rule."""
  # Ensure an exception occurs when attempting to create a Rule object that's
  # missing a required value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Field required \[type=missing",
  ):
    Rule(name="test")

  # Ensure an exception occurs when attempting to create a Rule object with an
  # invalid value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=(
          r"validation error for Rule\nenabled\n  Input should be a valid"
          r" boolean"
      ),
  ):
    Rule(
        name="rule_name",
        id=None,
        resource_name=None,
        create_time=None,
        revision_id=None,
        revision_create_time=None,
        # enabled should be True/False, not None
        enabled=None,
        alerting=True,
        archived=False,
        archive_time=None,
        run_frequency=None,
        type=None,
        text="rule_text",
    )


def test_check_rule_settings(parsed_test_rules: Rules):
  """Tests for rules.Rules.check_rule_settings."""
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


def test_compare_rule_text():
  """Tests for rules.Rules.compare_rule_text."""
  result = Rules.compare_rule_text(rule_text_1="rule1", rule_text_2="rule1")
  assert result is False

  result = Rules.compare_rule_text(rule_text_1="rule1", rule_text_2="rule2")
  assert result is True


def test_check_for_duplicate_rule_names(parsed_test_rules):
  """Tests for rules.Rules.check_for_duplicate_rule_names."""
  rules = copy.deepcopy(parsed_test_rules.rules)
  rules[0].name = rules[1].name

  with pytest.raises(
      expected_exception=DuplicateRuleNameError,
      match=r"Duplicate rule names found",
  ):
    Rules.check_for_duplicate_rule_names(rules)

  # Ensure a DuplicateRuleNameError exception is raised when duplicate rule
  # names are found with different character casing
  rules[0].name = rules[1].name.upper()
  with pytest.raises(
      expected_exception=DuplicateRuleNameError,
      match=r"Duplicate rule names found",
  ):
    Rules.check_for_duplicate_rule_names(rules)


def test_check_for_duplicate_rule_ids(parsed_test_rules):
  """Tests for rules.Rules.check_for_duplicate_rule_ids."""
  rules = copy.deepcopy(parsed_test_rules.rules)
  rules[0].id = rules[1].id

  with pytest.raises(DuplicateRuleIdError) as excinfo:
    Rules.check_for_duplicate_rule_ids(rules)
  assert "Duplicate rule IDs found" in str(excinfo.value)


def test_build_rule_update_plan_unchanged(parsed_test_rules):
  """An unchanged ruleset produces a stable, empty plan."""
  remote_rules = copy.deepcopy(parsed_test_rules)

  plan = Rules.build_rule_update_plan(parsed_test_rules, remote_rules)
  reversed_plan = Rules.build_rule_update_plan(
      Rules(rules=list(reversed(parsed_test_rules.rules))), remote_rules
  )

  assert plan["changes"] == []
  assert plan["unchanged_rules"] == len(parsed_test_rules.rules)
  assert plan["plan_digest"] == reversed_plan["plan_digest"]


def test_build_rule_update_plan_revision_and_state(parsed_test_rules):
  """Text and deployment differences are represented as separate changes."""
  remote_rules = copy.deepcopy(parsed_test_rules)
  remote_rule = remote_rules.rules[0]
  remote_rule.text = f"{remote_rule.text}\n// remote-only change"
  remote_rule.enabled = not parsed_test_rules.rules[0].enabled
  remote_rule.alerting = not parsed_test_rules.rules[0].alerting

  plan = Rules.build_rule_update_plan(parsed_test_rules, remote_rules)
  rule_changes = [
      change
      for change in plan["changes"]
      if change["rule_name"] == parsed_test_rules.rules[0].name
  ]

  assert [change["action"] for change in rule_changes] == [
      "create_revision",
      "set_enabled",
      "set_alerting",
  ]
  assert rule_changes[0]["remote_revision_id"] == remote_rule.revision_id
  assert "text" not in json.dumps(plan)
  assert "projects/" not in json.dumps(plan)


def test_build_rule_update_plan_create_and_rename(parsed_test_rules):
  """New and renamed rules retain state and revision evidence."""
  local_rules = copy.deepcopy(parsed_test_rules)
  remote_rules = copy.deepcopy(parsed_test_rules)
  new_rule = local_rules.rules[0].model_copy(update={
      "name": "new_rule",
      "id": None,
      "resource_name": None,
      "revision_id": None,
  })
  renamed_rule = local_rules.rules[1].model_copy(
      update={"name": "renamed_rule"}
  )
  local_rules.rules = [new_rule, renamed_rule]

  plan = Rules.build_rule_update_plan(local_rules, remote_rules)

  assert plan["changes"][0]["action"] == "create"
  assert plan["changes"][0]["desired_state"] == {
      "enabled": new_rule.enabled,
      "alerting": new_rule.alerting,
      "archived": new_rule.archived,
  }
  assert plan["changes"][1]["action"] == "create_revision"
  assert (
      plan["changes"][1]["remote_revision_id"]
      == remote_rules.rules[1].revision_id
  )


def test_plan_remote_rule_updates_never_mutates(monkeypatch, parsed_test_rules):
  """Planning may read remote state but must never call a mutating API."""
  remote_rules = copy.deepcopy(parsed_test_rules)
  mutation_calls = []

  monkeypatch.setattr(
      Rules,
      "load_rules",
      classmethod(lambda cls, rules_dir, rule_config_file: parsed_test_rules),
  )
  monkeypatch.setattr(
      Rules,
      "get_remote_rules",
      classmethod(lambda cls, http_session: remote_rules),
  )

  def record_mutation(*args, **kwargs):
    mutation_calls.append((args, kwargs))

  monkeypatch.setattr("content_manager.rules.create_rule", record_mutation)
  monkeypatch.setattr("content_manager.rules.update_rule", record_mutation)
  monkeypatch.setattr(
      "content_manager.rules.update_rule_deployment", record_mutation
  )

  plan = Rules.plan_remote_rule_updates(http_session=object())

  assert plan is not None
  assert mutation_calls == []


def test_extract_rule_name(parsed_test_rules: Rules):
  """Tests for rules.Rules.extract_rule_name."""
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


def test_check_rule_config():
  """Tests for rules.Rules.check_rule_config."""
  # Ensure an exception occurs when a rule config file contains duplicate
  # keys (rule names).
  with pytest.raises(ruamel.yaml.constructor.DuplicateKeyError):
    Rules.load_rule_config(
        rule_config_file=TEST_DATA_DIR / "test_rule_config_duplicate_keys.yaml",
        rules_dir=TEST_RULES_DIR,
    )

  rule_config = Rules.load_rule_config(
      rule_config_file=TEST_RULE_CONFIG_FILE, rules_dir=TEST_RULES_DIR
  )

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


def test_rule_config_entry():
  """Tests for rules.RuleConfigEntry."""
  # Ensure an exception occurs when attempting to create a RuleConfigEntry
  # object that's missing a required value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Field required \[type=missing",
  ):
    RuleConfigEntry(
        name="rule_name",
    )

  # Ensure an exception occurs when attempting to create a RuleConfigEntry
  # object with an invalid value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=(
          r"validation error for RuleConfigEntry\nalerting\n  Input should be a"
          r" valid boolean"
      ),
  ):
    RuleConfigEntry(
        name="rule_name",
        id=None,
        resource_name=None,
        create_time=None,
        revision_id=None,
        revision_create_time=None,
        enabled=True,
        alerting="invalid_value",
        archived=False,
        archive_time=None,
        run_frequency=None,
        type=None,
    )
