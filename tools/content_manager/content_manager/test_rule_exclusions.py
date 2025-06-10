# Copyright 2025 Google LLC
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
"""Tests for content_manager.rule_exclusions."""
import copy
import json
import pathlib
from typing import Any, Mapping, Sequence

from content_manager.common.custom_exceptions import RuleExclusionConfigError
from content_manager.rule_exclusions import RuleExclusion
from content_manager.rule_exclusions import RuleExclusionConfigEntry
from content_manager.rule_exclusions import RuleExclusions
import pydantic
import pytest
import ruamel.yaml
import ruamel.yaml.constructor

ROOT_DIR = pathlib.Path(__file__).parent.parent
RULE_EXCLUSIONS_CONFIG_FILE = ROOT_DIR / "rule_exclusions_config.yaml"
TEST_DATA_DIR = pathlib.Path(__file__).parent / "test_data"
TEST_RULE_EXCLUSIONS_CONFIG_FILE = (
    TEST_DATA_DIR / "test_rule_exclusions_config.yaml"
)

# Use ruamel.yaml to raise an exception if a YAML file contains duplicate keys
ruamel_yaml = ruamel.yaml.YAML(typ="safe")


@pytest.fixture(name="parsed_test_rule_exclusions")
def parsed_test_rule_exclusions_fixture() -> RuleExclusions:
  """Load and parse test rule exclusions."""
  return RuleExclusions.load_rule_exclusion_config(
      rule_exclusion_config_file=TEST_RULE_EXCLUSIONS_CONFIG_FILE
  )


@pytest.fixture(name="raw_test_rule_exclusions")
def raw_rule_exclusions_fixture() -> Sequence[Mapping[str, Any]]:
  """Return a list of raw (unparsed) rule exclusions."""
  test_rule_exclusions_file = TEST_DATA_DIR / "test_rule_exclusions.json"
  with open(test_rule_exclusions_file, "r", encoding="utf-8") as f:
    return json.load(f)


def test_parse_rule_exclusions(
    raw_test_rule_exclusions: Sequence[Mapping[str, Any]],
):
  """Tests for rule_exclusions.RuleExclusions.parse_rule_exclusions."""
  raw_rule_exclusions = copy.deepcopy(raw_test_rule_exclusions)

  # Ensure an exception occurs when attempting to parse a rule exclusion that's
  # missing a required value
  del raw_rule_exclusions[0]["displayName"]

  with pytest.raises(expected_exception=KeyError, match=r"displayName"):
    RuleExclusions.parse_rule_exclusions(rule_exclusions=raw_rule_exclusions)

  raw_rule_exclusions = copy.deepcopy(raw_test_rule_exclusions)

  # Ensure an exception occurs when attempting to parse a rule exclusion that
  # has an invalid value
  raw_rule_exclusions[0]["displayName"] = True

  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=(
          r"validation error for RuleExclusion\nname\n  Input should be a valid"
          r" string"
      ),
  ):
    RuleExclusions.parse_rule_exclusions(rule_exclusions=raw_rule_exclusions)

  raw_rule_exclusions = copy.deepcopy(raw_test_rule_exclusions)

  # Ensure an exception occurs when attempting to parse a rule exclusion with an
  # invalid type
  raw_rule_exclusions[0]["type"] = "invalid type"

  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Input should be .* \[type=literal_error",
  ):
    RuleExclusions.parse_rule_exclusions(rule_exclusions=raw_rule_exclusions)


def test_rule_exclusion():
  """Tests for rule_exclusions.RuleExclusion."""
  # Ensure an exception occurs when attempting to create a RuleExclusion object
  # that's missing a required value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Field required \[type=missing",
  ):
    RuleExclusion(name="test")


def test_load_rule_exclusion_config():
  """Tests for rule_exclusions.load_rule_exclusion_config."""
  RULE_EXCLUSIONS_CONFIG_FILE.touch(exist_ok=True)

  # Test that all local rule exclusions can be loaded
  RuleExclusions.load_rule_exclusion_config()

  # Ensure an exception occurs when a rule exclusions config file contains
  # duplicate keys (e.g. rule exclusion display names).
  with pytest.raises(ruamel.yaml.constructor.DuplicateKeyError):
    RuleExclusions.load_rule_exclusion_config(
        rule_exclusion_config_file=TEST_DATA_DIR
        / "test_rule_exclusions_config_duplicate_keys.yaml"
    )


def test_rule_exclusion_config_entry():
  """Tests for rule_exclusions.RuleExclusionConfigEntry."""
  # Ensure an exception occurs when attempting to create a
  # RuleExclusionConfigEntry object that's missing a required value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Field required \[type=missing",
  ):
    RuleExclusion(name="test")

  # Ensure an exception occurs when attempting to create a
  # RuleExclusionConfigEntry object that has an invalid value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=(
          r"validation error for RuleExclusionConfigEntry\nresource_name\n "
          r" Input should be a valid string"
      ),
  ):
    RuleExclusionConfigEntry(
        name="Rule Exclusion 1",
        resource_name=1234,
        type="DETECTION_EXCLUSION",
        description="Rule exclusion description",
        create_time="2025-03-07T17:23:44.121775Z",
        update_time="2025-03-07T17:23:44.121775Z",
        query='(principal.hostname = "lab-desktop-1234")',
        enabled=True,
        archived=False,
        deployment_state_update_time="2025-03-07T17:23:44.121775Z",
        exclusion_applications={},
    )


def test_check_rule_exclusion_config():
  """Tests for rule_exclusions.RuleExclusions.check_rule_exclusion_config."""
  with open(TEST_RULE_EXCLUSIONS_CONFIG_FILE, "r", encoding="utf-8") as f:
    rule_exclusion_config = ruamel_yaml.load(f)

  # Ensure an exception occurs when a rule exclusion config file contains an
  # invalid key
  rule_exclusion_config["Test 1"]["invalid_key"] = "invalid"
  with pytest.raises(
      RuleExclusionConfigError,
      match=r"Invalid keys .* found for rule exclusion - ",
  ):
    RuleExclusions.check_rule_exclusion_config(config=rule_exclusion_config)

  # Ensure an exception occurs when a rule exclusion config file is missing a
  # required key
  del rule_exclusion_config["Test 1"]["invalid_key"]
  del rule_exclusion_config["Test 1"]["enabled"]
  with pytest.raises(
      RuleExclusionConfigError,
      match=r"Required key \(enabled\) not found for rule exclusion - ",
  ):
    RuleExclusions.check_rule_exclusion_config(config=rule_exclusion_config)


def test_extract_rule_exclusion_id_from_resource_name():
  """Tests for rule_exclusions.RuleExclusions.extract_rule_exclusion_id_from_resource_name."""
  resource_name = "projects/1234567890123/locations/us/instances/871419d4-e315-454c-bc07-b3506aab606a/findingsRefinements/fr_7415c05b-3b00-4de5-9de8-73b46e0ee958"
  rule_exclusion_id = (
      RuleExclusions.extract_rule_exclusion_id_from_resource_name(
          rule_exclusion_resource_name=resource_name
      )
  )
  assert rule_exclusion_id == "fr_7415c05b-3b00-4de5-9de8-73b46e0ee958"
