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
"""Tests for content_manager.reference_lists."""

import copy
import json
import pathlib
from typing import Any, Mapping, Sequence

from content_manager.common.custom_exceptions import ReferenceListConfigError
from content_manager.reference_lists import ReferenceList
from content_manager.reference_lists import ReferenceListConfigEntry
from content_manager.reference_lists import ReferenceLists
import pydantic
import pytest
import ruamel.yaml.constructor


ROOT_DIR = pathlib.Path(__file__).parent.parent
REF_LISTS_DIR = ROOT_DIR / "reference_lists"
REF_LIST_CONFIG_FILE = ROOT_DIR / "reference_list_config.yaml"
TEST_DATA_DIR = pathlib.Path(__file__).parent / "test_data"
TEST_REF_LISTS_DIR = TEST_DATA_DIR / "reference_lists"
TEST_REF_LISTS_CONFIG_FILE = TEST_DATA_DIR / "test_reference_list_config.yaml"


@pytest.fixture(name="parsed_test_ref_lists")
def parsed_test_ref_list_fixture() -> ReferenceLists:
  """Load and parse test reference lists."""
  return ReferenceLists.load_ref_lists(
      ref_lists_dir=TEST_REF_LISTS_DIR,
      ref_list_config_file=TEST_REF_LISTS_CONFIG_FILE,
  )


@pytest.fixture(name="raw_test_ref_lists")
def raw_ref_lists_fixture() -> Sequence[Mapping[str, Any]]:
  """Return a list of raw (unparsed) reference lists."""
  test_ref_lists_file = TEST_DATA_DIR / "test_reference_lists.json"
  with open(test_ref_lists_file, "r", encoding="utf-8") as f:
    return json.load(f)


def test_load_ref_lists():
  """Tests for reference_lists.ReferenceLists.load_ref_lists."""
  REF_LIST_CONFIG_FILE.touch(exist_ok=True)

  # Test that all local reference lists can be loaded
  ref_list_files_count = len(list(REF_LISTS_DIR.glob("*.txt")))
  ref_lists = ReferenceLists.load_ref_lists()
  assert ref_list_files_count == len(ref_lists.ref_lists)

  # Ensure an exception occurs if a reference list config entry is found that
  # doesn't have a corresponding txt file in the reference lists dir
  with pytest.raises(
      expected_exception=ReferenceListConfigError,
      match=r"Reference list file not found with name .*\.txt in ",
  ):
    ReferenceLists.load_ref_lists(
        ref_lists_dir=TEST_REF_LISTS_DIR,
        ref_list_config_file=TEST_DATA_DIR
        / "test_reference_list_config_missing_rule_file.yaml",
    )

  # Ensure an exception occurs if the txt file for a reference list does not
  # have a corresponding entry in the reference list config file
  # Create temporary file in ref lists dir
  temp_ref_list_path = TEST_REF_LISTS_DIR / "test.txt"
  with open(TEST_REF_LISTS_DIR / "test.txt", "w") as f:
    f.write("test")

  with pytest.raises(
      expected_exception=ReferenceListConfigError,
      match=r"Reference list .* not found in reference list config file ",
  ):
    ReferenceLists.load_ref_lists(
        ref_lists_dir=TEST_REF_LISTS_DIR,
        ref_list_config_file=TEST_REF_LISTS_CONFIG_FILE,
    )
  temp_ref_list_path.unlink()


def test_parse_ref_lists(raw_test_ref_lists: Sequence[Mapping[str, Any]]):
  """Tests for reference_lists.ReferenceLists.parse_ref_lists."""
  raw_ref_lists = copy.deepcopy(raw_test_ref_lists)

  # Ensure an exception occurs when attempting to parse a reference list that's
  # missing a required value
  del raw_ref_lists[0]["displayName"]

  with pytest.raises(expected_exception=KeyError, match=r"displayName"):
    ReferenceLists.parse_ref_lists(ref_lists=raw_ref_lists)

  raw_ref_lists = copy.deepcopy(raw_test_ref_lists)

  # Ensure an exception occurs when attempting to parse a reference list that
  # has an invalid value
  raw_ref_lists[0]["name"] = True

  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=(
          r"validation error for ReferenceList\nresource_name\n  Input should"
          r" be a valid string"
      ),
  ):
    ReferenceLists.parse_ref_lists(ref_lists=raw_ref_lists)

  raw_ref_lists = copy.deepcopy(raw_test_ref_lists)

  # Ensure an exception occurs when attempting to parse a ReferenceList with an
  # invalid syntax type
  raw_ref_lists[0]["syntaxType"] = "invalid syntax type"

  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Input should be .* \[type=literal_error",
  ):
    ReferenceLists.parse_ref_lists(ref_lists=raw_ref_lists)


def test_ref_list():
  """Tests for reference_lists.ReferenceList."""
  # Ensure an exception occurs when attempting to create a ReferenceList object
  # that's missing a required value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Field required \[type=missing",
  ):
    ReferenceList(name="test")


def test_load_ref_list_config():
  """Tests for reference_lists.load_ref_list_config."""
  # Ensure an exception occurs when a reference list config file contains
  # duplicate keys (reference list names).
  with pytest.raises(ruamel.yaml.constructor.DuplicateKeyError):
    ReferenceLists.load_ref_list_config(
        ref_list_config_file=TEST_DATA_DIR
        / "test_reference_list_config_duplicate_keys.yaml"
    )


def test_ref_list_config_entry():
  """Tests for reference_lists.ReferenceListConfigEntry."""
  # Ensure an exception occurs when attempting to create a
  # ReferenceListConfigEntry object that's missing a required value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Field required \[type=missing",
  ):
    ReferenceListConfigEntry(name="test")

  # Ensure an exception occurs when attempting to create a
  # ReferenceListConfigEntry object that has an invalid value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=(
          r"validation error for ReferenceListConfigEntry\nresource_name\n "
          r" Input should be a valid string"
      ),
  ):
    ReferenceListConfigEntry(
        name="name",
        resource_name=1234,
        description="description",
        revision_create_time=None,
        syntax_type="REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING",
        rules=None,
        rule_associations_count=None,
    )

  # Ensure an exception occurs when attempting to parse a
  # ReferenceListConfigEntry object with an invalid syntax type
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Input should be .* \[type=literal_error",
  ):
    ReferenceListConfigEntry(
        name="name",
        resource_name="resource_name",
        description="description",
        revision_create_time=None,
        syntax_type="invalid syntax type",
        rules=None,
        rule_associations_count=None,
    )


def test_check_ref_list_config():
  """Tests for reference_lists.ReferenceLists.check_ref_list_config."""
  ref_list_config = ReferenceLists.load_ref_list_config(
      ref_list_config_file=TEST_REF_LISTS_CONFIG_FILE
  )

  # Ensure an exception occurs when a reference list config file contains an
  # invalid key
  ref_list_config["test_list_1"]["invalid_key"] = "invalid"
  with pytest.raises(
      ReferenceListConfigError,
      match=r"Invalid keys .* found for reference list - ",
  ):
    ReferenceLists.check_ref_list_config(config=ref_list_config)

  # Ensure an exception occurs when a reference list config file is missing a
  # required key
  del ref_list_config["test_list_1"]["invalid_key"]
  del ref_list_config["test_list_1"]["description"]
  with pytest.raises(
      ReferenceListConfigError,
      match=r"Required key \(description\) not found for reference list - ",
  ):
    ReferenceLists.check_ref_list_config(config=ref_list_config)


def test_compare_ref_list_content():
  """Tests for reference_lists.ReferenceLists.compare_ref_list_content."""
  # Test that the expected result is returned when the content of two reference
  # lists is compared
  result = ReferenceLists.compare_ref_list_content(
      ref_list_1_entries=["one, two, three"],
      ref_list_2_entries=["one, two, three"],
  )
  assert result is False  # pylint: disable="g-bool-id-comparison"

  result = ReferenceLists.compare_ref_list_content(
      ref_list_1_entries=["one, two, three"],
      ref_list_2_entries=["one, two, four"],
  )
  assert result is True  # pylint: disable="g-bool-id-comparison"
