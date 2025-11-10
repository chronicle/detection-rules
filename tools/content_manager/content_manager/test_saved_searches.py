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
"""Tests for content_manager.saved_searches."""

import copy
import json
import pathlib
from typing import Any, Mapping, Sequence

from content_manager.common.custom_exceptions import SavedSearchConfigError
from content_manager.saved_searches import SavedSearch
from content_manager.saved_searches import SavedSearchConfigEntry
from content_manager.saved_searches import SavedSearches

import pydantic
import pytest
import ruamel.yaml.constructor


ROOT_DIR = pathlib.Path(__file__).parent.parent
SAVED_SEARCHES_DIR = ROOT_DIR / "saved_searches"
SAVED_SEARCH_CONFIG_FILE = ROOT_DIR / "saved_search_config.yaml"
TEST_DATA_DIR = pathlib.Path(__file__).parent / "test_data"
TEST_SAVED_SEARCH_CONFIG_FILE = TEST_DATA_DIR / "test_saved_search_config.yaml"

# Use ruamel.yaml to raise an exception if a YAML file contains duplicate keys
ruamel_yaml = ruamel.yaml.YAML(typ="safe")


@pytest.fixture(name="parsed_test_saved_searches")
def parsed_test_saved_searches_fixture() -> SavedSearches:
  """Load and parse test saved searches."""
  return SavedSearches.load_saved_search_config(
      saved_search_config_file=TEST_SAVED_SEARCH_CONFIG_FILE,
  )


@pytest.fixture(name="raw_test_saved_searches")
def raw_test_saved_searches_fixture() -> Sequence[Mapping[str, Any]]:
  """Return a list of raw (unparsed) saved searches."""
  test_saved_searches_file = TEST_DATA_DIR / "test_saved_searches.json"
  with open(test_saved_searches_file, "r", encoding="utf-8") as f:
    return json.load(f)


def test_load_saved_searches_config():
  """Tests for saved_searches.SavedSearches.load_saved_search_config."""
  SAVED_SEARCH_CONFIG_FILE.touch(exist_ok=True)


def test_parse_saved_searches(raw_test_saved_searches: Sequence[Mapping[str, Any]]):
  """Tests for saved_searches.SavedSearches.parse_saved_searches."""
  raw_saved_searches = copy.deepcopy(raw_test_saved_searches)

  # Ensure an exception occurs when attempting to parse a saved search that's
  # missing a required value
  del raw_saved_searches[0]["query"]

  with pytest.raises(expected_exception=KeyError, match=r"query"):
    SavedSearches.parse_saved_searches(raw_saved_searches)


def test_saved_search():
  """Tests for saved_searches.SavedSearch."""
  # Ensure an exception occurs when attempting to create a SavedSearch object
  # that's missing a required value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Field required \[type=missing",
  ):
    SavedSearch(
        name="Blocked Windows Logins by Host",
        resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/users/me/searchQueries/74257fc4-cb92-497d-84be-c9b5bfcd287c",
        query_id="Ab9e5XWvQTu46prKxvQx6Q==",
        user_id="player1@example.com",
        create_time="2025-11-07T16:17:40.197090Z",
        update_time="2025-11-07T16:17:40.197090Z",
        description="Statistical Search Workshop",
        sharing_mode=None,
        query_type=None,
        placeholder_names=None,
        placeholder_descriptions=None
    )

  # Ensure an exception occurs when attempting to create a SavedSearch object
  # with an invalid value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=(
          r"validation error for SavedSearch\nname\n  Input should be a valid"
          r" string"
      ),
  ):
    SavedSearch(
        name=4,
        resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/users/me/searchQueries/74257fc4-cb92-497d-84be-c9b5bfcd287c",
        query_id="Ab9e5XWvQTu46prKxvQx6Q==",
        user_id="player1@example.com",
        create_time="2025-11-07T16:17:40.197090Z",
        update_time="2025-11-07T16:17:40.197090Z",
        description="Statistical Search Workshop",
        query="metadata.vendor_name = \"Microsoft\" AND metadata.product_name = /Windows/ AND metadata.event_type = \"USER_LOGIN\" AND security_result.action = \"BLOCK\" AND principal.hostname != \"\"\n$host = principal.hostname\n$user = target.user.userid\nmatch:\n  $host\noutcome:\n  $user_distinct_count = count_distinct($user)\n  $user_count = count($user)\n  $users_uniq_list = array_distinct($user)\norder:\n   $user_count desc, $user_distinct_count desc",
        sharing_mode=None,
        query_type=None,
        placeholder_names=None,
        placeholder_descriptions=None,
    )


def test_check_saved_search_config():
  """Tests for saved_searches.SavedSearches.check_saved_search_config."""
  # Ensure an exception occurs when a saved search config file contains
  # duplicate keys (saved search names).
  with pytest.raises(ruamel.yaml.constructor.DuplicateKeyError):
    SavedSearches.load_saved_search_config(
        saved_search_config_file=TEST_DATA_DIR / "test_saved_search_config_duplicate_keys.yaml"
    )

  with open(TEST_SAVED_SEARCH_CONFIG_FILE, "r", encoding="utf-8") as f:
    saved_search_config = ruamel_yaml.load(f)

  # Ensure an exception occurs when a saved search config file contains an
  # invalid key
  saved_search_config["Blocked Windows Logins by Host"]["invalid_key"] = "invalid"
  with pytest.raises(
      SavedSearchConfigError,
      match=r"Invalid keys .* found for saved search - ",
  ):
    SavedSearches.check_saved_search_config(config=saved_search_config)

  # Ensure an exception occurs when a saved search config file is missing a
  # required key
  del saved_search_config["Blocked Windows Logins by Host"]["invalid_key"]
  del saved_search_config["Blocked Windows Logins by Host"]["query"]
  with pytest.raises(
      SavedSearchConfigError,
      match=r"Required key \(query\) not found for saved search - ",
  ):
    SavedSearches.check_saved_search_config(config=saved_search_config)


def test_saved_search_config_config_entry():
  """Tests for saved_searches.SavedSearchConfigEntry."""
  # Ensure an exception occurs when attempting to create a
  # SavedSearchConfigEntry object that's missing a required value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Field required \[type=missing",
  ):
    SavedSearchConfigEntry(
      name="Blocked Windows Logins by Host",
      resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/users/me/searchQueries/74257fc4-cb92-497d-84be-c9b5bfcd287c",
      query_id="Ab9e5XWvQTu46prKxvQx6Q==",
      user_id="player1@example.com",
      create_time="2025-11-07T16:17:40.197090Z",
      update_time="2025-11-07T16:17:40.197090Z",
      description="Statistical Search Workshop",
      sharing_mode=None,
      query_type=None,
      placeholder_names=None,
      placeholder_descriptions=None
    )

  # Ensure an exception occurs when attempting to create a
  # SavedSearchConfigEntry object with an invalid value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=(
          r"validation error for SavedSearchConfigEntry\nsharing_mode\n "
          r" Input should be "
      ),
  ):
    SavedSearchConfigEntry(
        name="Blocked Windows Logins by Host",
        resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/users/me/searchQueries/74257fc4-cb92-497d-84be-c9b5bfcd287c",
        query_id="Ab9e5XWvQTu46prKxvQx6Q==",
        user_id="player1@example.com",
        create_time="2025-11-07T16:17:40.197090Z",
        update_time="2025-11-07T16:17:40.197090Z",
        description="Statistical Search Workshop",
        query='metadata.vendor_name = "Microsoft" AND metadata.product_name = /Windows/ AND metadata.event_type = "USER_LOGIN" AND security_result.action = "BLOCK" AND principal.hostname != ""\n$host = principal.hostname\n$user = target.user.userid\nmatch:\n  $host\noutcome:\n  $user_distinct_count = count_distinct($user)\n  $user_count = count($user)\n  $users_uniq_list = array_distinct($user)\norder:\n   $user_count desc, $user_distinct_count desc',
        sharing_mode="INVALID",
        query_type=None,
        placeholder_names=None,
        placeholder_descriptions=None,
    )
