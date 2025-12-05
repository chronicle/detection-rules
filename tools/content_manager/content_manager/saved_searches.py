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
"""Manage saved searches in Google SecOps."""

import json
import logging
import pathlib
from typing import Any, Literal

from content_manager.common.custom_exceptions import SavedSearchConfigError
from google.auth.transport import requests
from google_secops_api.saved_searches.create_saved_search import create_saved_search
from google_secops_api.saved_searches.list_saved_searches import list_saved_searches
from google_secops_api.saved_searches.update_saved_search import update_saved_search
import pydantic
import ruamel.yaml


LOGGER = logging.getLogger()

ROOT_DIR = pathlib.Path(__file__).parent.parent
SAVED_SEARCH_CONFIG_FILE = ROOT_DIR / "saved_search_config.yaml"
SHARING_MODES = Literal["MODE_SHARED_WITH_CUSTOMER"]  # pylint: disable="invalid-name"

# Use ruamel.yaml to raise an exception if a YAML file contains duplicate keys
ruamel_yaml = ruamel.yaml.YAML()
ruamel_yaml.default_flow_style = False


class SavedSearch(pydantic.BaseModel):
  """Class for a saved search."""

  name: str
  resource_name: str | None
  query_id: str | None
  user_id: str | None
  create_time: str | None
  update_time: str | None
  description: str | None
  query: str
  sharing_mode: SHARING_MODES | None
  query_type: str | None
  placeholder_names: list[str] | None
  placeholder_descriptions: list[str] | None


class SavedSearchConfigEntry(pydantic.BaseModel):
  """Class for a saved search config file entry."""

  name: str
  resource_name: str | None
  query_id: str | None
  user_id: str | None
  create_time: str | None
  update_time: str | None
  description: str | None
  query: str
  sharing_mode: SHARING_MODES | None
  query_type: str | None
  placeholder_names: list[str] | None
  placeholder_descriptions: list[str] | None


class SavedSearches:
  """Class used to manage saved searches in Google SecOps."""

  def __init__(self, saved_searches: list[SavedSearch]):
    self.saved_searches: list[SavedSearch] = saved_searches

  @classmethod
  def parse_saved_search(cls, saved_search: dict[str, Any]) -> SavedSearch:
    """Parse a saved search into a SavedSearch object."""
    try:
      parsed_saved_search = SavedSearch(
          name=saved_search["displayName"],
          resource_name=saved_search.get("name"),
          query_id=saved_search.get("queryId"),
          user_id=saved_search.get("userId"),
          create_time=saved_search["metadata"]["createTime"],
          update_time=saved_search["metadata"]["updateTime"],
          description=saved_search.get("description"),
          query=saved_search["query"],
          sharing_mode=saved_search["metadata"].get("sharingMode"),
          query_type=saved_search.get("queryType"),
          placeholder_names=saved_search.get("placeholderNames"),
          placeholder_descriptions=saved_search.get("placeholderDescriptions"),
      )
    except pydantic.ValidationError as e:
      LOGGER.error(
          "ValidationError occurred for saved search %s\n%s",
          saved_search,
          json.dumps(e.errors(), indent=4),
      )
      raise

    return parsed_saved_search

  @classmethod
  def parse_saved_searches(
      cls, saved_searches: list[dict[str, Any]]
  ) -> list[SavedSearch]:
    """Parse a list of saved searches into a list of SavedSearch objects."""
    parsed_saved_searches = []

    for saved_search in saved_searches:
      parsed_saved_searches.append(
          SavedSearches.parse_saved_search(saved_search)
      )

    return parsed_saved_searches

  @classmethod
  def load_saved_search_config(
      cls, saved_search_config_file: pathlib.Path = SAVED_SEARCH_CONFIG_FILE
  ) -> "SavedSearches":
    """Load saved search config from file."""
    LOGGER.info(
        "Loading saved search config from %s",
        saved_search_config_file,
    )
    with open(saved_search_config_file, "r", encoding="utf-8") as f:
      saved_search_config = ruamel_yaml.load(f)

    if not saved_search_config:
      LOGGER.info("Saved search config file is empty.")
      return SavedSearches(saved_searches=[])

    SavedSearches.check_saved_search_config(saved_search_config)

    saved_searches_parsed = []

    for (
        saved_search_name,
        saved_search_config_entry,
    ) in saved_search_config.items():
      try:
        saved_searches_parsed.append(
            SavedSearch(
                name=saved_search_name,
                resource_name=saved_search_config_entry.get("resource_name"),
                query_id=saved_search_config_entry.get("query_id"),
                user_id=saved_search_config_entry.get("user_id"),
                create_time=saved_search_config_entry.get("create_time"),
                update_time=saved_search_config_entry.get("update_time"),
                description=saved_search_config_entry.get("description"),
                query=saved_search_config_entry["query"],
                sharing_mode=saved_search_config_entry.get("sharing_mode"),
                query_type=saved_search_config_entry.get("query_type"),
                placeholder_names=saved_search_config_entry.get(
                    "placeholder_names"
                ),
                placeholder_descriptions=saved_search_config_entry.get(
                    "placeholder_descriptions"
                ),
            )
        )
      except pydantic.ValidationError as e:
        LOGGER.error(
            "ValidationError occurred for saved search config entry %s\n%s",
            saved_search_name,
            json.dumps(e.errors(), indent=4),
        )
        raise

    LOGGER.info(
        "Loaded %s saved search config entries from file %s",
        len(saved_searches_parsed),
        saved_search_config_file,
    )

    return SavedSearches(saved_searches=saved_searches_parsed)

  @classmethod
  def check_saved_search_config(cls, config: dict[str, Any]):
    """Check saved search config file for invalid keys."""
    required_keys = ["query"]
    allowed_keys = [
        "create_time",
        "description",
        "placeholder_names",
        "placeholder_descriptions",
        "query",
        "query_id",
        "query_type",
        "resource_name",
        "sharing_mode",
        "update_time",
        "user_id",
    ]
    invalid_keys = []

    for saved_search_name, saved_search_config in config.items():
      for key in list(saved_search_config.keys()):
        if key not in allowed_keys:
          invalid_keys.append(key)

      if invalid_keys:
        raise SavedSearchConfigError(
            f"Invalid keys ({invalid_keys}) found for saved search -"
            f" {saved_search_name}"
        )

      for key in required_keys:
        if key not in list(saved_search_config.keys()):
          raise SavedSearchConfigError(
              f"Required key ({key}) not found for saved search -"
              f" {saved_search_name}"
          )

  def dump_saved_search_config(self):
    """Dump the configuration and metadata for a collection of saved searches."""
    saved_search_config = {}

    for saved_search in self.saved_searches:
      try:
        saved_search_config_entry = SavedSearchConfigEntry(
            name=saved_search.name,
            resource_name=saved_search.resource_name,
            query_id=saved_search.query_id,
            user_id=saved_search.user_id,
            create_time=saved_search.create_time,
            update_time=saved_search.update_time,
            description=saved_search.description,
            query=saved_search.query,
            sharing_mode=saved_search.sharing_mode,
            query_type=saved_search.query_type,
            placeholder_names=saved_search.placeholder_names,
            placeholder_descriptions=saved_search.placeholder_descriptions,
        )
      except pydantic.ValidationError as e:
        LOGGER.error(
            "ValidationError occurred for saved search config entry %s\n%s",
            saved_search,
            json.dumps(e.errors(), indent=4),
        )
        raise

      saved_search_config[saved_search.name] = (
          saved_search_config_entry.model_dump(exclude={"name"})
      )

      # Use ruamel.yaml.scalarstring import LiteralScalarString on the Saved
      # Search query field to force the YAML dumper to use the "literal block
      # style" (denoted by the | character) when writing multi-line strings to
      # a file.
      if "\n" in saved_search_config[saved_search.name]["query"]:
        saved_search_config[saved_search.name]["query"] = (
            ruamel.yaml.scalarstring.LiteralScalarString(saved_search.query)
        )

    LOGGER.info("Writing saved search config to %s", SAVED_SEARCH_CONFIG_FILE)
    with open(
        SAVED_SEARCH_CONFIG_FILE, "w", encoding="utf-8"
    ) as saved_search_config_file:
      ruamel_yaml.dump(
          saved_search_config,
          saved_search_config_file,
      )

  @classmethod
  def get_remote_saved_searches(
      cls, http_session: requests.AuthorizedSession
  ) -> "SavedSearches":
    """Retrieve the latest version of all saved searches from Google SecOps."""
    raw_saved_searches = []
    next_page_token = None

    LOGGER.info("Attempting to retrieve all saved searches from Google SecOps")
    while True:
      (
          retrieved_saved_searches,
          next_page_token,
      ) = list_saved_searches(
          http_session=http_session,
          page_size=None,
          page_token=next_page_token,
      )

      if retrieved_saved_searches is not None:
        LOGGER.info(
            "Retrieved %s saved searches",
            len(retrieved_saved_searches),
        )
        raw_saved_searches.extend(retrieved_saved_searches)

      if next_page_token:
        LOGGER.info(
            "Attempting to retrieve saved searches with page token %s",
            next_page_token,
        )
      else:
        # Break if there are no more pages of saved searches to retrieve
        break

    raw_saved_searches_count = len(raw_saved_searches)

    LOGGER.info(
        "Retrieved a total of %s saved searches", raw_saved_searches_count
    )

    if not raw_saved_searches:
      return SavedSearches(saved_searches=[])

    parsed_saved_searches = SavedSearches.parse_saved_searches(
        saved_searches=raw_saved_searches
    )

    return SavedSearches(saved_searches=parsed_saved_searches)

  @classmethod
  def update_remote_saved_searches(
      cls,
      http_session: requests.AuthorizedSession,
      saved_searches_config_file: pathlib.Path = SAVED_SEARCH_CONFIG_FILE,
  ) -> dict[str, list[tuple[str, str]]] | None:
    """Update saved searches in Google SecOps based on a local config file."""
    LOGGER.info(
        "Attempting to update saved searches in Google SecOps based on local"
        " config file %s",
        saved_searches_config_file,
    )
    local_saved_searches = SavedSearches.load_saved_search_config()

    if not local_saved_searches.saved_searches:
      return None

    LOGGER.info(
        "Attempting to retrieve latest version of all saved searches from"
        " Google SecOps"
    )
    remote_saved_searches = SavedSearches.get_remote_saved_searches(
        http_session=http_session
    )

    # Create a dictionary containing the remote saved searches using the saved
    # search's Google Cloud resource name as the key for each item.
    remote_saved_searches_dict = {}

    if remote_saved_searches.saved_searches:
      for remote_saved_search in remote_saved_searches.saved_searches:
        remote_saved_searches_dict[remote_saved_search.resource_name] = (
            remote_saved_search
        )

    # Keep track of saved search updates to log a final summary of changes
    # made.
    update_summary = {
        "created": [],
        "updated": [],
    }

    LOGGER.info("Checking if any saved search updates are required")
    for local_saved_search in local_saved_searches.saved_searches:
      saved_search_name = local_saved_search.name
      saved_search_resource_name = local_saved_search.resource_name
      update_remote_saved_search = False

      # If the local saved search doesn't have a Google Cloud resource name,
      # create a new saved search in Google SecOps
      if not saved_search_resource_name:
        new_saved_search = create_saved_search(
            http_session=http_session,
            name=local_saved_search.name,
            query=local_saved_search.query,
            description=local_saved_search.description,
            sharing_mode=local_saved_search.sharing_mode,
            placeholder_names=local_saved_search.placeholder_names,
            placeholder_descriptions=local_saved_search.placeholder_descriptions,
        )
        saved_search_resource_name = new_saved_search["name"]
        local_saved_search.resource_name = new_saved_search["name"]
        remote_saved_search = SavedSearches.parse_saved_search(new_saved_search)
        LOGGER.info("Created new saved search %s", remote_saved_search.name)
        update_summary["created"].append(
            (remote_saved_search.name, saved_search_resource_name)
        )

      else:
        # Saved search exists in Google SecOps with same Google Cloud resource
        # name as local saved search.
        remote_saved_search = remote_saved_searches_dict[
            saved_search_resource_name
        ]

        # Check if the saved search's name should be updated
        LOGGER.debug(
            "Saved search %s - Comparing the name of the local and remote"
            " saved search",
            saved_search_name,
        )
        if local_saved_search.name != remote_saved_search.name:
          LOGGER.info(
              "Saved search %s - Name for local and remote saved search is"
              " different. Remote saved search will be updated",
              saved_search_name,
          )
          update_remote_saved_search = True

        # Check if the saved search's description should be updated
        LOGGER.debug(
            "Saved search %s - Comparing the description of the local and"
            " remote saved search",
            saved_search_name,
        )
        if local_saved_search.description != remote_saved_search.description:
          LOGGER.info(
              "Saved search %s - Description for local and remote saved search"
              " is different. Remote saved search will be updated",
              saved_search_name,
          )
          update_remote_saved_search = True

        # Check if the saved search's query should be updated
        LOGGER.debug(
            "Saved search %s - Comparing the query for the local and remote"
            " saved search",
            saved_search_name,
        )
        if local_saved_search.query != remote_saved_search.query:
          LOGGER.info(
              "Saved search %s - Query is different in local and remote saved"
              " search. Remote saved search will be updated",
              saved_search_name,
          )
          update_remote_saved_search = True

        if local_saved_search.sharing_mode != remote_saved_search.sharing_mode:
          LOGGER.info(
              "Saved search %s - Sharing mode is different in local and remote"
              " saved search. Remote saved search will be updated",
              saved_search_name,
          )
          update_remote_saved_search = True

        if (
            local_saved_search.placeholder_names
            != remote_saved_search.placeholder_names
        ):
          LOGGER.info(
              "Saved search %s - Placeholder names are different in local and "
              "remote saved search. Remote saved search will be updated",
              saved_search_name,
          )
          update_remote_saved_search = True

        if (
            local_saved_search.placeholder_descriptions
            != remote_saved_search.placeholder_descriptions
        ):
          LOGGER.info(
              "Saved search %s - Placeholder descriptions are different in"
              " local and remote saved search. Remote saved search will be"
              " updated",
              saved_search_name,
          )
          update_remote_saved_search = True

        # Check if the saved search's query type should be updated
        LOGGER.debug(
            "Saved search %s - Comparing the query type of the local and"
            " remote saved search",
            saved_search_name,
        )
        if local_saved_search.query_type != remote_saved_search.query_type:
          LOGGER.info(
              "Saved search %s - Query type for local and remote saved search"
              " is different. Remote saved search will be updated",
              saved_search_name,
          )
          update_remote_saved_search = True

        if update_remote_saved_search:
          LOGGER.info(
              "Saved search %s - Updating remote saved search",
              saved_search_name,
          )
          # Note on November 7, 2025. There is a bug with the API method used
          # to update (PATCH) saved searches. A bug has been filed for this.
          # Providing an update_mask and a value for "description" (as an
          # example) will update the description for the saved search, but
          # delete the values from the other fields. This breaks the saved
          # search in Google SecOps (e.g. the display name (Title) for the saved
          # search is deleted).
          update_saved_search(
              http_session=http_session,
              resource_name=local_saved_search.resource_name,
              updates={
                  "displayName": local_saved_search.name,
                  "description": local_saved_search.description,
                  "query": local_saved_search.query,
                  "placeholder_names": local_saved_search.placeholder_names,
                  "placeholder_descriptions": (
                      local_saved_search.placeholder_descriptions
                  ),
                  "metadata": {"sharing_mode": local_saved_search.sharing_mode},
                  "query_type": local_saved_search.query_type,
              },
          )

          update_summary["updated"].append(
              (saved_search_name, saved_search_resource_name)
          )

    return update_summary
