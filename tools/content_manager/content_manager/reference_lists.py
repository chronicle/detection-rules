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
"""Manage reference lists in Google SecOps."""

# pylint: disable="g-bool-id-comparison"

import hashlib
import json
import logging
import pathlib
from typing import Any, List, Literal, Mapping, Sequence, Tuple

from content_manager.common.custom_exceptions import ReferenceListConfigError
from google.auth.transport import requests
from google_secops_api.reference_lists.create_reference_list import create_reference_list
from google_secops_api.reference_lists.list_reference_lists import list_reference_lists
from google_secops_api.reference_lists.update_reference_list import update_reference_list
import pydantic
import ruamel.yaml
import yaml


LOGGER = logging.getLogger()

ROOT_DIR = pathlib.Path(__file__).parent.parent
REF_LISTS_DIR = ROOT_DIR / "reference_lists"
REF_LIST_CONFIG_FILE = ROOT_DIR / "reference_list_config.yaml"
REF_LIST_SYNTAX_TYPES = Literal[  # pylint: disable="invalid-name"
    "REFERENCE_LIST_SYNTAX_TYPE_UNSPECIFIED",
    "REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING",
    "REFERENCE_LIST_SYNTAX_TYPE_REGEX",
    "REFERENCE_LIST_SYNTAX_TYPE_CIDR",
]

# Use ruamel.yaml to raise an exception if a YAML file contains duplicate keys
# (i.e. duplicate reference list names)
ruamel_yaml = ruamel.yaml.YAML(typ="safe")


class ReferenceList(pydantic.BaseModel):
  """Class for a reference list."""

  name: str
  resource_name: str | None
  revision_create_time: str | None
  description: str
  syntax_type: REF_LIST_SYNTAX_TYPES
  entries: Sequence[str | None]
  rules: Sequence[str] | None
  rule_associations_count: int | None


class ReferenceListConfigEntry(pydantic.BaseModel):
  """Class for a reference list config file entry."""

  name: str
  resource_name: str | None
  revision_create_time: str | None
  description: str
  syntax_type: REF_LIST_SYNTAX_TYPES
  rules: Sequence[str] | None
  rule_associations_count: int | None


class ReferenceLists:
  """Class used to manage reference lists."""

  def __init__(self, ref_lists: List[ReferenceList]):
    self.ref_lists: List[ReferenceList] = ref_lists

  @classmethod
  def parse_ref_lists(
      cls, ref_lists: Sequence[Mapping[str, Any]]
  ) -> List[ReferenceList]:
    """Parse a list of reference lists into a list of ReferenceList objects."""
    parsed_ref_lists = []

    for ref_list in ref_lists:
      ref_list_entries = []
      for entry in ref_list["entries"]:
        # If entry is an empty dictionary {} then the reference list is empty
        if not entry:
          continue
        ref_list_entries.append(entry.get("value"))

      try:
        parsed_ref_list = ReferenceList(
            name=ref_list["displayName"],
            resource_name=ref_list.get("name"),
            revision_create_time=ref_list["revisionCreateTime"],
            description=ref_list["description"],
            syntax_type=ref_list["syntaxType"],
            entries=ref_list_entries,
            rules=ref_list.get("rules"),
            rule_associations_count=ref_list.get("ruleAssociationsCount"),
        )
      except pydantic.ValidationError as e:
        LOGGER.error(
            """ValidationError occurred for reference list %s"
                    %s""",
            ref_list,
            json.dumps(e.errors(), indent=4),
        )
        raise

      parsed_ref_lists.append(parsed_ref_list)

    return parsed_ref_lists

  @classmethod
  def load_ref_lists(
      cls,
      ref_lists_dir: pathlib.Path = REF_LISTS_DIR,
      ref_list_config_file: pathlib.Path = REF_LIST_CONFIG_FILE,
  ) -> "ReferenceLists":
    """Load reference list files and config from disk."""
    ref_list_config = ReferenceLists.load_ref_list_config(ref_list_config_file)

    if not ref_list_config:
      return ReferenceLists(ref_lists=[])

    ref_list_files = list(ref_lists_dir.glob("*.txt"))
    non_ref_list_files = [
        file_path
        for file_path in ref_lists_dir.glob("*")
        if not file_path.name.endswith(".txt")
    ]

    if non_ref_list_files:
      LOGGER.warning(
          "%s files found in reference_lists directory without .txt extension."
          " These files will not be processed",
          len(non_ref_list_files),
      )

    ref_list_names = []

    # Raise an exception if a reference list config entry is found that doesn't
    # have a corresponding txt file in the reference lists dir
    for ref_list_file_path in ref_list_files:
      ref_list_names.append(ref_list_file_path.stem)
    for key in ref_list_config:
      if key not in ref_list_names:
        raise ReferenceListConfigError(
            f"Reference list file not found with name {key}.txt in"
            f" {ref_lists_dir}"
        )

    ref_lists = []
    # Raise an exception if the txt file for the reference list does not have a
    # corresponding entry in the reference list config file
    for ref_list_file_path in ref_list_files:
      ref_list_name = ref_list_file_path.stem
      if ref_list_config.get(ref_list_name) is None:
        raise ReferenceListConfigError(
            f"Reference list {ref_list_name} not found in reference list config"
            f" file {ref_list_config_file}"
        )

      # Read reference list file line by line into a list
      ref_list_content = ref_list_file_path.read_text().splitlines()

      ref_list = ReferenceList(
          name=ref_list_name,
          resource_name=ref_list_config[ref_list_name].get("resource_name"),
          revision_create_time=ref_list_config[ref_list_name].get(
              "revision_create_time"
          ),
          description=ref_list_config[ref_list_name].get("description"),
          syntax_type=ref_list_config[ref_list_name].get("syntax_type"),
          entries=ref_list_content,
          rules=ref_list_config[ref_list_name].get("rules"),
          rule_associations_count=ref_list_config[ref_list_name].get(
              "rule_associations_count"
          ),
      )

      ref_lists.append(ref_list)

    LOGGER.info(
        "Loaded %s reference lists from %s", len(ref_lists), ref_lists_dir
    )

    return ReferenceLists(ref_lists=ref_lists)

  @classmethod
  def load_ref_list_config(
      cls, ref_list_config_file: pathlib.Path = REF_LIST_CONFIG_FILE
  ) -> Mapping[str, Any]:
    """Load reference list config from file."""
    ref_list_config_parsed = {}

    LOGGER.info(
        "Loading reference list config file from %s", ref_list_config_file
    )
    with open(ref_list_config_file, "r", encoding="utf-8") as f:
      ref_list_config = ruamel_yaml.load(f)

    if not ref_list_config:
      LOGGER.info("Reference list config file is empty.")
      return

    ReferenceLists.check_ref_list_config(ref_list_config)

    for ref_list_name, ref_list_config_entry in ref_list_config.items():
      try:
        ref_list_config_entry_parsed = ReferenceListConfigEntry(
            name=ref_list_name,
            resource_name=ref_list_config_entry.get("resource_name"),
            revision_create_time=ref_list_config_entry.get(
                "revision_create_time"
            ),
            description=ref_list_config_entry.get("description"),
            syntax_type=ref_list_config_entry.get("syntax_type"),
            rules=ref_list_config_entry.get("rules"),
            rule_associations_count=ref_list_config_entry.get(
                "rule_associations_count"
            ),
        )
      except pydantic.ValidationError as e:
        LOGGER.error(
            """ValidationError occurred for reference list config entry %s"
                    %s""",
            ref_list_name,
            json.dumps(e.errors(), indent=4),
        )
        raise

      ref_list_config_parsed[ref_list_config_entry_parsed.name] = (
          ref_list_config_entry_parsed.model_dump(exclude={"name"})
      )

    return ref_list_config_parsed

  @classmethod
  def check_ref_list_config(cls, config: Mapping[str, Any]):
    """Check reference list config file for invalid keys."""
    required_keys = ["description", "syntax_type"]
    allowed_keys = [
        "resource_name",
        "revision_create_time",
        "description",
        "syntax_type",
        "rules",
        "rule_associations_count",
    ]
    invalid_keys = []

    for ref_list_name, ref_list_config in config.items():
      for key in list(ref_list_config.keys()):
        if key not in allowed_keys:
          invalid_keys.append(key)

      if invalid_keys:
        raise ReferenceListConfigError(
            f"Invalid keys ({invalid_keys}) found for reference list -"
            f" {ref_list_name}"
        )

      for key in required_keys:
        if key not in list(ref_list_config.keys()):
          raise ReferenceListConfigError(
              f"Required key ({key}) not found for reference list -"
              f" {ref_list_name}"
          )

  def dump_ref_lists(self, ref_lists_dir: pathlib.Path = REF_LISTS_DIR):
    """Dump a list of reference lists to local files."""
    # Write reference lists out to .txt files
    LOGGER.info(
        "Writing %s reference list files to %s",
        len(self.ref_lists),
        ref_lists_dir,
    )
    for ref_list in self.ref_lists:
      # Use the reference list display name (unique value in Google SecOps) for
      # the file name.
      ref_list_file_path = f"{ref_lists_dir}/{ref_list.name}.txt"

      # Dump the reference list to a file.
      with open(ref_list_file_path, "w", encoding="utf-8") as ref_list_file:
        for entry in ref_list.entries:
          ref_list_file.write(f"{entry}\n")

  def dump_ref_list_config(self):
    """Dump the configuration and metadata for a collection of reference lists."""
    ref_list_config = {}

    for ref_list in self.ref_lists:
      try:
        ref_list_config_entry = ReferenceListConfigEntry(
            name=ref_list.name,
            resource_name=ref_list.resource_name,
            revision_create_time=ref_list.revision_create_time,
            description=ref_list.description,
            syntax_type=ref_list.syntax_type,
            rules=ref_list.rules,
            rule_associations_count=ref_list.rule_associations_count,
        )
      except pydantic.ValidationError as e:
        LOGGER.error(
            """ValidationError occurred for reference list config entry %s"
                    %s""",
            ref_list,
            json.dumps(e.errors(), indent=4),
        )
        raise

      ref_list_config[ref_list.name] = ref_list_config_entry.model_dump(
          exclude={"name"}
      )

    ref_list_config_file_path = ROOT_DIR / "reference_list_config.yaml"

    LOGGER.info(
        "Writing reference list config to %s", ref_list_config_file_path
    )
    with open(
        ref_list_config_file_path, "w", encoding="utf-8"
    ) as ref_list_config_file:
      yaml.dump(ref_list_config, ref_list_config_file, sort_keys=True)

  @classmethod
  def get_remote_ref_lists(
      cls, http_session: requests.AuthorizedSession
  ) -> "ReferenceLists":
    """Retrieve the latest version of all reference lists from Google SecOps."""
    raw_ref_lists = []
    next_page_token = None

    LOGGER.info("Attempting to retrieve all reference lists from Google SecOps")
    while True:
      retrieved_ref_lists, next_page_token = list_reference_lists(
          http_session=http_session,
          page_size=None,
          page_token=next_page_token,
          view="REFERENCE_LIST_VIEW_FULL",
      )

      if retrieved_ref_lists is not None:
        LOGGER.info("Retrieved %s reference lists", len(retrieved_ref_lists))
        raw_ref_lists.extend(retrieved_ref_lists)

      if next_page_token:
        LOGGER.info(
            "Attempting to retrieve reference lists with page token %s",
            next_page_token,
        )
      else:
        # Break if there are no more pages of reference lists to retrieve
        break

    raw_ref_lists_count = len(raw_ref_lists)

    LOGGER.info("Retrieved a total of %s reference lists", raw_ref_lists_count)

    parsed_ref_lists = ReferenceLists.parse_ref_lists(ref_lists=raw_ref_lists)

    return ReferenceLists(ref_lists=parsed_ref_lists)

  @classmethod
  def compare_ref_list_content(
      cls,
      ref_list_1_entries: Sequence[str | None],
      ref_list_2_entries: Sequence[str | None],
  ) -> bool:
    """Compare the content (entries) of two reference lists."""
    # Compute MD5 hash for the content of each reference list.
    ref_list_1_hash = hashlib.md5(
        str(ref_list_1_entries).encode(encoding="utf-8")
    ).hexdigest()
    ref_list_2_hash = hashlib.md5(
        str(ref_list_2_entries).encode(encoding="utf-8")
    ).hexdigest()

    if ref_list_1_hash == ref_list_2_hash:
      return False
    else:
      # Return True if the content of the two reference lists is different.
      return True

  @classmethod
  def update_remote_ref_lists(
      cls,
      http_session: requests.AuthorizedSession,
      ref_lists_dir: pathlib.Path = REF_LISTS_DIR,
      ref_lists_config_file: pathlib.Path = REF_LIST_CONFIG_FILE,
  ) -> Mapping[str, Sequence[Tuple[str, str]]] | None:
    """Update reference lists in Google SecOps based on local files."""
    LOGGER.info(
        "Attempting to update reference lists in Google SecOps based on local"
        " files"
    )

    LOGGER.info("Loading local reference lists from %s", ref_lists_dir)
    local_ref_lists = ReferenceLists.load_ref_lists(
        ref_lists_dir=ref_lists_dir,
        ref_list_config_file=ref_lists_config_file,
    )

    if not local_ref_lists.ref_lists:
      LOGGER.info("No local reference list files found")
      return

    LOGGER.info(
        "Attempting to retrieve latest version of all reference lists from"
        " Google SecOps"
    )
    remote_ref_lists = ReferenceLists.get_remote_ref_lists(
        http_session=http_session
    )

    # Create a dictionary containing the remote reference lists using the
    # reference list's name as the key for each item.
    remote_ref_lists_dict = {}

    if remote_ref_lists.ref_lists:
      for remote_ref_list in remote_ref_lists.ref_lists:
        remote_ref_lists_dict[remote_ref_list.name] = remote_ref_list

    # Keep track of reference list updates to log a final summary of changes
    # made.
    update_summary = {
        "created": [],
        "updated": [],
    }

    LOGGER.info("Checking if any reference list updates are required")
    for local_ref_list in local_ref_lists.ref_lists:
      ref_list_name = local_ref_list.name
      update_remote_ref_list = False

      if ref_list_name not in remote_ref_lists_dict.keys():
        # A new reference list will be created if a remote reference list isn't
        # found with the same name
        LOGGER.info(
            "Local reference list name %s not found in remote reference list."
            " Creating a new reference list",
            ref_list_name,
        )
        create_reference_list(
            http_session=http_session,
            name=ref_list_name,
            description=local_ref_list.description,
            entries=local_ref_list.entries,
            syntax_type=local_ref_list.syntax_type,
        )
        update_summary["created"].append(ref_list_name)

      if ref_list_name in remote_ref_lists_dict.keys():
        # Reference list exists in Google SecOps with same name as local
        # reference list.
        remote_ref_list = remote_ref_lists_dict[ref_list_name]

        # Check if the reference list's description should be updated
        LOGGER.debug(
            "Reference list %s - Comparing the description of the local and"
            " remote reference list",
            ref_list_name,
        )
        if local_ref_list.description != remote_ref_list.description:
          LOGGER.info(
              "Reference list %s - Description for local and remote reference"
              " list is different. Remote reference list will be updated",
              ref_list_name,
          )
          update_remote_ref_list = True

        # Check if the reference list's syntax type should be updated
        LOGGER.debug(
            "Reference list %s - Comparing the syntax type of the local and"
            " remote reference list",
            ref_list_name,
        )
        if local_ref_list.syntax_type != remote_ref_list.syntax_type:
          LOGGER.info(
              "Reference list %s - Syntax type for local and remote reference"
              " list is different. Remote reference list will be updated",
              ref_list_name,
          )
          update_remote_ref_list = True

        # Check if the reference list's content (entries) should be updated
        LOGGER.debug(
            "Reference list %s - Comparing the content of the local and remote"
            " reference list",
            ref_list_name,
        )
        if (
            ReferenceLists.compare_ref_list_content(
                ref_list_1_entries=local_ref_list.entries,
                ref_list_2_entries=remote_ref_list.entries,
            )
            is True
        ):
          LOGGER.info(
              "Reference list %s - Content is different in local and remote"
              " reference list. Remote reference list will be updated",
              ref_list_name,
          )
          update_remote_ref_list = True

        if update_remote_ref_list:
          LOGGER.info(
              "Reference list %s - Updating remote reference list",
              ref_list_name,
          )
          update_reference_list(
              http_session=http_session,
              resource_name=local_ref_list.resource_name,
              updates={
                  "description": local_ref_list.description,
                  "syntax_type": local_ref_list.syntax_type,
                  "entries": local_ref_list.entries,
              },
          )
          update_summary["updated"].append(ref_list_name)

    return update_summary
