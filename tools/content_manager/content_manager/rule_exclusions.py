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
"""Manage rule exclusions in Google SecOps."""

# pylint: disable="g-bool-id-comparison"

import hashlib
import json
import logging
import pathlib
import re
from typing import Any, Literal, Mapping, Sequence

from content_manager.common.custom_exceptions import RuleExclusionConfigError
from google.auth.transport import requests
from google_secops_api.findings_refinements.create_findings_refinement import create_findings_refinement
from google_secops_api.findings_refinements.get_findings_refinement_deployment import get_findings_refinement_deployment
from google_secops_api.findings_refinements.list_findings_refinement_deployments import list_findings_refinement_deployments
from google_secops_api.findings_refinements.list_findings_refinements import list_findings_refinements
from google_secops_api.findings_refinements.update_findings_refinement import update_findings_refinement
from google_secops_api.findings_refinements.update_findings_refinement_deployment import update_refinement_findings_deployment
import pydantic
import ruamel.yaml
import yaml


LOGGER = logging.getLogger()

ROOT_DIR = pathlib.Path(__file__).parent.parent
RULE_EXCLUSIONS_CONFIG_FILE = ROOT_DIR / "rule_exclusions_config.yaml"
RULE_EXCLUSION_TYPES = Literal["DETECTION_EXCLUSION"]  # pylint: disable="invalid-name"
EXCLUSION_APPLICATIONS = Literal["curated_rule_sets", "curated_rules"]  # pylint: disable="invalid-name"

# Use ruamel.yaml to raise an exception if a YAML file contains duplicate keys
ruamel_yaml = ruamel.yaml.YAML(typ="safe")


class ExclusionApplication(pydantic.BaseModel):
  """Class for a detection exclusion application.

  Reference:
  https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/DetectionExclusionApplication
  """

  curated_rule_sets: Sequence[str] | None
  curated_rules: Sequence[str] | None


class RuleExclusion(pydantic.BaseModel):
  """Class for a rule exclusion."""

  name: str
  resource_name: str | None
  type: RULE_EXCLUSION_TYPES
  create_time: str | None
  update_time: str | None
  query: str
  enabled: bool
  archived: bool | None
  deployment_state_update_time: str | None
  exclusion_applications: Mapping[EXCLUSION_APPLICATIONS, Sequence[str] | None]


class RuleExclusionConfigEntry(pydantic.BaseModel):
  """Class for a rule exclusion config file entry."""

  name: str
  resource_name: str | None
  type: RULE_EXCLUSION_TYPES
  create_time: str | None
  update_time: str | None
  query: str
  enabled: bool
  archived: bool | None
  deployment_state_update_time: str | None
  exclusion_applications: Mapping[EXCLUSION_APPLICATIONS, Sequence[str] | None]


class RuleExclusions:
  """Class used to manage rule exclusions in Google SecOps."""

  def __init__(self, rule_exclusions: list[RuleExclusion]):
    self.rule_exclusions: list[RuleExclusion] = rule_exclusions

  @classmethod
  def parse_rule_exclusion(
      cls, rule_exclusion: Mapping[str, Any]
  ) -> RuleExclusion:
    """Parse a rule exclusion into a RuleExclusion object."""
    # Set enabled and archived options based on the rule exclusion's current
    # state in Google SecOps.
    if rule_exclusion["deployment_state"].get("enabled") is not True:
      rule_exclusion["deployment_state"]["enabled"] = False

    if rule_exclusion["deployment_state"].get("archived") is not True:
      rule_exclusion["deployment_state"]["archived"] = False

    if rule_exclusion["deployment_state"].get("detectionExclusionApplication"):
      exclusion_applications = {
          "curated_rule_sets": (
              rule_exclusion["deployment_state"][
                  "detectionExclusionApplication"
              ].get("curatedRuleSets")
          ),
          "curated_rules": (
              rule_exclusion["deployment_state"][
                  "detectionExclusionApplication"
              ].get("curatedRules")
          ),
      }
    else:
      exclusion_applications = {
          "curated_rule_sets": None,
          "curated_rules": None,
      }

    try:
      parsed_rule_exclusion = RuleExclusion(
          name=rule_exclusion["displayName"],
          resource_name=rule_exclusion.get("name"),
          type=rule_exclusion["type"],
          create_time=rule_exclusion["createTime"],
          update_time=rule_exclusion["updateTime"],
          query=rule_exclusion["query"],
          enabled=rule_exclusion["deployment_state"]["enabled"],
          archived=rule_exclusion["deployment_state"]["archived"],
          deployment_state_update_time=rule_exclusion["deployment_state"][
              "updateTime"
          ],
          exclusion_applications=exclusion_applications,
      )
    except pydantic.ValidationError as e:
      LOGGER.error(
          """ValidationError occurred for rule exclusion %s"
          %s""",
          rule_exclusion,
          json.dumps(e.errors(), indent=4),
      )
      raise

    return parsed_rule_exclusion

  @classmethod
  def parse_rule_exclusions(
      cls, rule_exclusions: Sequence[Mapping[str, Any]]
  ) -> list[RuleExclusion]:
    """Parse a list of rule exclusions into a list of RuleExclusion objects."""
    parsed_rule_exclusions = []

    for rule_exclusion in rule_exclusions:
      parsed_rule_exclusions.append(
          RuleExclusions.parse_rule_exclusion(rule_exclusion)
      )

    return parsed_rule_exclusions

  @classmethod
  def load_rule_exclusion_config(
      cls,
      rule_exclusion_config_file: pathlib.Path = RULE_EXCLUSIONS_CONFIG_FILE,
  ) -> "RuleExclusions":
    """Load rule exclusion config from file."""

    LOGGER.info(
        "Loading rule exclusion config file from %s",
        rule_exclusion_config_file,
    )
    with open(rule_exclusion_config_file, "r", encoding="utf-8") as f:
      rule_exclusion_config = ruamel_yaml.load(f)

    if not rule_exclusion_config:
      LOGGER.info("Rule exclusion config file is empty.")
      return RuleExclusions(rule_exclusions=[])

    RuleExclusions.check_rule_exclusion_config(rule_exclusion_config)

    rule_exclusions_parsed = []

    for (
        rule_exclusion_name,
        rule_exclusion_config_entry,
    ) in rule_exclusion_config.items():
      try:
        rule_exclusions_parsed.append(
            RuleExclusion(
                name=rule_exclusion_name,
                resource_name=rule_exclusion_config_entry.get("resource_name"),
                type=rule_exclusion_config_entry["type"],
                create_time=rule_exclusion_config_entry.get("create_time"),
                update_time=rule_exclusion_config_entry.get("update_time"),
                query=rule_exclusion_config_entry["query"],
                enabled=rule_exclusion_config_entry["enabled"],
                archived=rule_exclusion_config_entry.get("archived"),
                deployment_state_update_time=rule_exclusion_config_entry.get(
                    "deployment_state_update_time"
                ),
                exclusion_applications=rule_exclusion_config_entry[
                    "exclusion_applications"
                ],
            )
        )
      except pydantic.ValidationError as e:
        LOGGER.error(
            """ValidationError occurred for rule exclusion config entry %s"
                    %s""",
            rule_exclusion_name,
            json.dumps(e.errors(), indent=4),
        )
        raise

    LOGGER.info(
        "Loaded %s rule exclusion config entries from file %s",
        len(rule_exclusions_parsed),
        rule_exclusion_config_file,
    )

    return RuleExclusions(rule_exclusions=rule_exclusions_parsed)

  @classmethod
  def extract_rule_exclusion_id_from_resource_name(
      cls, rule_exclusion_resource_name: str
  ) -> str:
    """Extract the rule exclusion ID from a Google Cloud resource name.

    Args:
      rule_exclusion_resource_name: The Google Cloud resource name for the
        rule exclusion. example -
        projects/1234567890123/locations/us/instances/abcdef12-1234-1234-abc9-abcde1234566/findingsRefinements/fr_1172e8f3-7b49-45ad-ad4f-ef19bb794106

    Returns:
      The unique ID for the rule exclusion. Example -
      ru_e05bebd5-1234-410a-1234-4d7d0ee8b55f
    """
    # Extract the rule exclusion ID from the resource_name value
    exclusion_id_match = re.search(
        pattern=r"\/(fr_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})",
        string=rule_exclusion_resource_name,
        flags=re.IGNORECASE,
    )

    exclusion_id = exclusion_id_match.group(1)

    return exclusion_id

  @classmethod
  def check_rule_exclusion_config(cls, config: Mapping[str, Any]):
    """Check rule exclusion config file for invalid keys."""
    required_keys = ["enabled", "query", "type"]
    allowed_keys = [
        "archived",
        "create_time",
        "deployment_state_update_time",
        "enabled",
        "exclusion_applications",
        "query",
        "resource_name",
        "type",
        "update_time",
    ]
    invalid_keys = []

    for rule_exclusion_name, rule_exclusion_config in config.items():
      for key in list(rule_exclusion_config.keys()):
        if key not in allowed_keys:
          invalid_keys.append(key)

      if invalid_keys:
        raise RuleExclusionConfigError(
            f"Invalid keys ({invalid_keys}) found for rule exclusion -"
            f" {rule_exclusion_name}"
        )

      for key in required_keys:
        if key not in list(rule_exclusion_config.keys()):
          raise RuleExclusionConfigError(
              f"Required key ({key}) not found for rule exclusion -"
              f" {rule_exclusion_name}"
          )

      if (
          rule_exclusion_config.get("enabled") is True
          and rule_exclusion_config.get("archived") is True
      ):
        raise RuleExclusionConfigError(
            f"Rule exclusion config error for {rule_exclusion_name}. Rule"
            " exclusion cannot be both enabled and archived."
        )

  def dump_rule_exclusion_config(self):
    """Dump the configuration and metadata for a collection of rule exclusions."""
    rule_exclusion_config = {}

    for rule_exclusion in self.rule_exclusions:
      try:
        rule_exclusion_config_entry = RuleExclusionConfigEntry(
            name=rule_exclusion.name,
            resource_name=rule_exclusion.resource_name,
            type=rule_exclusion.type,
            create_time=rule_exclusion.create_time,
            update_time=rule_exclusion.update_time,
            query=rule_exclusion.query,
            enabled=rule_exclusion.enabled,
            archived=rule_exclusion.archived,
            deployment_state_update_time=rule_exclusion.deployment_state_update_time,
            exclusion_applications=rule_exclusion.exclusion_applications,
        )
      except pydantic.ValidationError as e:
        LOGGER.error(
            """ValidationError occurred for rule exclusion config entry %s"
                    %s""",
            rule_exclusion,
            json.dumps(e.errors(), indent=4),
        )
        raise

      rule_exclusion_config[rule_exclusion.name] = (
          rule_exclusion_config_entry.model_dump(exclude={"name"})
      )

    LOGGER.info(
        "Writing rule exclusion config to %s", RULE_EXCLUSIONS_CONFIG_FILE
    )
    with open(
        RULE_EXCLUSIONS_CONFIG_FILE, "w", encoding="utf-8"
    ) as rule_exclusion_config_file:
      yaml.dump(
          rule_exclusion_config,
          rule_exclusion_config_file,
          sort_keys=True,
      )

  @classmethod
  def get_remote_rule_exclusions(
      cls, http_session: requests.AuthorizedSession
  ) -> "RuleExclusions":
    """Retrieve the latest version of all rule exclusions from Google SecOps."""
    raw_rule_exclusions = []
    next_page_token = None

    LOGGER.info("Attempting to retrieve all rule exclusions from Google SecOps")
    while True:
      (
          retrieved_rule_exclusions,
          next_page_token,
      ) = list_findings_refinements(
          http_session=http_session,
          page_size=None,
          page_token=next_page_token,
      )

      if retrieved_rule_exclusions is not None:
        LOGGER.info(
            "Retrieved %s rule exclusions",
            len(retrieved_rule_exclusions),
        )
        raw_rule_exclusions.extend(retrieved_rule_exclusions)

      if next_page_token:
        LOGGER.info(
            "Attempting to retrieve rule exclusions with page token %s",
            next_page_token,
        )
      else:
        # Break if there are no more pages of rule exclusions to retrieve
        break

    raw_rule_exclusions_count = len(raw_rule_exclusions)

    LOGGER.info(
        "Retrieved a total of %s rule exclusions", raw_rule_exclusions_count
    )

    if not raw_rule_exclusions:
      return RuleExclusions(rule_exclusions=[])

    rule_exclusion_deployments = []
    next_page_token = None

    LOGGER.info(
        "Attempting to retrieve deployment state for all rule exclusions"
    )
    while True:
      (
          retrieved_exclusion_deployments,
          next_page_token,
      ) = list_findings_refinement_deployments(
          http_session=http_session,
          page_size=None,
          page_token=next_page_token,
      )

      if retrieved_exclusion_deployments is not None:
        LOGGER.info(
            "Retrieved deployment state for %s rule exclusions",
            len(retrieved_exclusion_deployments),
        )
        rule_exclusion_deployments.extend(retrieved_exclusion_deployments)

      if next_page_token:
        LOGGER.info(
            "Attempting to retrieve rule exclusion deployment states with page"
            " token %s",
            next_page_token,
        )
      else:
        # Break if there are no more pages of rule exclusion deployments to
        # retrieve
        break

    LOGGER.info(
        "Retrieved deployment state for a total of %s rule exclusions",
        len(rule_exclusion_deployments),
    )

    # Store the rule exclusion deployment state objects in a dict using the
    # Google Cloud resource name as the key
    exclusion_deployments_dict = {}
    for exclusion_deployment in rule_exclusion_deployments:
      rule_exclusion_id = (
          RuleExclusions.extract_rule_exclusion_id_from_resource_name(
              rule_exclusion_resource_name=exclusion_deployment["name"]
          )
      )
      exclusion_deployments_dict[rule_exclusion_id] = exclusion_deployment

    # Add the deployment state to each raw rule exclusion for parsing
    for raw_rule_exclusion in raw_rule_exclusions:
      rule_exclusion_id = (
          RuleExclusions.extract_rule_exclusion_id_from_resource_name(
              rule_exclusion_resource_name=raw_rule_exclusion["name"]
          )
      )
      raw_rule_exclusion["deployment_state"] = exclusion_deployments_dict[
          rule_exclusion_id
      ]

    parsed_rule_exclusions = RuleExclusions.parse_rule_exclusions(
        rule_exclusions=raw_rule_exclusions
    )

    return RuleExclusions(rule_exclusions=parsed_rule_exclusions)

  @classmethod
  def update_remote_rule_exclusions(
      cls,
      http_session: requests.AuthorizedSession,
      rule_exclusions_config_file: pathlib.Path = RULE_EXCLUSIONS_CONFIG_FILE,
  ) -> Mapping[str, Sequence[tuple[str, str]]] | None:
    """Update rule exclusions in Google SecOps based on a local config file."""
    LOGGER.info(
        "Attempting to update rule exclusions in Google SecOps based on local"
        " config file %s",
        rule_exclusions_config_file,
    )
    local_rule_exclusions = RuleExclusions.load_rule_exclusion_config()

    if not local_rule_exclusions.rule_exclusions:
      return None

    LOGGER.info(
        "Attempting to retrieve latest version of all rule exclusions from"
        " Google SecOps"
    )
    remote_rule_exclusions = RuleExclusions.get_remote_rule_exclusions(
        http_session=http_session
    )

    # Create a dictionary containing the remote rule exclusions using the rule
    # exclusion's Google Cloud resource name as the key for each item.
    remote_rule_exclusions_dict = {}

    if remote_rule_exclusions.rule_exclusions:
      for remote_rule_exclusion in remote_rule_exclusions.rule_exclusions:
        remote_rule_exclusions_dict[remote_rule_exclusion.resource_name] = (
            remote_rule_exclusion
        )

    # Keep track of rule exclusion updates to log a final summary of changes
    # made.
    update_summary = {
        "created": [],
        "updated": [],
        "enabled": [],
        "disabled": [],
        "archived": [],
        "unarchived": [],
        "detection_exclusion_applications_updated": [],
    }

    LOGGER.info("Checking if any rule exclusion updates are required")
    for local_rule_exclusion in local_rule_exclusions.rule_exclusions:
      rule_exclusion_name = local_rule_exclusion.name
      rule_exclusion_resource_name = local_rule_exclusion.resource_name
      update_remote_rule_exclusion = False

      # If the local rule exclusion doesn't have a Google Cloud resource name,
      # create a new rule exclusion in Google SecOps
      if not rule_exclusion_resource_name:
        new_rule_exclusion = create_findings_refinement(
            http_session=http_session,
            display_name=local_rule_exclusion.name,
            findings_refinement_type=local_rule_exclusion.type,
            query=local_rule_exclusion.query,
        )
        rule_exclusion_resource_name = new_rule_exclusion["name"]
        local_rule_exclusion.resource_name = new_rule_exclusion["name"]
        new_rule_exclusion["deployment_state"] = (
            get_findings_refinement_deployment(
                http_session=http_session,
                resource_name=rule_exclusion_resource_name,
            )
        )
        remote_rule_exclusion = RuleExclusions.parse_rule_exclusion(
            new_rule_exclusion
        )
        LOGGER.info("Created new rule exclusion %s", remote_rule_exclusion.name)
        update_summary["created"].append(
            (remote_rule_exclusion.name, rule_exclusion_resource_name)
        )

      else:
        # Rule exclusion exists in Google SecOps with same Google Cloud resource
        # name as local rule exclusion.
        remote_rule_exclusion = remote_rule_exclusions_dict[
            rule_exclusion_resource_name
        ]

        # Check if the rule exclusion's name should be updated
        LOGGER.debug(
            "Rule exclusion %s - Comparing the name of the local and remote"
            " rule exclusion",
            rule_exclusion_name,
        )
        if local_rule_exclusion.name != remote_rule_exclusion.name:
          LOGGER.info(
              "Rule exclusion %s - Name for local and remote rule exclusion is"
              " different. Remote rule exclusion will be updated",
              rule_exclusion_name,
          )
          update_remote_rule_exclusion = True

        # Check if the rule exclusion's type should be updated
        LOGGER.debug(
            "Rule exclusion %s - Comparing the type of the local and remote"
            " rule exclusion",
            rule_exclusion_name,
        )
        if local_rule_exclusion.type != remote_rule_exclusion.type:
          LOGGER.info(
              "Rule exclusion %s - Type for local and remote rule exclusion is"
              " different. Remote rule exclusion will be updated",
              rule_exclusion_name,
          )
          update_remote_rule_exclusion = True

        # Check if the rule exclusion's query should be updated
        LOGGER.debug(
            "Rule exclusion %s - Comparing the query for the local and remote"
            " rule exclusion",
            rule_exclusion_name,
        )
        if local_rule_exclusion.query != remote_rule_exclusion.query:
          LOGGER.info(
              "Rule exclusion %s - Query is different in local and remote rule"
              " exclusion. Remote rule exclusion will be updated",
              rule_exclusion_name,
          )
          update_remote_rule_exclusion = True

        if update_remote_rule_exclusion:
          LOGGER.info(
              "Rule exclusion %s - Updating remote rule exclusion",
              rule_exclusion_name,
          )
          update_findings_refinement(
              http_session=http_session,
              resource_name=local_rule_exclusion.resource_name,
              update_mask=["display_name", "type", "query"],
              updates={
                  "display_name": local_rule_exclusion.name,
                  "type": local_rule_exclusion.type,
                  "query": local_rule_exclusion.query,
              },
          )
          update_summary["updated"].append(
              (rule_exclusion_name, rule_exclusion_resource_name)
          )

      rule_exclusion_state_updates = (
          RuleExclusions.update_remote_rule_exclusion_state(
              http_session=http_session,
              local_rule_exclusion=local_rule_exclusion,
              remote_rule_exclusion=remote_rule_exclusion,
          )
      )

      # Update change summary dictionary with any rule exclusion changes that
      # were made.
      if rule_exclusion_state_updates.get("enabled") is True:
        update_summary["enabled"].append(
            (rule_exclusion_name, rule_exclusion_resource_name)
        )
      if rule_exclusion_state_updates.get("disabled") is True:
        update_summary["disabled"].append(
            (rule_exclusion_name, rule_exclusion_resource_name)
        )
      if rule_exclusion_state_updates.get("archived") is True:
        update_summary["archived"].append(
            (rule_exclusion_name, rule_exclusion_resource_name)
        )
      if rule_exclusion_state_updates.get("unarchived") is True:
        update_summary["unarchived"].append(
            (rule_exclusion_name, rule_exclusion_resource_name)
        )
      if (
          rule_exclusion_state_updates.get(
              "detection_exclusion_applications_updated"
          )
          is True
      ):
        update_summary["detection_exclusion_applications_updated"].append(
            (rule_exclusion_name, rule_exclusion_resource_name)
        )

    return update_summary

  @classmethod
  def update_remote_rule_exclusion_state(
      cls,
      http_session: requests.AuthorizedSession,
      local_rule_exclusion: RuleExclusion,
      remote_rule_exclusion: RuleExclusion,
  ) -> Mapping[str, Any]:
    """Update the deployment state for a rule exclusion based on the configuration of a local rule exclusion and a remote rule exclusion."""
    rule_exclusion_updates = {}
    rule_exclusion_name = local_rule_exclusion.name
    log_msg_prefix = f"Rule exclusion {rule_exclusion_name}"

    LOGGER.debug(
        "%s - Checking if the rule exclusion should be unarchived",
        log_msg_prefix,
    )
    # Unarchive the rule exclusion if required.
    if (
        local_rule_exclusion.archived is False
        and remote_rule_exclusion.archived is True
    ):
      LOGGER.info("%s - Unarchiving rule exclusion", log_msg_prefix)
      update_refinement_findings_deployment(
          http_session=http_session,
          resource_name=local_rule_exclusion.resource_name,
          update_mask=["archived"],
          updates={"archived": False},
      )
      rule_exclusion_updates["unarchived"] = True

    LOGGER.debug(
        "%s - Checking if the rule exclusion should be enabled/disabled.",
        log_msg_prefix,
    )
    # Enable the rule exclusion if required.
    if (
        local_rule_exclusion.enabled is True
        and remote_rule_exclusion.enabled is False
    ):
      LOGGER.info("%s - Enabling rule exclusion", log_msg_prefix)
      update_refinement_findings_deployment(
          http_session=http_session,
          resource_name=local_rule_exclusion.resource_name,
          update_mask=["enabled"],
          updates={"enabled": True},
      )
      rule_exclusion_updates["enabled"] = True

    # Disable the rule exclusion if required.
    elif (
        local_rule_exclusion.enabled is False
        and remote_rule_exclusion.enabled is True
    ):
      LOGGER.info("%s - Disabling rule exclusion", log_msg_prefix)
      update_refinement_findings_deployment(
          http_session=http_session,
          resource_name=local_rule_exclusion.resource_name,
          update_mask=["enabled"],
          updates={"enabled": False},
      )
      rule_exclusion_updates["disabled"] = True

    # Compute MD5 hash for the local and remote rule exclusion's detection
    # exclusion applications.
    local_rule_exclusion_applications_hash = hashlib.md5(
        json.dumps(
            local_rule_exclusion.exclusion_applications, sort_keys=True
        ).encode(encoding="utf-8")
    ).hexdigest()
    remote_rule_exclusion_applications_hash = hashlib.md5(
        json.dumps(
            remote_rule_exclusion.exclusion_applications, sort_keys=True
        ).encode(encoding="utf-8")
    ).hexdigest()

    # Update the rule exclusion's detection exclusion applications if required
    LOGGER.debug(
        "%s - Checking if the detection exclusion applications should be"
        " updated",
        log_msg_prefix,
    )
    if (
        local_rule_exclusion_applications_hash
        != remote_rule_exclusion_applications_hash
    ):
      LOGGER.debug(
          "%s - Local and remote detection exclusion applications are"
          " different.\nLocal:\n%s.\nRemote:\n%s",
          log_msg_prefix,
          json.dumps(
              local_rule_exclusion.exclusion_applications,
              sort_keys=True,
              indent=4,
          ),
          json.dumps(
              remote_rule_exclusion.exclusion_applications,
              sort_keys=True,
              indent=4,
          ),
      )
      LOGGER.info(
          "%s - Updating detection exclusion applications", log_msg_prefix
      )
      update_refinement_findings_deployment(
          http_session=http_session,
          resource_name=local_rule_exclusion.resource_name,
          update_mask=["detection_exclusion_application"],
          updates={
              "detection_exclusion_application": (
                  local_rule_exclusion.exclusion_applications
              )
          },
      )
      rule_exclusion_updates["detection_exclusion_applications_updated"] = True

    LOGGER.debug(
        "%s - Checking if the rule exclusion should be archived",
        log_msg_prefix,
    )
    # Archive the rule exclusion if required.
    if (
        local_rule_exclusion.archived is True
        and remote_rule_exclusion.archived is False
    ):
      LOGGER.info("%s - Archiving rule exclusion", log_msg_prefix)
      update_refinement_findings_deployment(
          http_session=http_session,
          resource_name=local_rule_exclusion.resource_name,
          update_mask=["archived"],
          updates={"archived": True},
      )
      rule_exclusion_updates["archived"] = True

    return rule_exclusion_updates
