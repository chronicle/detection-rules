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
"""Content Manager Command Line Interface - Manage content in Google SecOps such as rules, reference lists, and exclusions."""

# pylint: disable="invalid-name","g-bool-id-comparison"

import datetime
import json
import logging
import os
import pathlib

import click
from content_manager.common import datetime_converter
from content_manager.common.custom_exceptions import RuleVerificationError
from content_manager.reference_lists import ReferenceLists
from content_manager.rule_exclusions import RuleExclusions
from content_manager.rules import Rules
import dotenv
import google.auth.transport.requests
from google_secops_api import auth
from google_secops_api.rules.stream_test_rule import test_rule
from google_secops_api.rules.verify_rule import verify_rule


LOGGER = logging.getLogger()

ROOT_DIR = pathlib.Path(__file__).parent.parent
RULES_DIR = ROOT_DIR / "rules"
REF_LISTS_DIR = ROOT_DIR / "reference_lists"

dotenv.load_dotenv()


def initialize_http_session() -> (
    google.auth.transport.requests.AuthorizedSession
):
  """Initialize an authorized HTTP session with the Google SecOps API."""
  return auth.initialize_http_session(
      scopes=json.loads(os.environ["AUTHORIZATION_SCOPES"]).get(
          "GOOGLE_SECOPS_API"
      )
  )


class RuleOperations:
  """Manage rules in Google SecOps."""

  @classmethod
  def get(cls):
    """Retrieves the latest version of all rules from Google SecOps and updates the local rule files."""
    http_session = initialize_http_session()

    remote_rules = Rules.get_remote_rules(http_session=http_session)

    if not remote_rules.rules:
      return

    # Delete existing local rule files before writing a fresh copy of all rules
    # pulled from Google SecOps
    for local_rule_file in list(RULES_DIR.glob("*.yaral")):
      local_rule_file.unlink()

    remote_rules.dump_rules()
    remote_rules.dump_rule_config()

  @classmethod
  def update(cls):
    """Update rules in Google SecOps based on local rule files."""
    http_session = initialize_http_session()

    rule_updates = Rules.update_remote_rules(http_session=http_session)

    # Log summary of rule updates that occurred.
    LOGGER.info("Logging summary of rule changes...")
    for update_type, rules in rule_updates.items():  # pylint: disable="redefined-outer-name"
      LOGGER.info("Rules %s: %s", update_type, len(rules))
      for rule in rules:
        LOGGER.info("%s %s (%s)", update_type, rule[1], rule[0])

    # Retrieve the latest version of all rules after any changes were made and
    # update the local rule files.
    RuleOperations.get()

  @classmethod
  def verify(cls, rule_file_path: pathlib.Path):
    """Verify that a rule is a valid YARA-L rule using Google SecOps' API."""
    http_session = initialize_http_session()

    with open(rule_file_path, "r", encoding="utf-8") as f:
      rule_text = f.read()

    response = verify_rule(http_session=http_session, rule_text=rule_text)

    if response.get("success") is True:
      LOGGER.info(
          "Rule verified successfully (%s). Response: %s",
          rule_file_path,
          response,
      )

    else:
      raise RuleVerificationError(
          f"Rule verification error ({rule_file_path}). Response:"
          f" {json.dumps(response, indent=4)}"
      )

  @classmethod
  def verify_all(cls):
    """Verify that all rules are valid YARA-L rules using Google SecOps' API."""
    http_session = initialize_http_session()

    # Maintain lists of successful and failed YARA-L verification responses.
    verify_rule_successes = []
    verify_rule_errors = []

    for rule_file in list(RULES_DIR.glob("*.yaral")):
      with open(rule_file, "r", encoding="utf-8") as f:
        rule_text = f.read()

      response = verify_rule(http_session=http_session, rule_text=rule_text)

      if response.get("success") is True:
        LOGGER.info(
            "Rule verification succeeded for rule (%s). Response: %s",
            rule_file,
            response,
        )
        verify_rule_successes.append(rule_file)

      else:
        verify_rule_errors.append({"rule": rule_file, "response": response})

    LOGGER.info(
        "Rule verification succeeded for %s rules", len(verify_rule_successes)
    )

    if verify_rule_errors:
      LOGGER.error(
          "Rule verification failed for %s rules", len(verify_rule_errors)
      )
      # Log each rule verification error before raising an exception
      for error in verify_rule_errors:
        LOGGER.error(
            "Rule verification failed for rule (%s). Response: %s",
            error["rule"],
            json.dumps(error["response"], indent=4),
        )
      raise RuleVerificationError(
          f"Rule verification failed for {len(verify_rule_errors)} rules"
      )

  @classmethod
  def stream_test(
      cls,
      rule_file_path: pathlib.Path,
      start_time: datetime.datetime | None = None,
      end_time: datetime.datetime | None = None,
      max_detections: int | None = None,
      scope: str | None = None,
  ):
    """Test a rule in Google SecOps without persisting results."""
    # Initialize an authorized HTTP session
    http_session = auth.initialize_http_session(
        scopes=json.loads(os.environ["AUTHORIZATION_SCOPES"]).get(
            "GOOGLE_SECOPS_API"
        ),
    )

    with open(rule_file_path, "r", encoding="utf-8") as f:
      rule_text = f.read()

    detections = test_rule(
        http_session=http_session,
        rule_text=rule_text,
        start_time=start_time,
        end_time=end_time,
        max_detections=max_detections,
        scope=scope,
    )

    LOGGER.info(
        "Retrieved %s detections for rule: %s",
        len(detections),
        rule_file_path,
    )

    # Remove or comment out the following lines to prevent detections from
    # being logged
    if detections:
      LOGGER.debug("Logging retrieved detections for rule: %s", rule_text)
      for detection in detections:
        LOGGER.debug(detection)

    # This code can be customized to process the detections that were retrieved
    # for the rule that was tested
    # For example, the code below can be used to write the detections to a json
    # file
    # if len(detections) > 0:
    #   current_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    #   detections_results_file_path = (
    #       ROOT_DIR
    #       / f"rule_test_results_{rule_file_path.stem}_{current_time}.json"
    #   )
    #   with open(detections_results_file_path, "w", encoding="utf-8") as f:
    #     json.dump(detections, f, indent=4)
    #   LOGGER.debug(
    #       "Detections for rule written to %s", detections_results_file_path
    #   )


class ReferenceListOperations:
  """Manage reference lists in Google SecOps."""

  @classmethod
  def get(cls):
    """Retrieves the latest version of all reference lists from Google SecOps and updates the local reference list files."""
    http_session = initialize_http_session()

    remote_ref_lists = ReferenceLists.get_remote_ref_lists(
        http_session=http_session
    )

    if not remote_ref_lists.ref_lists:
      return

    # Delete existing local reference list files before writing a fresh copy of
    # all reference lists pulled from Google SecOps
    for local_ref_list_file in list(REF_LISTS_DIR.glob("*.txt")):
      local_ref_list_file.unlink()

    remote_ref_lists.dump_ref_lists()
    remote_ref_lists.dump_ref_list_config()

  @classmethod
  def update(cls):
    """Update reference lists in Google SecOps based on local reference list files."""
    http_session = initialize_http_session()

    ref_list_updates = ReferenceLists.update_remote_ref_lists(
        http_session=http_session
    )

    # Log summary of reference list updates that occurred.
    LOGGER.info("Logging summary of reference list changes...")
    for update_type, ref_list_names in ref_list_updates.items():
      LOGGER.info("Reference lists %s: %s", update_type, len(ref_list_names))
      for ref_list_name in ref_list_names:
        LOGGER.info("%s Reference list %s", update_type, ref_list_name)

    # Retrieve the latest version of all reference lists after any changes were
    # made and update the local Reference List files.
    ReferenceListOperations.get()


class RuleExclusionOperations:
  """Manage rule exclusions in Google SecOps."""

  @classmethod
  def get(cls):
    """Retrieves the latest version of rule exclusions from Google SecOps and updates the local config file."""
    http_session = initialize_http_session()

    remote_rule_exclusions = RuleExclusions.get_remote_rule_exclusions(
        http_session=http_session
    )

    if not remote_rule_exclusions.rule_exclusions:
      LOGGER.info("No rule exclusions retrieved")
      return

    remote_rule_exclusions.dump_rule_exclusion_config()

  @classmethod
  def update(cls):
    """Update findings refinements in Google SecOps based on local config file."""
    http_session = initialize_http_session()

    rule_exclusion_updates = RuleExclusions.update_remote_rule_exclusions(
        http_session=http_session
    )

    # Log summary of rule exclusion updates that occurred.
    LOGGER.info("Logging summary of rule exclusion changes...")
    for update_type, rule_exclusion_names in rule_exclusion_updates.items():
      LOGGER.info(
          "Rule exclusions %s: %s", update_type, len(rule_exclusion_names)
      )
      for rule_exclusion_name in rule_exclusion_names:
        LOGGER.info("%s rule exclusion %s", update_type, rule_exclusion_name)

    # Retrieve the latest version of all rule exclusions after any changes
    # were made.
    RuleExclusionOperations.get()


@click.group()
def cli():
  """Content Manager - Manage content in Google SecOps such as rules, reference lists, and exclusions."""


@click.group()
def rules():
  """Manage rules."""


@rules.command(
    "get",
    short_help="""Retrieve the latest version of all rules from Google SecOps and update local files""",
)
def get_rules():
  """Retrieve the latest version of all rules from Google SecOps and update local files."""
  LOGGER.info(
      "Attempting to pull latest version of all rules from Google SecOps and"
      " update local files"
  )
  RuleOperations.get()


@rules.command(
    "update",
    short_help=(
        "Update rules in Google SecOps based on local rule files and config."
    ),
)
def update_rules():
  """Update rules in Google SecOps based on local rule files and config."""
  LOGGER.info(
      "Attempting to update rules in Google SecOps based on local rule files"
  )
  RuleOperations.update()


@rules.command(
    "verify", short_help="Verify a single rule file is a valid YARA-L rule."
)
@click.option(
    "--rule-file-path",
    "-f",
    required=True,
    type=click.Path(
        exists=True, file_okay=True, dir_okay=False, path_type=pathlib.Path
    ),
    help="File path for the rule to verify.",
)
def verify(rule_file_path: pathlib.Path):
  """Verify a single rule file is a valid YARA-L rule."""
  LOGGER.info("Attempting to verify rule %s", rule_file_path)
  RuleOperations.verify(rule_file_path=rule_file_path)


@rules.command(
    "verify-all", short_help="Verify all local rules are valid YARA-L rules."
)
def verify_all():
  """Verify all local rules are valid YARA-L rules."""
  LOGGER.info("Attempting to verify all local rules")
  RuleOperations.verify_all()


@rules.command(
    "test",
    short_help="Test a rule in Google SecOps without persisting results.",
)
@click.option(
    "--rule-file-path",
    "-f",
    required=True,
    type=click.Path(
        exists=True, file_okay=True, dir_okay=False, path_type=pathlib.Path
    ),
    help="File path for the rule to test.",
)
@click.option(
    "--start-time",
    type=datetime_converter.iso8601_datetime_utc,
    required=False,
    help=(
        "The start time (in UTC format 'yyyy-mm-ddThh:mm:ssZ') of the time"
        " range of events to test the rule text over. If unspecified, will"
        " default to 12 hours before end_time."
    ),
)
@click.option(
    "--end-time",
    type=datetime_converter.iso8601_datetime_utc,
    required=False,
    help=(
        "The end time (in UTC format 'yyyy-mm-ddThh:mm:ssZ') of the time"
        " range of events to test the rule text over. If unspecified, will"
        " either default to 12 hours after start_time, or the last 12 hours"
        " of events if start_time is also unspecified."
    ),
)
@click.option(
    "--max-detections",
    "-md",
    type=int,
    required=False,
    default=1000,
    help=(
        "Maximum number of detections to stream back. Default is 1,000."
        " Maximum is 10,000."
    ),
)
@click.option(
    "--scope",
    type=str,
    required=False,
    help=(
        "The data access scope to use to run the rule. Required if data"
        " access control is enabled."
    ),
)
def test(
    rule_file_path: pathlib.Path,
    start_time: datetime.datetime | None,
    end_time: datetime.datetime | None,
    max_detections: int | None,
    scope: str | None,
):
  """Test a rule over a time range without persisting results."""
  LOGGER.info(
      "Attempting to test rule %s with event start time of %s and event end"
      " time of %s and scope %s",
      rule_file_path,
      start_time,
      end_time,
      scope,
  )
  RuleOperations.stream_test(
      rule_file_path=rule_file_path,
      start_time=start_time,
      end_time=end_time,
      max_detections=max_detections,
      scope=scope,
  )


@click.group()
def reference_lists():
  """Manage reference lists."""


@reference_lists.command(
    "get",
    short_help=(
        "Retrieve the latest reference lists from Google SecOps and update"
        " local files."
    ),
)
def get_reference_lists():
  """Retrieve the latest reference lists from Google SecOps and update local files."""
  LOGGER.info(
      "Attempting to pull latest version of all reference lists from Google"
      " SecOps and update local files"
  )
  ReferenceListOperations.get()


@reference_lists.command(
    "update",
    short_help=(
        "Update reference lists in Google SecOps based on local files and"
        " config."
    ),
)
def update_reference_lists():
  """Update reference lists in Google SecOps based on local files and config."""
  LOGGER.info(
      "Attempting to update reference lists in Google SecOps based on local"
      " reference list files"
  )
  ReferenceListOperations.update()


@click.group()
def rule_exclusions():
  """Manage rule exclusions."""


@rule_exclusions.command(
    "get",
    short_help=(
        "Retrieve the latest rule exclusions from Google SecOps and update"
        " local config."
    ),
)
def get_rule_exclusions():
  """Retrieve the latest rule exclusions from Google SecOps and update local config."""
  LOGGER.info(
      "Attempting to pull latest version of all rule exclusions from Google"
      " SecOps and update local config file"
  )
  RuleExclusionOperations.get()


@rule_exclusions.command(
    "update",
    short_help=(
        "Update rule exclusions in Google SecOps based on local config file"
    ),
)
def update():
  """Update rule exclusions in Google SecOps based on local config file."""
  LOGGER.info(
      "Attempting to update rule exclusions in Google SecOps based on "
      "local config file"
  )
  RuleExclusionOperations.update()


if __name__ == "__main__":
  LOGGER.info("Content Manager started")
  # Create content directories if they don't exist.
  if not RULES_DIR.is_dir():
    RULES_DIR.mkdir()
  if not REF_LISTS_DIR.is_dir():
    REF_LISTS_DIR.mkdir()

  cli.add_command(rules)
  cli.add_command(reference_lists)
  cli.add_command(rule_exclusions)

  cli()
