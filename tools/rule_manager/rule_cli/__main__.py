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
"""Rule Command Line Interface - Example code for managing rules via Chronicle's API."""

# pylint: disable="invalid-name","g-bool-id-comparison"

import argparse
import json
import logging
import os
import pathlib
import sys
import time

from chronicle_api import chronicle_auth
from chronicle_api.rules.verify_rule import verify_rule
import dotenv
import google.auth.transport.requests
from rule_cli.common import RuleVerificationError
from rule_cli.reference_lists import ReferenceLists
from rule_cli.rules import Rules

LOGGER = logging.getLogger()

ROOT_DIR = pathlib.Path(__file__).parent.parent
RULES_DIR = ROOT_DIR / "rules"
REF_LISTS_DIR = ROOT_DIR / "reference_lists"

dotenv.load_dotenv()


def initialize_http_session() -> (
    google.auth.transport.requests.AuthorizedSession
):
  """Initialize an authorized HTTP session with Chronicle."""
  return chronicle_auth.initialize_http_session(
      chronicle_api_credentials=json.loads(
          os.environ["CHRONICLE_API_CREDENTIALS"]
      ),
      scopes=json.loads(os.environ["AUTHORIZATION_SCOPES"]).get(
          "CHRONICLE_API"
      ),
  )


def pull_latest_rules():
  """Retrieves the latest version of all rules from Chronicle and updates the local rule files."""
  http_session = initialize_http_session()

  remote_rules = Rules.get_remote_rules(http_session=http_session)

  if len(remote_rules.rules) == 0:  # pylint: disable="g-explicit-length-test"
    return

  # Delete existing local rule files before writing a fresh copy of all rules
  # pulled from Chronicle.
  for local_rule_file in list(RULES_DIR.glob("*.yaral")):
    local_rule_file.unlink()

  remote_rules.dump_rules()

  remote_rules.dump_rule_config()


def update_remote_rules():
  """Update rules in Chronicle based on local rule files."""
  http_session = initialize_http_session()

  rule_updates = Rules.update_remote_rules(http_session=http_session)

  # Log summary of rule updates that occurred.
  LOGGER.info("Logging summary of rule changes...")
  for update_type, rules in rule_updates.items():
    LOGGER.info("Rules %s: %s", update_type, len(rules))
    for rule in rules:
      LOGGER.info("%s %s (%s)", update_type, rule[1], rule[0])

  # Retrieve the latest version of all rules after any changes were made and
  # update the local rule files.
  pull_latest_rules()


def pull_latest_reference_lists():
  """Retrieves the latest version of all reference lists from Chronicle and updates the local reference list files."""
  http_session = initialize_http_session()

  remote_ref_lists = ReferenceLists.get_remote_ref_lists(
      http_session=http_session
  )

  if len(remote_ref_lists.ref_lists) == 0:  # pylint: disable="g-explicit-length-test"
    return

  # Delete existing local reference list files before writing a fresh copy of
  # all reference lists pulled from Chronicle.
  for local_ref_list_file in list(REF_LISTS_DIR.glob("*.txt")):
    local_ref_list_file.unlink()

  remote_ref_lists.dump_ref_lists()

  remote_ref_lists.dump_ref_list_config()


def update_remote_ref_lists():
  """Update reference lists in Chronicle based on local reference list files."""
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
  pull_latest_reference_lists()


def verify_rule_text(rule_file: pathlib.Path):
  """Make an API call to verify that a detection rule is a valid YARA-L 2.0 rule."""
  if not rule_file.is_file():
    raise FileNotFoundError(rule_file)

  http_session = initialize_http_session()

  with open(rule_file, "r", encoding="utf-8") as f:
    rule_text = f.read()

  response = verify_rule(http_session=http_session, rule_text=rule_text)

  if response.get("success") is True:
    LOGGER.info(
        "Rule verified successfully (%s). Response: %s", rule_file, response
    )

  else:
    raise RuleVerificationError(
        f"Rule verification error ({rule_file}). Response:"
        f" {json.dumps(response, indent=4)}"
    )


def verify_rules():
  """Verify that all detection rules are valid YARA-L 2.0 rules using Chronicle's API."""
  http_session = initialize_http_session()

  # Maintain lists of successful and failed YARA-L 2.0 verification responses.
  verify_rule_successes = []
  verify_rule_errors = []

  for rule_file in list(RULES_DIR.glob("*.yaral")):
    with open(rule_file, "r", encoding="utf-8") as f:
      rule_text = f.read()

    response = verify_rule(http_session=http_session, rule_text=rule_text)
    time.sleep(0.6)  # Sleep to avoid exceeding API rate limit

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


if __name__ == "__main__":
  LOGGER.info("Rule CLI started")

  parser = argparse.ArgumentParser(description="rule_cli")

  parser.add_argument(
      "--pull-latest-rules",
      action="store_true",
      help=(
          "Retrieve the latest version of all rules from Chronicle and write"
          " them to local files."
      ),
  )

  parser.add_argument(
      "--update-remote-rules",
      action="store_true",
      help="Update rules in Chronicle based on local rule files and config.",
  )

  parser.add_argument(
      "--pull-latest-reference-lists",
      action="store_true",
      help=(
          "Retrieve the latest version of all reference lists from Chronicle"
          " and write them to local files."
      ),
  )

  parser.add_argument(
      "--update-remote-reference-lists",
      action="store_true",
      help=(
          "Update reference lists in Chronicle based on local reference list"
          " files and config."
      ),
  )

  subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")

  verify_rule_subparser = subparsers.add_parser(
      name="verify-rule",
      help="Verify that a rule is a valid YARA-L 2.0 rule.",
  )

  verify_rule_subparser.add_argument(
      "--rule-file-path",
      "-f",
      type=pathlib.Path,
      help="File path for rule to verify.",
      required=True,
  )

  parser.add_argument(
      "--verify-rules",
      action="store_true",
      help="Verify that all local rules are valid YARA-L 2.0 rules.",
  )

  # Print CLI help if no arguments are provided.
  if len(sys.argv) == 1:
    parser.print_help()
    sys.exit()

  args = parser.parse_args()

  # Create content directories if they don't exist.
  if not RULES_DIR.is_dir():
    RULES_DIR.mkdir()
  if not REF_LISTS_DIR.is_dir():
    REF_LISTS_DIR.mkdir()

  if args.pull_latest_rules:
    LOGGER.info(
        "Attempting to pull latest version of all rules from Chronicle and"
        " update local files"
    )
    pull_latest_rules()

  elif args.update_remote_rules:
    LOGGER.info(
        "Attempting to update rules in Chronicle based on local rule files"
    )
    update_remote_rules()

  if args.pull_latest_reference_lists:
    LOGGER.info(
        "Attempting to pull latest version of all reference lists from"
        " Chronicle and update local files"
    )
    pull_latest_reference_lists()

  if args.update_remote_reference_lists:
    LOGGER.info(
        "Attempting to update reference lists in Chronicle based on local"
        " reference list files"
    )
    update_remote_ref_lists()

  elif args.subcommand == "verify-rule":
    rule_file_path = args.rule_file_path
    LOGGER.info("Attempting to verify rule %s", rule_file_path)
    verify_rule_text(rule_file_path)

  elif args.verify_rules:
    LOGGER.info("Attempting to verify all local rules")
    verify_rules()
