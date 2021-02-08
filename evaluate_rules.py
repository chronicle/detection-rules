#!/usr/bin/env python3

# Copyright 2021 Google LLC
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
"""Authoritative test for the correctness of all YARA-L detection rule files.

This script enumerates all the files with a ".yaral" extension located in or
under the current directory, uploads them to Chronicle using the Detection API,
and reports back the status of each rule - specifically whether or not it was
compiled successfully on the server side.

Future addition: optional execution of rules on historical data ("retrohunt") to
evaluate their actual efficacy, not just their syntax and semantics.

This script is executed manually, not as an automated unit test. There are two
reasons for this: it's relatively slow (1 second for each rule compilation, and
a few minutes for each rule execution), and it requires a Chronicle API key.

In that sense, this script does not replace the server-less syntax-only unit
test (syntax_test.py) which provides a sufficient level of confidence and fast
iteration when creating or modifying YARA-L rules without access to Chronicle.
However, this script does provide an even higher level of confidence that the
rules work as intended.

This code is based on https://github.com/chronicle/detection-api.
"""

import argparse
import functools
import pathlib
import time
from typing import Any, Callable, Mapping, Optional, Union

from google.auth.transport import requests
from google.oauth2 import service_account

DEFAULT_CREDENTIALS_FILE = pathlib.Path.home() / ".chronicle_credentials.json"
AUTHORIZATION_SCOPES = ["https://www.googleapis.com/auth/chronicle-backstory"]
CHRONICLE_API_BASE_URL = "https://backstory.googleapis.com"

# Ensure we do not exceed 1 QPS per RPC method.
start_times = {}


def initialize_http_session(
    credentials_file_path: Optional[Union[str, pathlib.Path]]
) -> requests.AuthorizedSession:
  """Initializes an authorized HTTP session, based on the given credentials.

  Args:
    credentials_file_path: Absolute or relative path to a JSON file containing
      the private OAuth 2.0 credentials of a Google Cloud Platform service
      account. Optional - the default is ".chronicle_credentials.json" in the
      user's home directory. Keep it secret, keep it safe.

  Returns:
    HTTP session object to send authorized requests and receive responses.

  Raises:
    OSError: Failed to read the given file, e.g. not found, no read access
      (https://docs.python.org/library/exceptions.html#os-exceptions).
    ValueError: Invalid file contents.
  """
  if not credentials_file_path:
    credentials_file_path = DEFAULT_CREDENTIALS_FILE
  credentials = service_account.Credentials.from_service_account_file(
      str(credentials_file_path), scopes=AUTHORIZATION_SCOPES)
  return requests.AuthorizedSession(credentials)


def evaluate_file(http_session: requests.AuthorizedSession,
                  relative_path: pathlib.Path, n: int):
  """Evaluates the given rule file with the Chronicle Detection API.

  Args:
    http_session: Authorized session for HTTP requests.
    relative_path: Rule file to evaluate, relative to the current directory.
    n: 1-based index of the given path, to improve output readability.
  """
  print(f"\nFile {n}: {relative_path}")

  # Read rule from file, and upload it, i.e. compile it.
  content = relative_path.read_text(encoding="utf-8").strip()
  rule = create_rule(http_session, content)
  print(f"Rule ID: {rule['ruleId']}")
  print(f"Rule name: {rule['ruleName']}")

  # Check rule compilation status.
  if rule["compilationState"] == "SUCCEEDED":
    print("(Compilation succeeded)")
  else:
    print(f"COMPILATION {rule['compilationState']}: " +
          f"{rule['compilationError']}")

  # Cleanup.
  delete_rule(http_session, rule["ruleId"])


def api_decorator(
    api_function: Callable[..., requests.requests.Response]
) -> Callable[..., Mapping[str, Any]]:
  """Decorator for all functions below that use the Chronicle Detection API.

  Args:
    api_function: Python function using a single Chronicle Detection API call.

  Returns:
    Python dictionary representing the JSON body of the HTTP response returned
    by api_function.

  Raises:
    requests.exceptions.HTTPError: HTTP request resulted in an error
      (response.status_code >= 400).
  """

  @functools.wraps(api_function)
  def wrapper(*args, **kwargs) -> Mapping[str, Any]:
    # Throttle RPCs to ensure we do not exceed 1 QPS per RPC type.
    global start_times
    api_function_name = api_function.__name__
    time_since_last_call = time.time() - start_times.get(api_function_name, 0)
    if time_since_last_call < 1:
      time.sleep(1 - time_since_last_call)
    start_times[api_function_name] = time.time()

    # API call with subsequent error handling.
    response = api_function(*args, **kwargs)
    if response.status_code >= 400:
      print(response.text)
    response.raise_for_status()
    return response.json()

  return wrapper


@api_decorator
def create_rule(http_session: requests.AuthorizedSession,
                rule_content: str) -> requests.requests.Response:
  """Uploads (compiles and stores) a new detection rule to Chronicle.

  Args:
    http_session: Authorized session for HTTP requests.
    rule_content: Content of the new detection rule.

  Returns:
    Details of the new detection rule, including server-side metadata.
  """
  url = f"{CHRONICLE_API_BASE_URL}/v2/detect/rules"
  body = {"rule_text": rule_content}
  return http_session.request("POST", url, json=body)


@api_decorator
def delete_rule(http_session: requests.AuthorizedSession,
                rule_id: str) -> requests.requests.Response:
  """Deletes the given detection rule.

  Args:
    http_session: Authorized session for HTTP requests.
    rule_id: Unique ID of the detection rule to delete ("ru_<UUID>").

  Returns:
    Empty dictionary.
  """
  url = f"{CHRONICLE_API_BASE_URL}/v2/detect/rules/{rule_id}"
  return http_session.request("DELETE", url)


if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument(
      "-c",
      "--credentials_file",
      type=str,
      help=f"credentials file path (default: '{DEFAULT_CREDENTIALS_FILE}')")

  command_line_args = parser.parse_args()
  session = initialize_http_session(command_line_args.credentials_file)

  cwd = pathlib.Path.cwd()
  print(f"Current directory: {cwd}")
  for i, absolute_path in enumerate(sorted(cwd.rglob("*.yaral")), start=1):
    evaluate_file(session, absolute_path.relative_to(cwd), i)
