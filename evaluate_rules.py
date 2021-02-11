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

Users can limit the scope to a specific subset files by specifying either the
"--include_files" argument or "--ignore_files" argument, where the value is a
list of path/directory/filename substrings. For example, given this directory
tree:

    detection-rules/xxx/aaa.yaral
                        bbb.yaral
                    yyy/ccc.yaral
                        ddd.yaral
                    zzz/eee.yaral
                        fff.yaral

Specifying "--include_files=aaa,fff" in the command-line will evaluate only the
files "aaa.yaral" and "fff.yaral", and "--ignored_files=xxx,yyy" will evaluate
all the files except the ones in or under the "xxx" and "yyy" directories, etc.

In addition, users may run each evaluated rule as a "retrohunt", i.e. detect
matching events in historical data, to evaluate the rule's actual efficacy, not
just its syntax and semantics. To do this, specify the "-r" flag, and optionally
specify the start and end times (the default time range is the last 24 hours).
If you want to save a file containing the detected events for each evaluated
rule file, specify the "-s" flag too.

This script is executed manually, not as an automated unit test. There are two
reasons for this: it's relatively slow (1 second for each rule compilation, and
close to a minute for each retrohunt), and it requires a Chronicle API key.

In that sense, this script does not replace the server-less syntax-only unit
test (syntax_test.py) which provides a sufficient level of confidence and fast
iteration when creating or modifying YARA-L rules without access to Chronicle.
However, this script does provide an even higher level of confidence that the
rules work as intended.

This code is based on https://github.com/chronicle/detection-api.
"""

import argparse
import datetime
import functools
import json
import pathlib
import re
import signal
import sys
import time
from typing import Any, Callable, Mapping, Optional, Sequence, Tuple, Union

from google.auth.transport import requests
from google.oauth2 import service_account

DEFAULT_CREDENTIALS_FILE = pathlib.Path.home() / ".chronicle_credentials.json"
AUTHORIZATION_SCOPES = ["https://www.googleapis.com/auth/chronicle-backstory"]
CHRONICLE_API_BASE_URL = "https://backstory.googleapis.com/v2/detect/rules"

# Ensure we do not exceed 1 QPS per RPC method.
start_times = {}

# Support a clean termination if/when the user presses Ctrl+C.
should_exit_soon = False


def signal_handler(unused_sig, unused_frame):
  """Signals the script to do a clean termination, instead of crashing."""
  print(" exiting!")
  global should_exit_soon
  should_exit_soon = True


def initialize_command_line_args(args=None) -> Optional[argparse.Namespace]:
  """Initializes and checks all the command-line arguments."""
  parser = argparse.ArgumentParser()
  parser.add_argument(
      "-c",
      "--credentials_file",
      type=str,
      help=f"credentials file path (default = '{DEFAULT_CREDENTIALS_FILE}')")
  parser.add_argument(
      "-in",
      "--include_files",
      type=parse_files_list,
      help=("evaluate only these files (comma-delimited list of path " +
            "substrings, default = include everything)"))
  parser.add_argument(
      "-ig",
      "--ignore_files",
      type=parse_files_list,
      help=("evaluate all files except these (comma-delimited list of path " +
            "substrings, default = ignore nothing)"))
  parser.add_argument(
      "-r",
      "--run_retrohunt",
      action="store_true",
      help=("also run a retrohunt after successful rule compilation " +
            "(default = false)"))
  parser.add_argument(
      "-ts",
      "--start_time",
      type=iso8601_to_utc_datetime,
      help=("lower bound of the retrohunt's time range, as an ISO 8601 " +
            "string ('yyyy-mm-ddThh:mm:ss', default = 48 hours ago)"))
  parser.add_argument(
      "-te",
      "--end_time",
      type=iso8601_to_utc_datetime,
      help=("upper bound of the retrohunt's time range, as an ISO 8601 " +
            "string ('yyyy-mm-ddThh:mm:ss', default = 24 hours ago)"))
  parser.add_argument(
      "-tl",
      "--local_time",
      action="store_true",
      help=("start and end times are specified in the system's local " +
            "timezone (default = UTC)"))
  parser.add_argument(
      "-s",
      "--save_results",
      action="store_true",
      help=("save retrohunt results (up to 10K events) in 'rule_name.json' " +
            "files (default = false)"))

  # Sanity checks for command-line arguments.
  parsed_args = parser.parse_args(args)
  start, end = define_time_range(parsed_args.start_time, parsed_args.end_time,
                                 parsed_args.local_time)
  if parsed_args.include_files and parsed_args.ignore_files:
    print("Error: 'include_files' and 'ignore_files' are mutually-exclusive")
    return None
  elif start >= end:
    print("Error: empty or negative time range, 'start_time' >= 'end_time'")
    return None
  elif parsed_args.save_results and not parsed_args.run_retrohunt:
    print("Error: specified 'save_results' depends on unspecified " +
          "'run_retrohunt'")
    return None
  else:
    return parsed_args


def parse_files_list(arg: str) -> Sequence[str]:
  """Converts the command-line argument "-in" or "-ig" to a list of paths."""
  return [path.strip() for path in arg.split(",") if path.strip()]


def is_file_in_scope(file_path: pathlib.Path, include_files: Sequence[str],
                     ignore_files: Sequence[str]) -> bool:
  """Decides if the given file should be evaluated, based on path filters."""
  path = str(file_path)
  include_files = include_files or []
  ignore_files = ignore_files or []
  # Does the YARA-L file path match at least one include-filter?
  if include_files:
    return any([path_substring in path for path_substring in include_files])
  # Alternatively, does it not match any of the ignore-filters?
  else:
    return all([path_substring not in path for path_substring in ignore_files])


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
                  relative_path: pathlib.Path, n: int) -> Mapping[str, Any]:
  """Evaluates the given rule file with the Chronicle Detection API.

  Args:
    http_session: Authorized session for HTTP requests.
    relative_path: Rule file to evaluate, relative to the current directory.
    n: 1-based index of the given path, to improve output readability.

  Returns:
    Python dictionary containing the details of the evaluated detection rule,
    including server-side metadata. The dictionary is empty if the rule
    compilation failed.
  """
  print(f"\nFile {n}: {relative_path}")

  # Read rule from file, and upload it, i.e. compile it.
  content = relative_path.read_text(encoding="utf-8").strip()
  rule = create_rule(http_session, content)
  print(f"Rule ID: {rule['ruleId']}")
  print(f"Rule name: {rule['ruleName']}")

  # Check rule compilation status.
  if rule["compilationState"] == "SUCCEEDED":
    print("Compilation succeeded")
    return rule
  else:
    print(f"COMPILATION {rule['compilationState']}: " +
          f"{rule['compilationError']}")
    return {}


def run_rule(http_session: requests.AuthorizedSession, rule: Mapping[str, Any],
             iso8601_start_time: str,
             iso8601_end_time: str) -> Sequence[Mapping[str, Any]]:
  """Runs a retrohunt using the given run in the given time range.

  Args:
    http_session: Authorized session for HTTP requests.
    rule: Python dictionary containing the details of the detection rule.
    iso8601_start_time: ISO 8601 string ("yyyy-mm-ddThh:mm:ssZ") representing
      the lower bound (start time) of the retrohunt's time range.
    iso8601_end_time: ISO 8601 string ("yyyy-mm-ddThh:mm:ssZ") representing the
      upper bound (end time) of the retrohunt's time range.

  Returns:
    All the detection results associated with the given rule.
  """
  retrohunt = start_retrohunt(http_session, rule["versionId"],
                              iso8601_start_time, iso8601_end_time)
  start_dt = iso8601_to_utc_datetime(retrohunt["retrohuntStartTime"])
  print(f"Retrohunt execution start time: {utc_datetime_to_local(start_dt)}")

  global should_exit_soon
  while retrohunt["state"] == "RUNNING" and not should_exit_soon:
    # Currently using "poll_retrohunt" instead of "wait_for_retrohunt" in order
    # to allow the user to break whenever they want, without having to wait for
    # the RPC call to return or time-out.
    # try:
    #   # Blocks until the RPC succeeds or times-out.
    #   retrohunt = wait_for_retrohunt(http_session, rule["versionId"],
    #                                  retrohunt["retrohuntId"])
    # except requests.requests.ReadTimeout:
    #   pass

    for _ in range(5):
      if not should_exit_soon:
        time.sleep(1)
      else:
        return []

    retrohunt = poll_retrohunt(http_session, rule["versionId"],
                               retrohunt["retrohuntId"])
    if 0 < retrohunt.get("progressPercentage", 0) < 100:
      print(f"Progress: {retrohunt['progressPercentage']}%")

  if not should_exit_soon:
    end_dt = iso8601_to_utc_datetime(retrohunt["retrohuntEndTime"])
    detections = retrieve_detections(http_session, rule["versionId"])
    print(f"{retrohunt['state']} (duration: {end_dt - start_dt}, " +
          f"matching events: {len(detections)}" +
          # API limit: return maximum of 10,000 detections.
          f"{'+' if len(detections) == 10000 else ''})")
    return detections
  else:
    return []


def retrieve_detections(http_session: requests.AuthorizedSession,
                        rule_version_id: str) -> Sequence[Mapping[str, Any]]:
  """Retrieves all the detections associated with the given rule.

  Args:
    http_session: Authorized session for HTTP requests.
    rule_version_id: Unique ID of the detection rule, optionally with a specific
      version ("ru_<UUID>[@v_<seconds>_<nanoseconds>]").

  Returns:
    All detection results.
  """
  first_chunk = list_detections(http_session, rule_version_id)
  next_page_token = first_chunk.get("nextPageToken", "")
  all_detections = first_chunk.get("detections", [])

  global should_exit_soon
  while next_page_token and not should_exit_soon:
    detections = list_detections(http_session, rule_version_id, next_page_token)
    all_detections.extend(detections.get("detections", []))
    next_page_token = detections.get("nextPageToken", "")

  return all_detections


def save_detection_results(yaral_path: pathlib.Path,
                           detections: Sequence[Mapping[str, Any]]):
  """Saves the given rule's detections in a similarly-named JSON file."""
  json_path = yaral_path.with_suffix(".json")
  if detections:
    data = json.dumps(detections, indent=2)
    json_path.write_text(data, encoding="utf-8")
    print(f"Saved detections: {json_path}")


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
  url = f"{CHRONICLE_API_BASE_URL}"
  return http_session.request("POST", url, json={"rule_text": rule_content})


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
  url = f"{CHRONICLE_API_BASE_URL}/{rule_id}"
  return http_session.request("DELETE", url)


@api_decorator
def start_retrohunt(http_session: requests.AuthorizedSession,
                    rule_version_id: str, iso8601_start_time: str,
                    iso8601_end_time: str) -> Mapping[str, Any]:
  """Starts a retrohunt using the given detection rule.

  Args:
    http_session: Authorized session for HTTP requests.
    rule_version_id: Unique ID of the detection rule to run, optionally with a
      specific version ("ru_<UUID>[@v_<seconds>_<nanoseconds>]").
    iso8601_start_time: ISO 8601 string ("yyyy-mm-ddThh:mm:ssZ") representing
      the lower bound (start time) of the retrohunt's time range.
    iso8601_end_time: ISO 8601 string ("yyyy-mm-ddThh:mm:ssZ") representing the
      upper bound (end time) of the retrohunt's time range.

  Returns:
    Details and status of the new retrohunt.
  """
  url = (f"{CHRONICLE_API_BASE_URL}/{rule_version_id}:runRetrohunt")
  body = {"start_time": iso8601_start_time, "end_time": iso8601_end_time}
  return http_session.request("POST", url, json=body)


@api_decorator
def poll_retrohunt(http_session: requests.AuthorizedSession,
                   rule_version_id: str,
                   retrohunt_id: str) -> Mapping[str, Any]:
  """Polls the status of the given retrohunt.

  Args:
    http_session: Authorized session for HTTP requests.
    rule_version_id: Unique ID of the detection rule, optionally with a specific
      version ("ru_<UUID>[@v_<seconds>_<nanoseconds>]").
    retrohunt_id: Unique ID of the a detection rule's retrohunt execution
      ("oh_<UUID>").

  Returns:
    Details and status of the given retrohunt.
  """
  url = f"{CHRONICLE_API_BASE_URL}/{rule_version_id}/retrohunts/{retrohunt_id}"
  return http_session.request("GET", url)


@api_decorator
def wait_for_retrohunt(http_session: requests.AuthorizedSession,
                       rule_version_id: str,
                       retrohunt_id: str) -> Mapping[str, Any]:
  """Waits up to 2 minutes for the given retrohunt to complete.

  Args:
    http_session: Authorized session for HTTP requests.
    rule_version_id: Unique ID of the detection rule, optionally with a specific
      version ("ru_<UUID>[@v_<seconds>_<nanoseconds>]").
    retrohunt_id: Unique ID of the a detection rule's retrohunt execution
      ("oh_<UUID>").

  Returns:
    Details and status of the given retrohunt.
  """
  url = (f"{CHRONICLE_API_BASE_URL}/{rule_version_id}/retrohunts/" +
         f"{retrohunt_id}:wait")
  return http_session.request("POST", url)


@api_decorator
def list_detections(http_session: requests.AuthorizedSession,
                    rule_version_id: str,
                    page_token: str = "") -> Mapping[str, Any]:
  """Retrieves a chunk of all the detections associated with the given rule.

  Args:
    http_session: Authorized session for HTTP requests.
    rule_version_id: Unique ID of the detection rule, optionally with a specific
      version ("ru_<UUID>[@v_<seconds>_<nanoseconds>]").
    page_token: Base64-encoded string token to retrieve a specific page of
      detection results. Optional - the first page's token is an empty string.

  Returns:
    Detection results: {"detections": [{...}, ..., "nextPageToken": "..."]}.
  """
  url = f"{CHRONICLE_API_BASE_URL}/{rule_version_id}/detections"
  params = {"page_size": 1000, "page_token": page_token}
  return http_session.request("GET", url, params=params)


def define_time_range(iso8601_start_time: Optional[datetime.datetime],
                      iso8601_end_time: Optional[datetime.datetime],
                      is_local_timezone: bool) -> Tuple[str, str]:
  """Returns the lower and upper bounds of the retrohunt's time range.

  Default if unspecified by the user in the command-line: from 48 hours ago to
  24 hours ago (truncating minutes and seconds).

  Args:
    iso8601_start_time: Timezone-aware UTC datetime object representing the
      lower bound (start time) of the retrohunt's time range.
    iso8601_end_time: Timezone-aware UTC datetime object representing the upper
      bound (end time) of the retrohunt's time range.
    is_local_timezone: Use the system's local timezone (True), or UTC (False)?

  Returns:
    Start and end times for the retrohunt's events, as ISO 8601 strings.
  """
  now = datetime.datetime.utcnow().replace(minute=0, second=0, microsecond=0)
  if not iso8601_start_time:
    iso8601_start_time = now - datetime.timedelta(days=2)
  if not iso8601_end_time:
    iso8601_end_time = now - datetime.timedelta(days=1)

  if is_local_timezone:
    iso8601_start_time = iso8601_start_time.replace(tzinfo=None)
    iso8601_end_time = iso8601_end_time.replace(tzinfo=None)

  return (datetime_to_iso8601(iso8601_start_time),
          datetime_to_iso8601(iso8601_end_time))


def iso8601_to_utc_datetime(iso_8601: str) -> datetime.datetime:
  """Converts an ISO 8601 string to a timezone-aware UTC datetime object.

  More details: https://en.wikipedia.org/wiki/ISO_8601

  Args:
    iso_8601: Date and time in the extended ("T") ISO 8601 format. In addition,
      accept letter-case mistakes ("t", "z") and a missing "Z".

  Returns:
    Timezone-aware UTC datetime object.

  Raises:
    ValueError: Invalid input value.
  """
  # Work-around fixable issues in user-specified command-line arguments.
  iso_8601 = iso_8601.upper()
  if iso_8601[-1] != "Z":
    iso_8601 += "Z"

  # Append the suffix "+0000" in order to produce a timezone-aware UTC datetime,
  # because strptime's "%z" does not recognize the meaning of the "Z" suffix.
  try:
    # Support (but don't require) sub-second parsing, but ignore anything
    # smaller than microseconds.
    iso_8601 = re.sub(r"(\d{6})\d+Z", r"\1Z", iso_8601)
    return datetime.datetime.strptime(f"{iso_8601}+0000",
                                      "%Y-%m-%dT%H:%M:%S.%fZ%z")
  except ValueError:
    # No microseconds? No problem, try to parse without them.
    # If there's a different parsing problem, it will surface below too.
    pass

  return datetime.datetime.strptime(f"{iso_8601}+0000", "%Y-%m-%dT%H:%M:%SZ%z")


def datetime_to_iso8601(dt: datetime.datetime) -> str:
  """Converts a datetime to an ISO 8601 string, regardless of itz timezone."""
  return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_datetime_to_local(utc_dt: datetime.datetime) -> datetime.datetime:
  """Converts a timezone-aware UTC datetime to a local one without a timezone.

  Attention: this is a simple implementation, use other open source libraries
  if historical accuracy is important!

  Args:
    utc_dt: Timezone-aware UTC datetime object.

  Returns:
    Datetime object without a timezone, representing local system time.
  """
  offset = time.localtime().tm_gmtoff
  return utc_dt.replace(tzinfo=None) + datetime.timedelta(seconds=offset)


def local_datetime_to_utc(local_dt: datetime.datetime) -> datetime.datetime:
  """Converts a local datetime without a timezone to a TZ-aware UTC one."""
  return local_dt.astimezone(datetime.timezone.utc)


if __name__ == "__main__":
  cli = initialize_command_line_args()
  if not cli:
    sys.exit(1)  # A sanity check failed.

  cwd = pathlib.Path.cwd()
  print(f"Current directory: {cwd}")
  if cli.run_retrohunt:
    start_time, end_time = define_time_range(cli.start_time, cli.end_time,
                                             cli.local_time)
    print(f"Retrohunt time range: {start_time} - {end_time}")

  session = initialize_http_session(cli.credentials_file)
  signal.signal(signal.SIGINT, signal_handler)  # Register Ctrl+C callback.
  i = 0

  for absolute_path in sorted(cwd.rglob("*.yaral")):
    rule_path = absolute_path.relative_to(cwd)
    if is_file_in_scope(rule_path, cli.include_files, cli.ignore_files):
      i += 1
      new_rule = evaluate_file(session, rule_path, i)
      if new_rule and cli.run_retrohunt and not should_exit_soon:
        detection_results = run_rule(session, new_rule, start_time, end_time)
        if cli.save_results:
          save_detection_results(rule_path, detection_results)
      delete_rule(session, new_rule["ruleId"])
    if should_exit_soon:
      break
