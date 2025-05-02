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
"""Test a rule over a specified time range without persisting results.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.legacy/legacyTestRuleStreaming
"""
import datetime
import json
import logging
import os
from typing import Any, Iterator, Mapping, Sequence, Tuple

from content_manager.common import datetime_converter
from google.auth.transport import requests

# Set up logger that will include timestamps.
logging.basicConfig(
    level=os.getenv(key="LOGGING_LEVEL", default="INFO"),
    format="%(asctime)s | %(levelname)s | %(funcName)s | %(message)s",
    datefmt="%d-%b-%y %H:%M:%S %Z",
    handlers=[logging.StreamHandler()],
    encoding="utf-8",
)
LOGGER = logging.getLogger()

# Type alias for a result, which comes from one stream response. A Result is
# either a detection or rule execution error.
Result = Mapping[str, Any]


def parse_stream(
    response: requests.requests.Response,
) -> Iterator[Mapping[str, Any]]:
  """Parses a stream response containing one result.

  The requests library provides utilities for iterating over the HTTP stream
  response, so we do not have to worry
  about chunked transfer encoding.

  The response is a stream of bytes that represent a JSON array. Each top-level
  element of the JSON array is a
  result. The server can send a result at any time, thus adding to the JSON
  array. The array should end when the
  stream closes.

  Args:
    response: The response object returned from post().

  Yields:
    Dictionary representations of each result that was sent over the stream.
  """
  try:
    if response.encoding is None:
      response.encoding = "utf-8"

    for line in response.iter_lines(decode_unicode=True, delimiter="\r\n"):
      if not line:
        continue

      # Don't try to parse a line as JSON if it doesn't contain an opening and
      # closing brace. This can happen when no JSON elements are streamed and
      # the stream closes, which is a normal case when testing a rule that
      # doesn't generate any results.
      if len(line.split("{", 1)) < 2 and len(line.rsplit("}", 1)) < 2:
        continue

      # Trim all characters before first opening brace, and after last closing
      # brace. Example:
      #   Input:  "  {'key1': 'value1'},  "
      #   Output: "{'key1': 'value1'}"
      json_string = "{" + line.split("{", 1)[1].rsplit("}", 1)[0] + "}"
      yield json.loads(json_string)

  except Exception as e:  # pylint: disable=broad-except
    # Google SecOps's servers will generally send a {"error": ...} dict over
    # the stream to indicate retryable failures (e.g. due to periodic internal
    # server maintenance), which will not cause this except block to fire.
    #
    # In rarer cases, the streaming connection may silently fail; the
    # connection will close without an error dict, which manifests as a
    # requests.requests.exceptions.ChunkedEncodingError; see
    # https://github.com/urllib3/urllib3/issues/1516 for details from the
    # `requests` and `urllib3` community.
    #
    # Instead of allowing streaming clients to crash (for ChunkedEncodingErrors,
    # and for other Exceptions that may occur while reading from the stream),
    # we will catch exceptions, then yield a dict containing the error, so the
    # client may report the error.
    yield {
        "error": {
            "code": 503,
            "status": "UNAVAILABLE",
            "message": (
                "exception caught while reading stream response. This "
                "python client is catching all errors and is returning "
                "error code 503 as a catch-all. The original error "
                "message is as follows: {}".format(repr(e))
            ),
        }
    }


def stream_test_rule(
    http_session: requests.AuthorizedSession, request_data: Mapping[str, Any]
) -> Tuple[Sequence[Result], Sequence[Result], str]:
  """Makes one call to stream_test_rule and runs until disconnection.

  Each call to stream_test_rule streams all detections/rule execution errors
  found for the given rule and time range.
  The number of detections streamed is capped at the given number of max
  results. If a max number of results is not
  specified, a server-side default is used.

  The server sends a stream of bytes, which is interpreted as a list of python
  dictionaries; each dictionary
  represents one "result."

      - A result might have the key "error", either containing a rule execution
      error from Rules Engine or an error
        related to connection failure. If a connection failure error is
        returned, a RuntimeError will be raised
        indicating that you should retry testing the rule.
      - A result might have the key "detection", containing a detection from
      Rules Engine.

  The contents of a detection follow this format:
    {
      "id": "de_<UUID>",
      "type": "RULE_DETECTION",
      "detectionTime": "yyyy-mm-ddThh:mm:ssZ",
      "timeWindow": {
        "startTime": "yyyy-mm-ddThh:mm:ssZ",
        "endTime": "yyyy-mm-ddThh:mm:ssZ",
      }
      "collectionElements": [
        {
          "label": "e1",
          "references": [
            {
              "event": <UDM keys and values / sub-dictionaries>...
            },
            ...
          ],
        },
        {
          "label": "e2",
          ...
        },
        ...
      ],
      "detection": [
        {
          "ruleName": "<rule_name>",
          "description": "<rule description>
          "ruleType": "SINGLE_EVENT"/"MULTI_EVENT",
          "ruleLabels": [
            {
              "key": "<field name>",
              "value": "<field value>"
            }
          ]
        },
      ],
    }

  The contents of a rule execution error follow this format:
    {
      "category": "RULES_EXECUTION_ERROR",
      "error": <error message>,
      "timeWindow": {
        "startTime": "yyyy-mm-ddThh:mm:ssZ",
        "endTime": "yyyy-mm-ddThh:mm:ssZ",
      },
    }

  Args:
      http_session: Authorized session for HTTP requests.
      request_data: Dictionary containing connection request parameters
        (contains key, "rule_text" and optional keys, "start_time", "end_time",
        "max_results", and "scope").

  Returns:
      Tuple containing (all detections successfully streamed back, all rule
      execution errors successfully streamed
      back, disconnection reason).
  """
  url = f"{os.environ['GOOGLE_SECOPS_API_BASE_URL']}/{os.environ['GOOGLE_SECOPS_INSTANCE']}/legacy:legacyTestRuleStreaming"

  detections = []
  rule_execution_errors = []
  disconnection_reason = ""

  # Results should be streamed continuously.
  # A client-side timeout of 180s (3 minutes) is imposed between streamed
  # results. This should be enough time to handle delays in streaming back the
  # first result.
  with http_session.post(
      url=url, stream=True, data=request_data, timeout=180
  ) as response:
    # Expected server response is a continuous stream of bytes that represent a
    # JSON array. The parsing is handled by parse_stream. See docstring above
    # for formats of detections and rule execution errors.
    #
    # Example stream of bytes:
    # [
    #   {detection 1},
    #   # Some delay before server sends next result...
    #   {rule execution error 1},
    #   # Some delay before server sends next result(s)...
    #   # We expect the ']' to arrive if all results are streamed before a
    #   # server-side timeout; otherwise, a connection failure error may be
    #   # streamed back if/when the connection breaks.
    LOGGER.info("Initiated connection to test rule stream")
    if response.status_code >= 400:
      disconnection_reason = (
          f"Connection closed with status={response.status_code},"
          f" error={response.text}"
      )
    else:
      for result in parse_stream(response):
        if "detection" in result:
          detection = result["detection"]
          LOGGER.debug("Retrieved detection")
          detections.append(detection)
        elif "error" in result:
          # We distinguish rule execution errors from other errors sent back
          # over the stream by checking to see if the error has the
          # RULES_EXECUTION_ERROR category.
          error = result["error"]
          if error.get("category") == "RULES_EXECUTION_ERROR":
            LOGGER.error("A rule execution error occurred")
            rule_execution_errors.append(error)
          else:
            error_dump = json.dumps(error, indent="\t")
            disconnection_reason = f"Connection aborted with error={error_dump}"
            break

  return detections, rule_execution_errors, disconnection_reason


def test_rule(
    http_session: requests.AuthorizedSession,
    rule_text: str,
    start_time: datetime.datetime | None = None,
    end_time: datetime.datetime | None = None,
    max_detections: int | None = 0,
    scope: str | None = None,
) -> Sequence[Mapping[str, Any]]:
  """Calls legacy.legacyTestRuleStreaming API method once to test rule.

  https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.legacy/legacyTestRuleStreaming

  Args:
    http_session: Authorized session for HTTP requests.
    rule_text: The content of the YARA-L 2.0 rule to test as a UTF-8 string.
    start_time (optional): Start time of the time range of logs to test the rule
      over. If unspecified, will default to 12 hours before end_time. Time range
      between start_time and end_time must not exceed two weeks. A timestamp in
      RFC3339 UTC "Zulu" format, with nanosecond resolution and up to nine
      fractional digits. Examples: "2014-10-02T15:01:23Z" and
      "2014-10-02T15:01:23.045123456Z".
    end_time (optional): End time of the time range of logs to test the rule
      over. Optional. The end time of the time range of events to test the rule
      text over. If unspecified, will either default to 12 hours after
      start_time, or the current day bucket if start_time is also unspecified.
      Time range between start_time and end_time must not exceed two weeks. A
      timestamp in RFC3339 UTC "Zulu" format, with nanosecond resolution and up
      to nine fractional digits. Examples - "2014-10-02T15:01:23Z" and
      "2014-10-02T15:01:23.045123456Z". Time range between start_time and
      end_time must not exceed two weeks.
    max_detections (optional): Maximum number of detections to return. The
      maximum number of detections to return. The service may return fewer than
      this value. If unspecified, at most 1,000 detections will be returned. The
      maximum value is 10,000; values above 10,000 will be coerced to 10,000.
    scope (optional): The data access scope to use to run the rule. This field
      is only required if data access control is enabled.

  Returns:
    A list of detection objects.

  Raises:
    RuntimeError: Streaming connection was unexpectedly closed or aborted.
  """
  request_data = {
      "rule_text": rule_text,
      "start_time": datetime_converter.strftime(start_time),
      "end_time": datetime_converter.strftime(end_time),
      "max_detections": max_detections,
      "scope": scope,
  }

  detections, rule_execution_errors, disconnection_reason = stream_test_rule(
      http_session=http_session, request_data=request_data
  )

  # Log the total number of detections/rule execution errors that were
  # successfully found from testing the rule, up to the point of disconnection.
  LOGGER.info(
      "Retrieved %s detections and %s rule execution errors",
      len(detections),
      len(rule_execution_errors),
  )

  if disconnection_reason:
    raise RuntimeError(f"Connection failed: {disconnection_reason}.")

  if rule_execution_errors:
    for error in rule_execution_errors:
      LOGGER.error("A rule execution error occurred: %s", error)
    raise RuntimeError(
        "A rule execution error occurred."
        f"{json.dumps(rule_execution_errors, indent=4)}"
    )

  return detections
