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
"""Unit tests for the "stream_test_rule" module."""

import json
import unittest
from unittest import mock

from google.auth.transport import requests
from google_secops_api.rules import stream_test_rule


class StreamTestRuleTest(unittest.TestCase):
  """Unit tests for the stream_test_rule module."""

  @mock.patch.object(
      target=requests, attribute="AuthorizedSession", autospec=True
  )
  def test_http_error(self, mock_session: unittest.mock.MagicMock):
    """Test that an HTTP error occurs."""
    # Mock a streaming connection failure with a non-200 status code.
    mock_session.post.return_value.__enter__.return_value.status_code = 429

    # Prepare dummy detections and rule execution errors to be streamed back
    mock_results = [
        '{"detection": {"id": "1"}}',
        '{"detection": {"id": "2"}}',
        '{"error": {"category": "RULES_EXECUTION_ERROR"}}',
    ]

    # Make the streamed responses from response.iter_lines() return the above
    # results
    mock_session.post.return_value.__enter__.return_value.iter_lines.side_effect = [
        mock_results,
    ]

    # Call stream_test_rule
    request_data = {
        "rule_text": "dummy rule content",
        "start_time": "2024-03-12T00:00:00Z",
        "end_time": "2024-03-13T00:00:00Z",
    }

    (
        detections,
        rule_execution_errors,
        disconnection_reason,
    ) = stream_test_rule.stream_test_rule(
        http_session=mock_session, request_data=request_data
    )

    # No detections/rule execution errors should have been returned
    self.assertEqual(len(detections), 0)
    self.assertEqual(len(rule_execution_errors), 0)

    # A disconnection reason related to closed connection should be returned
    self.assertIn("Connection closed with status=429", disconnection_reason)

  @mock.patch.object(
      target=requests, attribute="AuthorizedSession", autospec=True
  )
  def test_connection_failure_error(
      self, mock_session: unittest.mock.MagicMock
  ):
    """Test that a connection failure error occurs."""
    # Mock a successful streaming connection.
    mock_session.post.return_value.__enter__.return_value.status_code = 200

    # Prepare detections/rule execution errors to be streamed back
    mock_detection_template = {
        "id": "PLACEHOLDER",  # To be replaced with unique ID.
        "type": "RULE_DETECTION",
        "detectionTime": "2021-01-05T01:00:00Z",
        "timeWindow": {
            "startTime": "2021-01-05T00:00:00Z",
            "endTime": "2021-01-05T01:00:00Z",
        },
        "detection": [{
            "ruleName": "rule content",
            "ruleType": "MULTI_EVENT",
            "detectionFields": [{
                "key": "fieldName",
                "value": "fieldValue",
            }],
        }],
    }

    mock_execution_error_template = {
        "category": "RULES_EXECUTION_ERROR",
        "text": "PLACEHOLDER",  # To be replaced with unique error text.
        "ruleExecution": {
            "windowStartTime": "2021-01-04T00:00:00Z",
            "windowEndTime": "2020-01-06T00:05:00Z",
        },
    }

    # Prepare a "stream-aborting" error to be streamed back. This error should
    # not be considered a rule execution error, and should stop any further
    # stream processing
    mock_stream_error = {
        "code": 503,
        "status": "UNAVAILABLE",
        "message": "exception caught while reading...",
    }

    mock_detections = []
    mock_execution_errors = []
    for i in range(5):
      mock_detection = mock_detection_template.copy()
      mock_detection["id"] = str(i)
      mock_detections.append(mock_detection)

      mock_execution_error = mock_execution_error_template.copy()
      mock_execution_error["text"] = str(i)
      mock_execution_errors.append(mock_execution_error)

    # Make the streamed responses from response.iter_lines() return some of the
    # above results, followed by the "stream-aborting" failure, followed by the
    # remaining results
    mock_stream_responses = []
    num_results_to_stream = 3
    for i in range(num_results_to_stream):
      mock_stream_responses.append(
          f'{{"detection":{json.dumps(mock_detections[i])}}}'  # pylint: disable="bad-whitespace"
          )
      mock_stream_responses.append(
          f'{{"error": {json.dumps(mock_execution_errors[i])}}}'  # pylint: disable="bad-whitespace"
      )

    mock_stream_responses.append(
        f'{{"error": {json.dumps(mock_stream_error)}}}'  # pylint: disable="bad-whitespace"
    )

    for i in range(num_results_to_stream, 5):
      mock_stream_responses.append(
          f'{{"detection": {json.dumps(mock_detections[i])}}}'  # pylint: disable="bad-whitespace"
      )
      mock_stream_responses.append(
          f'{{"error": {json.dumps(mock_execution_errors[i])}}}'  # pylint: disable="bad-whitespace"
      )

    mock_session.post.return_value.__enter__.return_value.iter_lines.side_effect = [
        mock_stream_responses,
    ]

    # Call stream_test_rule.
    request_data = {
        "rule.rule_text": "dummy rule content",
        "start_time": "2021-01-01T00:00:00Z",
        "end_time": "2021-01-14T00:00:00Z",
    }
    (
        detections,
        rule_execution_errors,
        disconnection_reason,
    ) = stream_test_rule.stream_test_rule(
        http_session=mock_session, request_data=request_data
    )

    # Only results streamed before the stream error should be returned. The
    # "stream-aborting" error should also not be included among rule execution
    # errors to be returned
    self.assertEqual(detections, mock_detections[:num_results_to_stream])
    self.assertEqual(
        rule_execution_errors, mock_execution_errors[:num_results_to_stream]
    )

    # A disconnection reason related to aborted connection should be returned
    self.assertIn("Connection aborted with error", disconnection_reason)

  @mock.patch.object(
      target=requests, attribute="AuthorizedSession", autospec=True
  )
  def test_happy_path(self, mock_session: unittest.mock.MagicMock):
    """Test that detections and rule execution errors are returned successfully."""
    # Mock a successful streaming connection.
    mock_session.post.return_value.__enter__.return_value.status_code = 200

    # Prepare detections/rule execution errors to be streamed back
    mock_detection_template = {
        "id": "PLACEHOLDER",  # To be replaced with unique ID
        "type": "RULE_DETECTION",
        "detectionTime": "2021-01-05T01:00:00Z",
        "timeWindow": {
            "startTime": "2021-01-05T00:00:00Z",
            "endTime": "2021-01-05T01:00:00Z",
        },
        "detection": [{
            "ruleName": "rule content",
            "ruleType": "MULTI_EVENT",
            "detectionFields": [{
                "key": "fieldName",
                "value": "fieldValue",
            }],
        }],
    }

    mock_execution_error_template = {
        "category": "RULES_EXECUTION_ERROR",
        "text": "PLACEHOLDER",  # To be replaced with unique error text
        "ruleExecution": {
            "windowStartTime": "2021-01-04T00:00:00Z",
            "windowEndTime": "2020-01-06T00:05:00Z",
        },
    }

    # Make the streamed responses from response.iter_lines() return the above
    # results
    mock_detections = []
    mock_execution_errors = []
    mock_stream_responses = []
    num_results = 5
    for i in range(num_results):
      mock_detection = mock_detection_template.copy()
      mock_detection["id"] = str(i)
      mock_detections.append(mock_detection)
      mock_stream_responses.append(
          f'{{"detection": {json.dumps(mock_detection)}}}'  # pylint: disable="bad-whitespace"
      )

      mock_execution_error = mock_execution_error_template.copy()
      mock_execution_error["text"] = str(i)
      mock_execution_errors.append(mock_execution_error)
      mock_stream_responses.append(
          f'{{"error": {json.dumps(mock_execution_error)}}}'  # pylint: disable="bad-whitespace"
      )

    mock_session.post.return_value.__enter__.return_value.iter_lines.side_effect = [
        mock_stream_responses,
    ]

    # Call stream_test_rule
    request_data = {
        "rule.rule_text": "dummy rule content",
        "start_time": "2021-01-01T00:00:00Z",
        "end_time": "2021-01-14T00:00:00Z",
    }
    (
        detections,
        rule_execution_errors,
        disconnection_reason,
    ) = stream_test_rule.stream_test_rule(
        http_session=mock_session, request_data=request_data
    )

    # All detections/rule execution errors should be returned
    self.assertEqual(detections, mock_detections)
    self.assertEqual(rule_execution_errors, mock_execution_errors)

    # A disconnection reason should not be returned
    self.assertEqual(disconnection_reason, "")

  @mock.patch.object(
      target=requests, attribute="AuthorizedSession", autospec=True
  )
  def tests_happy_path_no_results(self, mock_session: unittest.mock.MagicMock):
    """Tests that no errors occur when no detections are returned."""
    # Mock a successful streaming connection
    mock_session.post.return_value.__enter__.return_value.status_code = 200

    # Make the streamed responses from response.iter_lines() return no results
    mock_session.post.return_value.__enter__.return_value.iter_lines.side_effect = [
        "[]",
    ]

    # Call stream_test_rule
    request_data = {
        "rule.rule_text": "dummy rule content",
        "start_time": "2021-01-01T00:00:00Z",
        "end_time": "2021-01-14T00:00:00Z",
    }
    (
        detections,
        rule_execution_errors,
        disconnection_reason,
    ) = stream_test_rule.stream_test_rule(
        http_session=mock_session, request_data=request_data
    )

    # No detections/rule execution errors should be returned
    self.assertEqual(len(detections), 0)
    self.assertEqual(len(rule_execution_errors), 0)

    # A disconnection reason should not be returned
    self.assertEqual(disconnection_reason, "")


if __name__ == "__main__":
  unittest.main()
