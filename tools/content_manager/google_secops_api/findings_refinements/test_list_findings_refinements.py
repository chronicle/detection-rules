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
"""Unit tests for the "list_findings_refinements" module."""

import unittest
from unittest import mock

from google.auth.transport import requests
from google_secops_api.findings_refinements.list_findings_refinements import (
    list_findings_refinements,
)


class ListRulesTest(unittest.TestCase):
  """Unit tests for the "list_findings_refinements" module."""

  @mock.patch.object(
      target=requests, attribute="AuthorizedSession", autospec=True
  )
  @mock.patch.object(
      target=requests.requests, attribute="Response", autospec=True
  )
  def test_http_error(
      self,
      mock_response: unittest.mock.MagicMock,
      mock_session: unittest.mock.MagicMock,
  ):
    """Test that an HTTP error occurs."""
    mock_session.request.return_value = mock_response
    type(mock_response).status_code = mock.PropertyMock(return_value=400)
    mock_response.raise_for_status.side_effect = (
        requests.requests.exceptions.HTTPError()
    )

    with self.assertRaises(requests.requests.exceptions.HTTPError):
      list_findings_refinements(http_session=mock_session)

  @mock.patch.object(
      target=requests, attribute="AuthorizedSession", autospec=True
  )
  @mock.patch.object(
      target=requests.requests, attribute="Response", autospec=True
  )
  def test_http_ok(
      self,
      mock_response: unittest.mock.MagicMock,
      mock_session: unittest.mock.MagicMock,
  ):
    """Test that HTTP response 200 (OK) occurs."""
    mock_session.request.return_value = mock_response
    type(mock_response).status_code = mock.PropertyMock(return_value=200)
    expected_rule_exclusion = {
        "name": (
            "projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/findingsRefinements/fr_caf666f6-bf55-45c9-8c25-7283616d00dc"
        ),
        "displayName": "Test 1",
        "type": "DETECTION_EXCLUSION",
        "createTime": "2025-03-11T15:19:39.156463Z",
        "updateTime": "2025-03-11T15:19:39.156463Z",
        "query": '(principal.user.userid = "56409778")',
    }
    expected_page_token = "page token here"
    mock_response.json.return_value = {
        "findingsRefinements": [expected_rule_exclusion],
        "nextPageToken": expected_page_token,
    }

    retrieved_rule_exclusions, next_page_token = list_findings_refinements(
        http_session=mock_session
    )
    self.assertEqual(len(retrieved_rule_exclusions), 1)
    self.assertEqual(retrieved_rule_exclusions[0], expected_rule_exclusion)
    self.assertEqual(next_page_token, expected_page_token)
