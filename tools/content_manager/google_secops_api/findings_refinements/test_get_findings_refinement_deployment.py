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
"""Unit tests for the "get_findings_refinement_deployment" module."""

import unittest
from unittest import mock

from google.auth.transport import requests
from google_secops_api.findings_refinements.get_findings_refinement_deployment import (
    get_findings_refinement_deployment,
)


class GetRuleDeploymentTest(unittest.TestCase):
  """Unit tests for the "get_findings_refinement_deployment" module."""

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
      get_findings_refinement_deployment(
          http_session=mock_session,
          resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/findingsRefinements/fr_7415c05b-3b34-4de5-9de8-73b46e0ee912/deployment",
      )

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
    expected_response = {
        "name": (
            "projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/findingsRefinements/fr_7415c05b-3b00-4de5-9de8-73b46e0ee958/deployment"
        ),
        "updateTime": "2025-03-07T17:37:46.650463Z",
        "detectionExclusionApplication": {
            "curatedRuleSets": [
                "projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/curatedRuleSetCategories/110fa43d-7165-2355-1985-a63b7cdf90e8/curatedRuleSets/11c505d4-b424-65e3-d918-1a81232cc76b"
            ]
        },
    }
    mock_response.json.return_value = expected_response

    response = get_findings_refinement_deployment(
        http_session=mock_session,
        resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/findingsRefinements/fr_7415c05b-3b00-4de5-9de8-73b46e0ee958",
    )
    self.assertEqual(response, expected_response)
