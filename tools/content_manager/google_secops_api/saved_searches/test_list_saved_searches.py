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
"""Unit tests for the "list_saved_searches" module."""

import unittest
from unittest import mock

from google.auth.transport import requests
from google_secops_api.saved_searches.list_saved_searches import list_saved_searches


class ListSavedSearchesTest(unittest.TestCase):
  """Unit tests for the "list_saved_searches" module."""

  @mock.patch.object(target=requests, attribute="AuthorizedSession", autospec=True)
  @mock.patch.object(target=requests.requests, attribute="Response", autospec=True)
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
      list_saved_searches(http_session=mock_session)

  @mock.patch.object(target=requests, attribute="AuthorizedSession", autospec=True)
  @mock.patch.object(target=requests.requests, attribute="Response", autospec=True)
  def test_http_ok(
      self,
      mock_response: unittest.mock.MagicMock,
      mock_session: unittest.mock.MagicMock,
  ):
    """Test that HTTP response 200 (OK) occurs."""
    mock_session.request.return_value = mock_response
    type(mock_response).status_code = mock.PropertyMock(return_value=200)
    expected_saved_search = {
        "name": "projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/users/me/searchQueries/baf471b7-067f-4a73-91c4-8c3ff0c0c29c",
        "metadata": {
            "createTime": "2025-11-10T16:27:10.139428Z",
            "updateTime": "2025-11-10T16:27:10.139428Z",
        },
        "displayName": "Windows Login Events",
        "query": 'metadata.vendor_name = "Microsoft" AND metadata.product_name = /Windows/ AND metadata.event_type = "USER_LOGIN"',
        "queryId": "Ab9e5XWvQTu46prKxvQx6Q==",
        "userId": "player1@example.com",
        "description": "Windows user login events",
    }
    expected_page_token = "page token here"
    mock_response.json.return_value = {
        "searchQueries": [expected_saved_search],
        "nextPageToken": expected_page_token,
    }

    saved_searches, next_page_token = list_saved_searches(http_session=mock_session)
    self.assertEqual(len(saved_searches), 1)
    self.assertEqual(saved_searches[0], expected_saved_search)
    self.assertEqual(next_page_token, expected_page_token)
