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
"""Unit tests for the "update_data_table" module."""

import unittest
from unittest import mock

from google.auth.transport import requests
from google_secops_api.data_tables.update_data_table import update_data_table


class UpdateDataTableTest(unittest.TestCase):
  """Unit tests for the "update_data_table" module."""

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
      update_data_table(
          http_session=mock_session,
          resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/dataTables/data_table_1",
          update_mask=["description"],
          updates={"my new description"},
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
    expected_data_table = {
        "name": (
            "projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/dataTables/data_table_1"
        ),
        "displayName": "data_table_1",
        "description": "my new description",
        "createTime": "2025-05-15T13:16:45.567170933Z",
        "updateTime": "1970-01-01T00:00:00Z",
        "columnInfo": [
            {"originalColumn": "userid", "columnType": "STRING"},
            {
                "columnIndex": 1,
                "originalColumn": "hostname",
                "columnType": "STRING",
            },
        ],
        "dataTableUuid": "1e738415d4154eb4b95128ab5ed50b9c",
    }
    mock_response.json.return_value = expected_data_table

    updated_data_table = update_data_table(
        http_session=mock_session,
        resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/dataTables/data_table_1",
        update_mask=["description"],
        updates={"my new description"},
    )
    self.assertEqual(updated_data_table, expected_data_table)
