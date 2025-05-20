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
"""Unit tests for the "upload_data_table" module."""

import pathlib
import tempfile
import unittest
from unittest import mock

from google.auth.transport import requests
from google_secops_api.data_tables.upload_data_table import upload_data_table


class UploadDataTableTest(unittest.TestCase):
  """Unit tests for the "upload_data_table" module."""

  def setUp(self):
    """Set up for each test method."""
    super().setUp()
    self.temp_dir_obj = tempfile.TemporaryDirectory()
    temp_dir_path = pathlib.Path(self.temp_dir_obj.name)
    self.data_table_file_path = temp_dir_path / "data_table_1.csv"
    self.data_table_file_path.touch()

  def tearDown(self):
    """Clean up after each test method."""
    # Explicitly clean up the temporary directory
    super().tearDown()
    self.temp_dir_obj.cleanup()

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
      upload_data_table(
          http_session=mock_session,
          name="data_table_1",
          description="data table description",
          column_info=[
              {
                  "column_index": 0,
                  "column_type": "STRING",
                  "original_column": "userid",
              },
              {
                  "column_index": 1,
                  "column_type": "STRING",
                  "original_column": "hostname",
              },
          ],
          file_path=self.data_table_file_path,
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
        "operation": {
            "name": (
                "projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/dataTables/data_table_1"
            ),
            "metadata": {
                "@type": (
                    "type.googleapis.com/google.cloud.chronicle.v1main.OperationMetadata"
                ),
                "state": "QUEUEING",
            },
        }
    }
    mock_response.json.return_value = expected_response

    response = upload_data_table(
        http_session=mock_session,
        name="data_table_1",
        description="data table description",
        column_info=[
            {
                "column_index": 0,
                "column_type": "STRING",
                "original_column": "userid",
            },
            {
                "column_index": 1,
                "column_type": "STRING",
                "original_column": "hostname",
            },
        ],
        file_path=self.data_table_file_path,
    )
    self.assertEqual(expected_response, response)
