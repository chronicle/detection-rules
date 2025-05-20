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
"""Create data table rows in bulk.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.dataTables.dataTableRows/bulkCreate
"""

import logging
import os
import time
from typing import Any, Mapping, Sequence

from google.auth.transport import requests

LOGGER = logging.getLogger()


def bulk_create_data_table_rows(
    http_session: requests.AuthorizedSession,
    resource_name: str,
    row_values: Sequence[Sequence[str]],
    max_retries: int = 3,
) -> Mapping[str, Any]:
  """Create data table rows in bulk.

  Args:
    http_session: Authorized session for HTTP requests.
    resource_name: The resource name of the data table to create rows for.
      Format -
      projects/{project}/locations/{location}/instances/{instance}/dataTables/{data_table_name}
    row_values: The values for the row. These values should be in the same order
      as data table's columns. Example: [["user1", "desktop1"], ["user2",
      "desktop2"]] A maximum of 1,000 rows can be created in a single request.
    max_retries (optional): Maximum number of times to retry HTTP request if
      certain response codes are returned. For example: HTTP response status
      code 429 (Too Many Requests)

  Returns:
    New data table rows.

  Raises:
    requests.exceptions.HTTPError: HTTP request resulted in an error
    (response.status_code >= 400).
    requests.exceptions.JSONDecodeError: If the server response is not valid
    JSON.
  """
  url = f"{os.environ['GOOGLE_SECOPS_API_BASE_URL']}/{resource_name}/dataTableRows:bulkCreate"

  # Populate a list of data table row requests. Reference:
  # https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.dataTables.dataTableRows/bulkCreate#CreateDataTableRowRequest
  data_table_row_requests = []
  for row in row_values:
    data_table_row_requests.append({
        "parent": resource_name,
        "data_table_row": {"values": row},
    })

  body = {"requests": data_table_row_requests}

  response = None

  for _ in range(max(max_retries, 0) + 1):
    response = http_session.request(method="POST", url=url, json=body)

    if response.status_code >= 400:
      LOGGER.warning(response.text)

    if response.status_code == 429:
      LOGGER.warning(
          "API rate limit exceeded. Sleeping for 60s before retrying"
      )
      time.sleep(60)
    else:
      break

  response.raise_for_status()

  return response.json()
