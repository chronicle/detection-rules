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
"""Update an existing saved search.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.users.searchQueries/patch
"""

import logging
import os
import time
from typing import Any, Mapping

from google.auth.transport import requests


LOGGER = logging.getLogger()


def update_saved_search(
    http_session: requests.AuthorizedSession,
    resource_name: str,
    updates: Mapping[str, Any],
    update_mask: list[str] | None = None,
    max_retries: int = 3,
) -> Mapping[str, Any]:
  """Updates an existing saved search.

  Args:
    http_session: Authorized session for HTTP requests.
    resource_name: The resource name of the saved search to update. Format:
      projects/{project}/locations/{location}/instances/{instance}/users/me/searchQueries/{saved_search_uuid}
    updates: A dictionary containing the updates to make to the saved search
      Example - A value of {"description": "My new saved search description"}
      will update the description for the saved search accordingly.
    update_mask (optional): The list of fields to update for the saved search.
      If no update_mask is provided, all non-empty fields will be updated.
      Example - An update_mask of ["description"] will update the description
      for the saved search.
    max_retries (optional): Maximum number of times to retry HTTP request if
      certain response codes are returned. For example: HTTP response status
      code 429 (Too Many Requests)

  Returns:
    New version of the saved search.

  Raises:
    requests.exceptions.HTTPError: HTTP request resulted in an error
    (response.status_code >= 400).
    requests.exceptions.JSONDecodeError: If the server response is not valid
    JSON.
  """
  url = f"{os.environ['GOOGLE_SECOPS_API_BASE_URL']}/{resource_name}"
  response = None

  # If no update_mask is provided, all non-empty fields will be updated
  if update_mask is None:
    params = {}
  else:
    params = {"updateMask": update_mask}

  for _ in range(max(max_retries, 0) + 1):
    response = http_session.request(
        method="PATCH", url=url, params=params, json=updates
    )

    if response.status_code >= 400:
      LOGGER.warning(response.text)

    if response.status_code == 429:
      LOGGER.warning("API rate limit exceeded. Sleeping for 60s before retrying")
      time.sleep(60)
    else:
      break

  response.raise_for_status()

  return response.json()
