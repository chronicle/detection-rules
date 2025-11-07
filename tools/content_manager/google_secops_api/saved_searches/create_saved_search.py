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
"""Create a new saved search.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.users.searchQueries/create
"""

import logging
import os
import time
from typing import Any, Mapping

from google.auth.transport import requests

LOGGER = logging.getLogger()


def create_saved_search(
    http_session: requests.AuthorizedSession,
    name: str,
    query: str,
    description: str | None = None,
    sharing_mode: str | None = None,
    placeholder_names: list[str] | None = None,
    placeholder_descriptions: list[str] | None = None,
    max_retries: int = 3,
) -> Mapping[str, Any]:
  """Creates a new saved search.

  Args:
    http_session: Authorized session for HTTP requests.
    name: The unique display name for the new saved search.
    query: The query for the saved search.
      Reference - https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.users.searchQueries#SearchQuery
    description (optional): A user-provided description of the saved search.
    sharing_mode (optional): The sharing mode for the saved search.
      Reference - https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.users.searchQueries#SharingMode
    placeholder_names (optional): A list of names for the query placeholders to
      be shown in the UI. Each elemeent's position corresponds to the
      description in the placeholder_descriptions field.
    placeholder_descriptions (optional): A list of descriptions for the query
      placeholders to be shown in the UI. Each elemeent's position corresponds
      to the name in the placeholder_names field.
    max_retries (optional): Maximum number of times to retry HTTP request if
      certain response codes are returned. For example: HTTP response status
      code 429 (Too Many Requests)

  Returns:
    New saved search.

  Raises:
    requests.exceptions.HTTPError: HTTP request resulted in an error
    (response.status_code >= 400).
    requests.exceptions.JSONDecodeError: If the server response is not valid
    JSON.
  """
  url = f"{os.environ['GOOGLE_SECOPS_API_BASE_URL']}/{os.environ['GOOGLE_SECOPS_INSTANCE']}/users/me/searchQueries"
  body = {
      "display_name": name,
      "description": description,
      "query": query,
      "placeholder_names": placeholder_names,
      "placeholder_descriptions": placeholder_descriptions,
      "metadata": {"sharing_mode": sharing_mode},
      }
  response = None

  for _ in range(max(max_retries, 0) + 1):
    response = http_session.request(method="POST", url=url, json=body)

    if response.status_code >= 400:
      LOGGER.warning(response.text)

    if response.status_code == 429:
      LOGGER.warning("API rate limit exceeded. Sleeping for 60s before retrying")
      time.sleep(60)
    else:
      break

  response.raise_for_status()

  return response.json()
