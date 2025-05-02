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
"""Retrieve a list of findings refinement deployment states.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances/listAllFindingsRefinementDeployments
"""

import logging
import os
import time
from typing import Any, List, Mapping, Tuple

from google.auth.transport import requests

LOGGER = logging.getLogger()


def list_findings_refinement_deployments(
    http_session: requests.AuthorizedSession,
    page_size: int | None = None,
    page_token: str | None = None,
    max_retries: int = 3,
) -> Tuple[List[Mapping[str, Any]], str]:
  """Retrieve a list of findings refinement deployment states.

  Args:
    http_session: Authorized session for HTTP requests.
    page_size (optional): Maximum number of findings refinement deployments to
      return. A server-side default of 100 is used if the size is 0 or a None
      value. The maximum value is 1,000.
    page_token (optional): Page token from a previous
      ListAllFindingsRefinementDeployments call used for pagination. The first
      page is retrieved if the token is the empty string or a None value.
    max_retries (optional): Maximum number of times to retry HTTP request if
      certain response codes are returned. For example: HTTP response status
      code 429 (Too Many Requests)

  Returns:
    List of findings refinement deployments and a page token for the next page
    of findings refinement deployments, if there are any.

  Raises:
    requests.exceptions.HTTPError: HTTP request resulted in an error
    (response.status_code >= 400).
    requests.exceptions.JSONDecodeError: If the server response is not valid
    JSON.
  """
  url = f"{os.environ['GOOGLE_SECOPS_API_BASE_URL']}/{os.environ['GOOGLE_SECOPS_INSTANCE']}:listAllFindingsRefinementDeployments"
  params = {"page_size": page_size, "page_token": page_token}
  response = None

  for _ in range(max(max_retries, 0) + 1):
    response = http_session.request(method="GET", url=url, params=params)

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

  response_json = response.json()

  return response_json.get(
      "allFindingsRefinementDeployments"
  ), response_json.get("nextPageToken")
