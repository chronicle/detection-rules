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
"""Create a new findings refinement.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.findingsRefinements/create
"""

import logging
import os
import time
from typing import Any, Mapping

from google.auth.transport import requests

LOGGER = logging.getLogger()


def create_findings_refinement(
    http_session: requests.AuthorizedSession,
    display_name: str,
    findings_refinement_type: str,
    query: str,
    max_retries: int = 3,
) -> Mapping[str, Any]:
  """Creates a new findings refinement.

  Args:
    http_session: Authorized session for HTTP requests.
    display_name: Display name for the findings refinement
    findings_refinement_type: The type of findings refinement to create.
      Reference
      https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.findingsRefinements#FindingsRefinementType
    query: The query for the findings refinement. Works in conjunction with the
      type field to determine the findings refinement behavior. The syntax of
      this query is the same as a UDM search string.
    max_retries (optional): Maximum number of times to retry HTTP request if
      certain response codes are returned. For example: HTTP response status
      code 429 (Too Many Requests)

  Returns:
    New findings refinement. Reference:
      https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.findingsRefinements#FindingsRefinement

  Raises:
    requests.exceptions.HTTPError: HTTP request resulted in an error
    (response.status_code >= 400).
    requests.exceptions.JSONDecodeError: If the server response is not valid
    JSON.
  """
  url = f"{os.environ['GOOGLE_SECOPS_API_BASE_URL']}/{os.environ['GOOGLE_SECOPS_INSTANCE']}/findingsRefinements"
  body = {
      "display_name": display_name,
      "type": findings_refinement_type,
      "query": query,
  }
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
