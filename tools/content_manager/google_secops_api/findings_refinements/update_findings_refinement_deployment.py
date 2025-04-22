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
"""Update the deployment state for a findings refinement.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.findingsRefinements/updateDeployment
"""

import logging
import os
import time
from typing import Any, Mapping

from google.auth.transport import requests

LOGGER = logging.getLogger()


def update_refinement_findings_deployment(
    http_session: requests.AuthorizedSession,
    resource_name: str,
    update_mask: list[str],
    updates: Mapping[str, Any],
    max_retries: int = 3,
) -> Mapping[str, Any]:
  """Update the deployment state for a findings refinement.

  Args:
    http_session: Authorized session for HTTP requests.
    resource_name: The resource name of the findings refinement deployment to
      update. Format:
      projects/{project}/locations/{location}/instances/{instance}/findingsRefinements/{findings_refinement_id}/deployment
    update_mask: The list of fields to update in the finding refinement's
      deployment state. Example - An update_mask of ["archived","enabled"] will
      update the finding refinement's archived and enabled state.
    updates: A dictionary containing the updates to the finding refinement's
      deployment state. Example: A value of {"archived": False, "enabled": True}
      will unarchive and enable the findings refinement.
    max_retries (optional): Maximum number of times to retry HTTP request if
      certain response codes are returned. For example: HTTP response status
      code 429 (Too Many Requests)

  Returns:
    The finding refinement's deployment state. Reference:
    https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/FindingsRefinementDeployment

  Raises:
    requests.exceptions.HTTPError: HTTP request resulted in an error
    (response.status_code >= 400).
    requests.exceptions.JSONDecodeError: If the server response is not valid
    JSON.
  """
  url = f"{os.environ['GOOGLE_SECOPS_API_BASE_URL']}/{resource_name}/deployment"
  params = {"updateMask": update_mask}
  response = None

  for _ in range(max(max_retries, 0) + 1):
    response = http_session.request(
        method="PATCH", url=url, params=params, json=updates
    )

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
