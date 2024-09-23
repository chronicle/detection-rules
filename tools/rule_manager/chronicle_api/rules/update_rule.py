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
"""Update an existing rule.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.rules/patch
"""

import os
import time
from typing import Any, Mapping, List

from google.auth.transport import requests


def update_rule(
    http_session: requests.AuthorizedSession,
    resource_name: str,
    update_mask: List[str],
    updates: Mapping[str, Any],
    max_retries: int = 3,
) -> Mapping[str, Any]:
  """Updates an existing rule.

  Args:
    http_session: Authorized session for HTTP requests.
    resource_name: The resource name of the rule to update. Format -
      projects/{project}/locations/{location}/instances/{instance}/rules/{rule_id}
    update_mask: The list of fields to update for the rule. For example, an
      update_mask of ["text"] will update the text field for a rule i.e. create
      a new version for the rule.
    updates: A dictionary containing the updates to make to the rule. For
      example, a value of {"text": "New YARA-L 2.0 rule"} will update the text
      field for the rule i.e. create a new version for the rule.
    max_retries (optional): Maximum number of times to retry HTTP request if
      certain response codes are returned. For example: HTTP response status
      code 429 (Too Many Requests)

  Returns:
    New version of the rule.

  Raises:
    requests.exceptions.HTTPError: HTTP request resulted in an error
    (response.status_code >= 400).
  """
  url = f"{os.environ['CHRONICLE_API_BASE_URL']}/{resource_name}"
  params = {"updateMask": update_mask}
  response = None

  for _ in range(max_retries + 1):
    response = http_session.request(
        method="PATCH", url=url, params=params, json=updates
    )

    if response.status_code >= 400:
      print(response.text)

    if response.status_code == 429:
      print("API rate limit exceeded. Sleeping for 60s before retrying")
      time.sleep(60)
    else:
      break

  response.raise_for_status()

  return response.json()
