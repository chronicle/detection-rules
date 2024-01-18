# Copyright 2023 Google LLC
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
"""Retrieve a rule.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.rules/get
"""

import os
from typing import Any, Mapping

from google.auth.transport import requests


def get_rule(
    http_session: requests.AuthorizedSession, resource_name: str
) -> Mapping[str, Any]:
  """Retrieves a rule.

  Args:
    http_session: Authorized session for HTTP requests.
    resource_name: The resource name of the rule to retrieve. Format -
      projects/{project}/locations/{location}/instances/{instance}/rules/{rule_id}

  Returns:
    Content and metadata about the requested rule.

  Raises:
    requests.exceptions.HTTPError: HTTP request resulted in an error
      (response.status_code >= 400).
  """
  url = f"{os.environ['CHRONICLE_API_BASE_URL']}/{resource_name}"

  response = http_session.request(method="GET", url=url)

  if response.status_code >= 400:
    print(response.text)
    response.raise_for_status()

  return response.json()
