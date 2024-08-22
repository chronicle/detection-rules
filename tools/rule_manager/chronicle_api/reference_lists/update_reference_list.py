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
"""Update an existing reference list.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.referenceLists/patch
"""

import copy
import os
from typing import Mapping, Any

from google.auth.transport import requests


def update_reference_list(
    http_session: requests.AuthorizedSession,
    resource_name: str,
    updates: Mapping[str, Any],
) -> Mapping[str, Any]:
  """Updates an existing reference list.

  Args:
      http_session: Authorized session for HTTP requests.
      resource_name: The resource name of the reference list to retrieve. format:
        projects/{project}/locations/{location}/instances/{instance}/referenceLists/{reference_list_name}
      updates: A dictionary containing the updates to make to the reference
        list. example: A value of {"entries": ["entry1", "entry2"]} will update
        the entries in the reference list accordingly.

  Returns:
      New version of the reference list.

  Raises:
      requests.exceptions.HTTPError: HTTP request resulted in an error
      (response.status_code >= 400).
  """
  url = f"{os.environ['CHRONICLE_API_BASE_URL']}/{resource_name}"
  if updates.get("entries") is not None:
    if len(updates.get("entries")) == 0:  # pylint: disable="g-explicit-length-test"
      # If 'entries' is an empty list, the reference list is empty [{}]
      updates["entries"] = [{}]
    else:
      # Format reference list entries as a list of
      # dictionaries: [{"value": <string>}, ...]
      reference_list_entries = []
      for entry in updates["entries"]:
        reference_list_entries.append({"value": entry.strip()})
      updates["entries"] = copy.deepcopy(reference_list_entries)
  updates["scope_info"] = None  # assumes Data RBAC is disabled
  params = {"updateMask": ",".join(updates.keys)}
  response = http_session.request(
      method="PATCH", url=url, params=params, json=updates
  )

  if response.status_code >= 400:
    print(response.text)
  response.raise_for_status()

  return response.json()
