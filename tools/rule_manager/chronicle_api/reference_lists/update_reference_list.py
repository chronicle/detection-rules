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
import time
from typing import Mapping, Any, List

from google.auth.transport import requests


def update_reference_list(
    http_session: requests.AuthorizedSession,
    resource_name: str,
    updates: Mapping[str, Any],
    update_mask: List[str] | None = None,
    max_retries: int = 3,
) -> Mapping[str, Any]:
  """Updates an existing reference list.

  Args:
      http_session: Authorized session for HTTP requests.
      resource_name: The resource name of the reference list to retrieve. format:
        projects/{project}/locations/{location}/instances/{instance}/referenceLists/{reference_list_name}
      updates: A dictionary containing the updates to make to the reference
        list. example: A value of {"entries": ["entry1", "entry2"]} will update
        the entries in the reference list accordingly.
      update_mask (optional): The list of fields to update for the reference
        list. If no update_mask is provided, all non-empty fields will be
        updated. example: An update_mask of ["entries"] will update the entries
        for a reference list.
      max_retries (optional): Maximum number of times to retry HTTP request if
        certain response codes are returned. For example: HTTP response status
        code 429 (Too Many Requests)

  Returns:
      New version of the reference list.

  Raises:
      requests.exceptions.HTTPError: HTTP request resulted in an error
      (response.status_code >= 400).
  """
  url = f"{os.environ['CHRONICLE_API_BASE_URL']}/{resource_name}"
  response = None

  # If no update_mask is provided, all non-empty fields will be updated
  if update_mask is None:
    params = {}
  else:
    params = {"updateMask": update_mask}

  if updates.get("entries") is not None:
    if len(updates.get("entries")) == 0:  # pylint: disable=g-explicit-length-test
      # If 'entries' is an empty list, the reference list is empty [{}]
      updates["entries"] = [{}]
    else:
      # Format reference list entries as a list of
      # dictionaries: [{"value": <string>}, ...]
      reference_list_entries = []
      for entry in updates["entries"]:
        reference_list_entries.append({"value": entry.strip()})
      updates["entries"] = copy.deepcopy(reference_list_entries)

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
