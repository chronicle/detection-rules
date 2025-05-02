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
"""Create a new reference list.

API reference:
https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.referenceLists/create
"""

import logging
import os
import time
from typing import Any, Mapping, Sequence

from google.auth.transport import requests

LOGGER = logging.getLogger()


def create_reference_list(
    http_session: requests.AuthorizedSession,
    name: str,
    description: str,
    entries: Sequence[str | None],
    syntax_type: str | None = None,
    max_retries: int = 3,
) -> Mapping[str, Any]:
  """Creates a new reference list.

  Args:
    http_session: Authorized session for HTTP requests.
    name: The name for the new reference list.
    description: A user-provided description of the reference list.
    entries: A list of entries for the reference list.
    syntax_type: The syntax type indicating how list entries should be
      validated. Reference:
      https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.referenceLists#ReferenceListSyntaxType
    max_retries (optional): Maximum number of times to retry HTTP request if
      certain response codes are returned. For example: HTTP response status
      code 429 (Too Many Requests)

  Returns:
    New reference list.

  Raises:
    requests.exceptions.HTTPError: HTTP request resulted in an error
    (response.status_code >= 400).
    requests.exceptions.JSONDecodeError: If the server response is not valid
    JSON.
  """
  url = f"{os.environ['GOOGLE_SECOPS_API_BASE_URL']}/{os.environ['GOOGLE_SECOPS_INSTANCE']}/referenceLists"
  params = {"referenceListId": name}
  response = None

  if not entries:
    # If 'entries' is an empty list, the reference list is empty [{}]
    reference_list_entries = [{}]
  else:
    # Format reference list entries as a list of
    # dictionaries: [{"value": <string>}, ...]
    reference_list_entries = []
    for entry in entries:
      reference_list_entries.append({"value": entry.strip()})

  body = {
      "description": description,
      "entries": reference_list_entries,
      "syntax_type": syntax_type,
  }

  for _ in range(max(max_retries, 0) + 1):
    response = http_session.request(
        method="POST", url=url, json=body, params=params
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
