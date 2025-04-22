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
"""Helper functions to access the Google SecOps API using OAuth 2.0.

Background information:

https://google-auth.readthedocs.io/en/latest/user-guide.html#service-account-private-key-files
https://developers.google.com/identity/protocols/oauth2#serviceaccount

Details about using the Google-auth library with the Requests library:

https://github.com/googleapis/google-auth-library-python/blob/master/google/auth/transport/requests.py
https://requests.readthedocs.io
"""

import json
import logging
import os
from typing import List

import google.auth
from google.auth.transport import requests
from google.oauth2 import service_account

LOGGER = logging.getLogger()

AUTHORIZATION_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def initialize_http_session(
    scopes: List[str] | None = None,
) -> requests.AuthorizedSession:
  """Initializes an authorized HTTP session to make requests to the Google SecOps API.

  Args:
      scopes: A list of OAuth scopes (https://oauth.net/2/scope/) that are
        associated with the endpoints to be accessed. The default is the Google
        SecOps API scope.

  Returns:
      HTTP session object to send authorized requests and receive responses.
  """
  # Attempt to authenticate using Application Default Credentials if environment
  # variable AUTHENTICATION_METHOD is not set (None)
  # Reference: https://googleapis.dev/python/google-auth/latest/user-guide.html#application-default-credentials  # pylint: disable="line-too-long"
  auth_method = os.environ.get(
      "GOOGLE_AUTHENTICATION_TYPE", "APPLICATION_DEFAULT_CREDENTIALS"
  )
  credentials = None

  if auth_method == "APPLICATION_DEFAULT_CREDENTIALS":
    LOGGER.debug(
        "Attempting authentication using Application Default Credentials"
    )
    credentials, _ = google.auth.default(scopes=scopes or AUTHORIZATION_SCOPES)
  elif auth_method == "SERVICE_ACCOUNT_KEY":
    LOGGER.debug("Attempting authentication using service account key")
    credentials = service_account.Credentials.from_service_account_info(
        json.loads(os.environ["GOOGLE_SECOPS_SERVICE_ACCOUNT_KEY"]),
        scopes=scopes or AUTHORIZATION_SCOPES,
    )

  return requests.AuthorizedSession(credentials)
