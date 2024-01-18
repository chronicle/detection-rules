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
"""Helper functions to access Chronicle API using OAuth 2.0.

Background information:

https://google-auth.readthedocs.io/en/latest/user-guide.html#service-account-private-key-files
https://developers.google.com/identity/protocols/oauth2#serviceaccount

Details about using the Google-auth library with the Requests library:

https://github.com/googleapis/google-auth-library-python/blob/master/google/auth/transport/requests.py
https://requests.readthedocs.io
"""

from typing import List

from google.auth.transport import requests
from google.oauth2 import service_account

AUTHORIZATION_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def initialize_http_session(
    chronicle_api_credentials: str, scopes: List[str] | None = None
) -> requests.AuthorizedSession:
  """Initializes an authorized HTTP session, based on the given credentials.

  Args:
    chronicle_api_credentials: The private service account info in Google
      format.
    scopes: A list of OAuth scopes (https://oauth.net/2/scope/) that are
      associated with the endpoints to be accessed. The default is the
      Chronicle API scope.

  Returns:
      HTTP session object to send authorized requests and receive responses.
  """
  credentials = service_account.Credentials.from_service_account_info(
      info=chronicle_api_credentials, scopes=scopes or AUTHORIZATION_SCOPES
  )

  return requests.AuthorizedSession(credentials)
