# Copyright 2021 Google LLC
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
"""Unit tests for the "evaluate_rules" module."""

import datetime
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from google.auth.transport import requests

import evaluate_rules


class InitHttpSessionTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    fd, self.path = tempfile.mkstemp(suffix=".json", text=True)
    fake_json_credentials = b"""{
        "client_email": "fake-username@fake-project.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.googleapis.com/token",
        "private_key": "
    """
    fake_private_key = b"""-----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDemycWcEiVMMKm
        /S3f8oRkgxVvbi14D0TWFBUPZq9w1nc7L4Udz7NZ8BKC49DuKi1EgwxF8z0Bve5i
        k6UMfb4JeXLkSSQN4Zy5IbZUr9Mm3w0sjIzTeA1JmIqY+r3EbUxeqFjpqc02HW4h
        j0L7Wj2on9KTvMd0zFRCsLLz7KoZyykDKW3jbvDBNx9n3uUNBb+ZriYNbuAWCSlC
        XD8QbVHq3dqFQFpsofHknDX/+UUS7Q85War4Y2qqdV7SwtTdy2LoNHKLLBHU0WMG
        8x6PZueahkO2tipebJN6js4tSxSyk8sYFkU6onZJV91ysE+7QuS0HdhHTYfZSnC5
        zHmJgyHVAgMBAAECggEABWtajsHKCpPG0WDtinuxfG7yiSVyBu+8OcgAYUEbOVCH
        U5ILGBgz4hclpDken4W4V2gnVtaeoBm7IXw9summxD1ILkWXkpzw/1LSSQqExff9
        Lp33Wbic/jMwAJxuHUeZ6d4IWBvxqoUZ5shBlbPzN1U4v68DXhURYhRCLw0OcRVE
        9I3Ohwy6MntjHAkNTvFrYxQBUnCsTKFKwkimn6huhwE8/nrMpYS8H/8DxPFsBprw
        AznRqWWfJ28yVoEzN+J1aIz631zk+LwSqY0m/TJra1uwMQ5J6bYqWlH8pS/UaI4s
        6Lbhukubpi7P03XpP1aHMwCpwcsZ6hGD7XpELDZBgQKBgQD8fF2lgDcX0ksvcgk2
        KKy4dPqwcONfB41lxbIYE9JZRo3hiWsAwQxfbW6Zt6cEdEqOnROw0jcaJhaKD+qf
        d14ciUA+NjeHyE1yJjbytOnO7fx5wlVamHUI0ykFH4NoN+GOI7zt3kLIb20Zvqab
        4Dt5e5qY5s+Mnr2wJVI8k4NcQQKBgQDhtFJ38bz7ehl9prTQ1AaAxAviU3XOBkko
        uDTglE2aoKjc3qoWoX6vT0iamsM3EYYVZxxbqzjSUCrhpSetKdP/NZNN3mtMvFzj
        ODXyhC43Ro3fVe+JvHzdxRtXbSwZ2GLmkbR8oyi7w4pU8rx9+/UfFOoiqcLIGQbb
        N03t8TJwlQKBgB2fVblaHpyb3phVb8E76m/Fwbe7tuFqWGuNU0TB5pb00SaZ4cT3
        4US86RH92wmJv0mWIj5Hm5Fk0JYoIeXNsmv0qmXiJIe4t2ViGGZHVXsirtF2PF9h
        rbF4XMKuHNO4Yq0zgjICNqGfeRRhKtj06OVq3At+YPFlmmm1Jz3WLL5BAoGAQ3hL
        Gs3px2cVjaky7iYjl4SDZPG8Co14ezKto+DRXgLe17+8Kq22GCPkOUtARgr4ARfk
        s0Z44u3SE8fyF2Kkm+rhEOsHOlYokkfwYIHA6wctS/D9fTgaP5U3eigJgeRclD5E
        LOn9ODvY81HopOSXvuXao+gJcRWCJi/fHNz4Tg0CgYEA0ruTbieHIzCjg8C1Sp40
        GBixMpHsZ2ld1OaqQvidYIUL48TutyQhWHaRIqaziSZJBaNIYB73pIQfLdHIi0hx
        3KHskc16JPhKgWLsl9cTP5GAIP2cqvSqBmnbvX+ArSRbqy4v7kxJwKPai+iaFi5H
        1njcNc79W7qohKZshYNUq/0=
        -----END PRIVATE KEY-----
    """
    fake_private_key = fake_private_key.replace(b" " * 4, b"")
    fake_private_key = fake_private_key.replace(b"\n", b"\\n")
    os.write(fd, fake_json_credentials.strip() + fake_private_key + b'"\n}\n')
    os.close(fd)

  def test_initialize_http_session_with_custom_json_credentials(self):
    evaluate_rules.initialize_http_session(self.path)

  def tearDown(self):
    os.remove(self.path)
    super().tearDown()


class FakeResponse(object):

  def __init__(self, status_code: int):
    self.status_code = status_code
    self.text = "text"

  def raise_for_status(self):
    if self.status_code >= 400:
      raise RuntimeError()

  def json(self) -> str:
    return "json"


@evaluate_rules.api_decorator
def api_function_throttle():
  return FakeResponse(200)


@evaluate_rules.api_decorator
def api_function_error():
  return FakeResponse(400)


class EvaluateRulesTest(unittest.TestCase):

  def test_initialize_command_line_args_sanity_checks(self):
    self.assertIsNone(
        evaluate_rules.initialize_command_line_args(["-in=foo", "-ig=bar"]))
    self.assertIsNone(
        evaluate_rules.initialize_command_line_args(
            ["-ts", "2021-01-02T03:04:05", "-te", "2020-01-02T03:04:05"]))
    self.assertIsNone(
        evaluate_rules.initialize_command_line_args(["--save_results"]))
    self.assertIsNotNone(
        evaluate_rules.initialize_command_line_args(["--run_retrohunt"]))

  def test_parse_files_list_empty(self):
    self.assertEqual([], evaluate_rules.parse_files_list(""))

  def test_parse_files_list_regular(self):
    self.assertEqual(["a"], evaluate_rules.parse_files_list("a"))
    self.assertEqual(["a", "b"], evaluate_rules.parse_files_list("a,b"))

  def test_parse_files_list_discard_empty_elements(self):
    self.assertEqual(["c", "d"], evaluate_rules.parse_files_list(",c,,d,"))

  def test_is_file_in_scope_empty(self):
    path = pathlib.Path("abc/def/ghi.yaral")
    self.assertTrue(evaluate_rules.is_file_in_scope(path, [], []))

  def test_is_file_in_scope_include(self):
    path = pathlib.Path("abc/def/ghi.yaral")
    self.assertTrue(evaluate_rules.is_file_in_scope(path, ["ghi"], []))
    self.assertTrue(evaluate_rules.is_file_in_scope(path, ["ghi", "xyz"], []))

    self.assertFalse(evaluate_rules.is_file_in_scope(path, ["xyz"], []))

  def test_is_file_in_scope_ignore(self):
    path = pathlib.Path("abc/def/ghi.yaral")
    self.assertFalse(evaluate_rules.is_file_in_scope(path, [], ["def"]))
    self.assertFalse(evaluate_rules.is_file_in_scope(path, [], ["def", "xyz"]))

    self.assertTrue(evaluate_rules.is_file_in_scope(path, [], ["xyz"]))

  @mock.patch.object(requests, "AuthorizedSession", autospec=True)
  @mock.patch.object(evaluate_rules, "create_rule", autospec=True)
  def test_evaluate_file_succeeded(self, mock_create_rule, mock_session):
    path = next(pathlib.Path.cwd().rglob("*.yaral"))
    mock_create_rule.return_value = {
        "ruleId": "ruleId",
        "ruleName": "ruleName",
        "compilationState": "SUCCEEDED",
    }
    evaluate_rules.evaluate_file(mock_session, path, 1)
    mock_create_rule.assert_called_once()

  @mock.patch.object(requests, "AuthorizedSession", autospec=True)
  @mock.patch.object(evaluate_rules, "create_rule", autospec=True)
  def test_evaluate_file_failed(self, mock_create_rule, mock_session):
    path = next(pathlib.Path.cwd().rglob("*.yaral"))
    mock_create_rule.return_value = {
        "ruleId": "ruleId",
        "ruleName": "ruleName",
        "compilationState": "FAILED",
        "compilationError": "compilationError",
    }
    evaluate_rules.evaluate_file(mock_session, path, 2)
    mock_create_rule.assert_called_once()

  @mock.patch.object(requests, "AuthorizedSession", autospec=True)
  @mock.patch.object(evaluate_rules, "start_retrohunt", autospec=True)
  @mock.patch.object(evaluate_rules, "poll_retrohunt", autospec=True)
  @mock.patch.object(evaluate_rules, "list_detections", autospec=True)
  def test_run_rule(self, mock_list_detections, mock_poll_retrohunt,
                    mock_start_retrohunt, mock_session):
    start_time = "2020-01-02T03:04:05Z"
    end_time = "2021-01-02T03:04:05Z"
    rule = {
        "versionId": "versionId",
    }
    mock_start_retrohunt.return_value = {
        "retrohuntStartTime": start_time,
        "state": "RUNNING",
        "retrohuntId": "retrohuntId",
        "progressPercentage": 50,
    }
    mock_poll_retrohunt.return_value = {
        "retrohuntStartTime": start_time,
        "retrohuntEndTime": end_time,
        "state": "DONE",
        "retrohuntId": "retrohuntId",
        "progressPercentage": 100,
    }
    mock_list_detections.return_value = {}
    evaluate_rules.run_rule(mock_session, rule, start_time, end_time)
    mock_start_retrohunt.assert_called_once()
    mock_poll_retrohunt.assert_called_once()
    mock_list_detections.assert_called_once()

  @mock.patch.object(requests, "AuthorizedSession", autospec=True)
  @mock.patch.object(evaluate_rules, "list_detections", autospec=True)
  def test_retrieve_detections(self, mock_list_detections, mock_session):
    mock_list_detections.side_effect = [{"nextPageToken": "nextPageToken"}, {}]
    evaluate_rules.retrieve_detections(mock_session, "rule version ID")
    mock_list_detections.assert_called()

  def test_save_detection_results_empty(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      path = pathlib.Path(f"{temp_dir}/rule_file.yaral")
      evaluate_rules.save_detection_results(path, {})

  def test_save_detection_results_non_empty(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      path = pathlib.Path(f"{temp_dir}/rule_file.yaral")
      evaluate_rules.save_detection_results(path, {"foo": "bar"})

  def test_api_decorator_throttle(self):
    self.assertEqual("json", api_function_throttle())

  def test_api_decorator_error(self):
    with self.assertRaises(RuntimeError):
      api_function_error()

  @mock.patch.object(requests, "AuthorizedSession", autospec=True)
  @mock.patch.object(requests.requests, "Response", autospec=True)
  def test_create_rule(self, mock_response, mock_session):
    mock_session.request.return_value = mock_response
    type(mock_response).status_code = mock.PropertyMock(return_value=200)
    mock_response.json.return_value = "json"

    actual = evaluate_rules.create_rule(mock_session, "new rule content")
    self.assertEqual("json", actual)

  @mock.patch.object(requests, "AuthorizedSession", autospec=True)
  @mock.patch.object(requests.requests, "Response", autospec=True)
  def test_delete_rule(self, mock_response, mock_session):
    mock_session.request.return_value = mock_response
    type(mock_response).status_code = mock.PropertyMock(return_value=200)
    mock_response.json.return_value = {}

    actual = evaluate_rules.delete_rule(mock_session, "rule ID")
    self.assertFalse(actual)

  @mock.patch.object(requests, "AuthorizedSession", autospec=True)
  @mock.patch.object(requests.requests, "Response", autospec=True)
  def test_start_retrohunt(self, mock_response, mock_session):
    mock_session.request.return_value = mock_response
    type(mock_response).status_code = mock.PropertyMock(return_value=200)
    mock_response.json.return_value = {}

    actual = evaluate_rules.start_retrohunt(mock_session, "rule version ID",
                                            "2020-01-02T03:04:05Z",
                                            "2021-01-02T03:04:05Z")
    self.assertFalse(actual)

  @mock.patch.object(requests, "AuthorizedSession", autospec=True)
  @mock.patch.object(requests.requests, "Response", autospec=True)
  def test_poll_retrohunt(self, mock_response, mock_session):
    mock_session.request.return_value = mock_response
    type(mock_response).status_code = mock.PropertyMock(return_value=200)
    mock_response.json.return_value = {}

    actual = evaluate_rules.poll_retrohunt(mock_session, "rule version ID",
                                           "retrohunt ID")
    self.assertFalse(actual)

  @mock.patch.object(requests, "AuthorizedSession", autospec=True)
  @mock.patch.object(requests.requests, "Response", autospec=True)
  def test_wait_for_retrohunt(self, mock_response, mock_session):
    mock_session.request.return_value = mock_response
    type(mock_response).status_code = mock.PropertyMock(return_value=200)
    mock_response.json.return_value = {}

    actual = evaluate_rules.wait_for_retrohunt(mock_session, "rule version ID",
                                               "retrohunt ID")
    self.assertFalse(actual)

  @mock.patch.object(requests, "AuthorizedSession", autospec=True)
  @mock.patch.object(requests.requests, "Response", autospec=True)
  def test_list_detections(self, mock_response, mock_session):
    mock_session.request.return_value = mock_response
    type(mock_response).status_code = mock.PropertyMock(return_value=200)
    mock_response.json.return_value = {}

    actual = evaluate_rules.list_detections(mock_session, "rule version ID")
    self.assertFalse(actual)

  def test_define_time_range_default(self):
    start_time, end_time = evaluate_rules.define_time_range(None, None, False)
    self.assertGreater(end_time, start_time)

  def test_define_time_range_cutomized_in_command_line(self):
    dt = datetime.datetime.now()
    start_time, end_time = evaluate_rules.define_time_range(
        dt - datetime.timedelta(days=1), dt, True)
    self.assertGreater(end_time, start_time)

  def test_iso8601_to_utc_datetime_lower_case(self):
    expected = datetime.datetime(
        2021, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    actual = evaluate_rules.iso8601_to_utc_datetime("2021-01-02t03:04:05z")
    self.assertEqual(expected, actual)

  def test_iso8601_to_utc_datetime_missing_z(self):
    expected = datetime.datetime(
        2021, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    actual = evaluate_rules.iso8601_to_utc_datetime("2021-01-02T03:04:05")
    self.assertEqual(expected, actual)

  def test_iso8601_to_utc_datetime_with_microseconds(self):
    expected = datetime.datetime(
        2021, 1, 2, 3, 4, 5, 6, tzinfo=datetime.timezone.utc)
    actual = evaluate_rules.iso8601_to_utc_datetime(
        "2021-01-02T03:04:05.000006Z")
    self.assertEqual(expected, actual)

  def test_datetime_to_iso8601(self):
    self.assertEqual(
        "2021-01-02T03:04:05Z",
        evaluate_rules.datetime_to_iso8601(
            datetime.datetime(2021, 1, 2, 3, 4, 5)))


if __name__ == "__main__":
  unittest.main()
