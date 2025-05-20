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
"""Custom exceptions used across multiple modules."""


class RuleError(Exception):
  """Raised when an issue is found with a YARA-L rule."""


class RuleVerificationError(Exception):
  """Raised when a YARA-L 2.0 rule verification error occurs."""


class RuleConfigError(Exception):
  """Raised when an issue with the rule config file is found."""


class DuplicateRuleIdError(Exception):
  """Raised when a duplicate rule ID is found."""


class DuplicateRuleNameError(Exception):
  """Raised when a duplicate rule name is found."""


class DataTableConfigError(Exception):
  """Raised when an issue with the data table config file is found."""


class ReferenceListConfigError(Exception):
  """Raised when an issue with the reference list config file is found."""


class RuleExclusionConfigError(Exception):
  """Raised when an issue with the rule exclusion config file is found."""
