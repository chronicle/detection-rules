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
"""Content Manager package."""

import logging
import os
import pathlib

import dotenv

dotenv.load_dotenv()

logging.basicConfig(
    level=os.getenv(key="LOGGING_LEVEL", default="INFO"),
    format="%(asctime)s | %(levelname)s | %(funcName)s | %(message)s",
    datefmt="%d-%b-%y %H:%M:%S %Z",
    handlers=[logging.StreamHandler()],
    encoding="utf-8",
)

LOGGER = logging.getLogger()

ROOT_DIR = pathlib.Path(__file__).parent.parent
RULES_DIR = ROOT_DIR / "rules"
RULE_CONFIG_FILE = ROOT_DIR / "rule_config.yaml"
REF_LISTS_DIR = ROOT_DIR / "reference_lists"
REF_LIST_CONFIG_FILE = ROOT_DIR / "reference_list_config.yaml"
DATA_TABLES_DIR = ROOT_DIR / "data_tables"
DATA_TABLE_CONFIG_FILE = ROOT_DIR / "data_table_config.yaml"
RULE_EXCLUSIONS_CONFIG_FILE = ROOT_DIR / "rule_exclusions_config.yaml"

# Create content directories if they don't exist.
RULES_DIR.mkdir(exist_ok=True)
REF_LISTS_DIR.mkdir(exist_ok=True)
DATA_TABLES_DIR.mkdir(exist_ok=True)

# Create config files if they don't exist
RULE_CONFIG_FILE.touch(exist_ok=True)
REF_LIST_CONFIG_FILE.touch(exist_ok=True)
DATA_TABLE_CONFIG_FILE.touch(exist_ok=True)
RULE_EXCLUSIONS_CONFIG_FILE.touch(exist_ok=True)
