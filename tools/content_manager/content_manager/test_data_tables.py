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
"""Tests for content_manager.data_tables."""

import copy
import json
import pathlib
from typing import Any, Mapping, Sequence

from content_manager.common.custom_exceptions import DataTableConfigError
from content_manager.data_tables import DataTable
from content_manager.data_tables import DataTableColumn
from content_manager.data_tables import DataTableConfigEntry
from content_manager.data_tables import DataTables
import pydantic
import pytest
import ruamel.yaml.constructor


ROOT_DIR = pathlib.Path(__file__).parent.parent
DATA_TABLES_DIR = ROOT_DIR / "data_tables"
DATA_TABLE_CONFIG_FILE = ROOT_DIR / "data_table_config.yaml"
TEST_DATA_DIR = pathlib.Path(__file__).parent / "test_data"
TEST_DATA_TABLES_DIR = TEST_DATA_DIR / "data_tables"
TEST_DATA_TABLE_CONFIG_FILE = TEST_DATA_DIR / "test_data_table_config.yaml"


@pytest.fixture(name="parsed_test_data_tables")
def parsed_test_data_tables_fixture() -> DataTables:
  """Load and parse test data_tables."""
  return DataTables.load_data_table_config(
      data_table_config_file=TEST_DATA_TABLE_CONFIG_FILE,
      data_tables_dir=TEST_DATA_TABLE_CONFIG_FILE,
  )


@pytest.fixture(name="raw_test_data_tables")
def raw_test_data_tables_fixture() -> Sequence[Mapping[str, Any]]:
  """Return a list of raw (unparsed) data tables."""
  test_data_tables_file = TEST_DATA_DIR / "test_data_tables.json"
  with open(test_data_tables_file, "r", encoding="utf-8") as f:
    return json.load(f)


def test_load_data_table_config():
  """Tests for data_tables.DataTables.load_data_table_config."""
  DATA_TABLE_CONFIG_FILE.touch(exist_ok=True)

  # Compare number of data table files in data tables dir to number of entries
  # in data tables config file
  data_tables_count = len(list(DATA_TABLES_DIR.glob("*.csv")))
  data_tables = DataTables.load_data_table_config()
  assert data_tables_count == len(data_tables)

  # Ensure an exception occurs if a data table config entry is found that
  # doesn't have a corresponding .csv file in the data tables directory
  with pytest.raises(
      DataTableConfigError,
      match=r"Data table file not found with name .*\.csv in .*",
  ):
    DataTables.load_data_table_config(
        data_table_config_file=TEST_DATA_DIR
        / "test_data_table_config_missing_data_table_file.yaml",
        data_tables_dir=TEST_DATA_TABLES_DIR,
    )


def test_parse_data_tables(raw_test_data_tables: Sequence[Mapping[str, Any]]):
  """Tests for data_tables.Data_Tables.parse_data_tables."""
  raw_data_tables = copy.deepcopy(raw_test_data_tables)

  # Ensure an exception occurs when attempting to parse a data table that's
  # missing a required value
  del raw_data_tables[0]["displayName"]

  with pytest.raises(expected_exception=KeyError, match=r"displayName"):
    DataTables.parse_data_tables(raw_data_tables)


def test_data_table():
  """Tests for data_tables.DataTable."""
  # Ensure an exception occurs when attempting to create a DataTable object
  # that's missing a required value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Field required \[type=missing",
  ):
    DataTable(
        resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/dataTables/data_table_1",
        uuid="091bafa1234d4f7396ea09f79fb6d209",
        description=100,
        create_time="2025-05-13T22:22:40.952537Z",
        update_time="2025-05-13T22:17:40.340730Z",
        columns=[
            DataTableColumn(
                column_index=0,
                original_column="user_id",
                column_type="STRING",
                mapped_column_path=None,
                key_column=False,
            ),
            DataTableColumn(
                column_index=1,
                original_column="hostname",
                column_type="STRING",
                mapped_column_path=None,
                key_column=False,
            ),
        ],
        row_time_to_live=None,
        rules=None,
        rule_associations_count=None,
    )

  # Ensure an exception occurs when attempting to create a DataTable object with
  # an invalid value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=(
          r"validation error for DataTable\nname\n  Input should be a valid"
          r" string"
      ),
  ):
    DataTable(
        name=4,
        resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/dataTables/data_table_1",
        uuid="091bafa1234d4f7396ea09f79fb6d209",
        description="data table 1",
        create_time="2025-05-13T22:22:40.952537Z",
        update_time="2025-05-13T22:17:40.340730Z",
        columns=[
            DataTableColumn(
                column_index=0,
                original_column="user_id",
                column_type="STRING",
                mapped_column_path=None,
                key_column=False,
            ),
            DataTableColumn(
                column_index=1,
                original_column="hostname",
                column_type="STRING",
                mapped_column_path=None,
                key_column=False,
            ),
        ],
        row_time_to_live=None,
        rules=None,
        rule_associations_count=None,
    )


def test_data_table_column():
  """Tests for data_tables.DataTableColumn."""
  # Ensure an exception occurs when attempting to create a DataTableColumn
  # object that's missing a required value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Field required \[type=missing",
  ):
    DataTableColumn(column_index=0)

  # Ensure an exception occurs when attempting to create a DataTableColumn
  # object with an invalid value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=(
          r"validation error for DataTableColumn\noriginal_column\n  Input"
          r" should be a valid string"
      ),
  ):
    DataTableColumn(
        column_index=0,
        original_column=100,
        column_type="STRING",
        mapped_column_path=None,
        key_column=False,
    )


def test_compare_data_table_contents():
  """Tests for data_tables.DataTables.compare_data_table_content."""
  data_table_1_row_values = [["alice", "desktop1234"], ["bob", "desktop5678"]]
  data_table_2_row_values = [["bob", "desktop5678"], ["alice", "desktop1234"]]

  # Ensure that False is returned when the contents of the two lists is the same
  result = DataTables.compare_data_table_content(
      data_table_1_row_values=data_table_1_row_values,
      data_table_2_row_values=data_table_2_row_values,
  )
  assert not result

  # Ensure that True is returned when the contents of the two lists is different
  data_table_1_row_values = [["alice", "desktop1234"], ["jon", "desktop1111"]]
  result = DataTables.compare_data_table_content(
      data_table_1_row_values=data_table_1_row_values,
      data_table_2_row_values=data_table_2_row_values,
  )
  assert result


def test_check_data_table_config():
  """Tests for data_tables.DataTables.check_data_table_config."""
  # Ensure an exception occurs when a data table config file contains duplicate
  # keys (data table names).
  with pytest.raises(ruamel.yaml.constructor.DuplicateKeyError):
    DataTables.load_data_table_config(
        data_table_config_file=TEST_DATA_DIR
        / "test_data_table_config_duplicate_keys.yaml",
        data_tables_dir=TEST_DATA_TABLES_DIR,
    )

  data_table_config = DataTables.load_data_table_config(
      data_table_config_file=TEST_DATA_TABLE_CONFIG_FILE,
      data_tables_dir=TEST_DATA_TABLES_DIR,
  )

  data_table_config["cisco_umbrella_top_1k_domains"]["invalid_key"] = "invalid"

  # Ensure an exception occurs when the data table config entry contains an
  # invalid key.
  with pytest.raises(
      DataTableConfigError, match=r"Invalid keys .* found for data table - "
  ):
    DataTables.check_data_table_config(config=data_table_config)

  del data_table_config["cisco_umbrella_top_1k_domains"]["invalid_key"]
  del data_table_config["cisco_umbrella_top_1k_domains"]["columns"]
  # Ensure an exception occurs when the data table config entry is missing a
  # required key.
  with pytest.raises(
      DataTableConfigError,
      match=r"Required key \(columns\) not found for data table - ",
  ):
    DataTables.check_data_table_config(config=data_table_config)


def test_data_table_config_entry():
  """Tests for data_tables.DataTableConfigEntry."""
  # Ensure an exception occurs when attempting to create a DataTableConfigEntry
  # object that's missing a required value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=r"Field required \[type=missing",
  ):
    DataTableConfigEntry(
        resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/dataTables/data_table_1",
        uuid="091bafa1234d4f7396ea09f79fb6d209",
        description="data table 1",
        create_time="2025-05-13T22:22:40.952537Z",
        update_time="2025-05-13T22:17:40.340730Z",
        columns=[
            DataTableColumn(
                column_index=0,
                original_column="user_id",
                column_type="STRING",
                mapped_column_path=None,
                key_column=False,
            ),
            DataTableColumn(
                column_index=1,
                original_column="hostname",
                column_type="STRING",
                mapped_column_path=None,
                key_column=False,
            ),
        ],
        row_time_to_live=30,
        rules=None,
        rule_associations_count=None,
    )

  # Ensure an exception occurs when attempting to create a DataTableConfigEntry
  # object with an invalid value
  with pytest.raises(
      expected_exception=pydantic.ValidationError,
      match=(
          r"validation error for DataTableConfigEntry\nrow_time_to_live\n "
          r" Input should be a valid string"
      ),
  ):
    DataTableConfigEntry(
        name="data_table_1",
        resource_name="projects/1234567891234/locations/us/instances/3f0ac524-5ae1-4bfd-b86d-53afc953e7e6/dataTables/data_table_1",
        uuid="091bafa1234d4f7396ea09f79fb6d209",
        description="data table 1",
        create_time="2025-05-13T22:22:40.952537Z",
        update_time="2025-05-13T22:17:40.340730Z",
        columns=[
            DataTableColumn(
                column_index=0,
                original_column="user_id",
                column_type="STRING",
                mapped_column_path=None,
                key_column=False,
            ),
            DataTableColumn(
                column_index=1,
                original_column="hostname",
                column_type="STRING",
                mapped_column_path=None,
                key_column=False,
            ),
        ],
        row_time_to_live=30,
        rules=None,
        rule_associations_count=None,
    )
