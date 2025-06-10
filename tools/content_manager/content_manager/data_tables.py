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
"""Manage data tables in Google SecOps."""

import csv
import json
import logging
import pathlib
from typing import Any, Literal, Mapping, Sequence

from content_manager.common.custom_exceptions import DataTableConfigError
from google.auth.transport import requests
from google_secops_api.data_table_rows.bulk_create_data_table_rows import bulk_create_data_table_rows
from google_secops_api.data_table_rows.bulk_replace_data_table_rows import bulk_replace_data_table_rows
from google_secops_api.data_table_rows.list_data_table_rows import list_data_table_rows
from google_secops_api.data_tables.list_data_tables import list_data_tables
from google_secops_api.data_tables.update_data_table import update_data_table
from google_secops_api.data_tables.upload_data_table import upload_data_table
import pydantic
import ruamel.yaml
import yaml

LOGGER = logging.getLogger()

ROOT_DIR = pathlib.Path(__file__).parent.parent
DATA_TABLES_DIR = ROOT_DIR / "data_tables"
DATA_TABLE_CONFIG_FILE = ROOT_DIR / "data_table_config.yaml"
DATA_TABLE_COLUMN_TYPES = Literal["CIDR", "STRING", "REGEX"]  # pylint: disable="invalid-name"

# Use ruamel.yaml to raise an exception if a YAML file contains duplicate keys
# (i.e. duplicate data table names)
ruamel_yaml = ruamel.yaml.YAML(typ="safe")


class DataTableColumn(pydantic.BaseModel):
  """Class for a data table column."""

  column_index: int | None
  original_column: str
  column_type: str | None
  mapped_column_path: str | None
  key_column: bool | None


class DataTable(pydantic.BaseModel):
  """Class for a data table."""

  name: str
  resource_name: str | None
  uuid: str | None
  description: str | None
  create_time: str | None
  update_time: str | None
  columns: Sequence[DataTableColumn]
  row_time_to_live: str | None
  rules: Sequence[str] | None
  rule_associations_count: int | None


class DataTableConfigEntry(pydantic.BaseModel):
  """Class for a data table config file entry."""

  name: str
  resource_name: str | None
  uuid: str | None
  description: str | None
  create_time: str | None
  update_time: str | None
  columns: Sequence[DataTableColumn]
  row_time_to_live: str | None
  rules: Sequence[str] | None
  rule_associations_count: int | None


class DataTables:
  """Class used to manage data tables."""

  def __init__(self, data_tables: Sequence[DataTable]):
    self.data_tables: Sequence[DataTable] = data_tables

  @classmethod
  def parse_data_table(cls, data_table: Mapping[str, Any]) -> DataTable:
    """Parse a data table into a DataTable object."""
    try:
      parsed_data_table = DataTable(
          name=data_table["displayName"],
          resource_name=data_table.get("name"),
          uuid=data_table.get("dataTableUuid"),
          description=data_table.get("description"),
          create_time=data_table.get("createTime"),
          update_time=data_table.get("updateTime"),
          columns=DataTables.parse_data_table_columns(
              columns=data_table["columnInfo"]
          ),
          row_time_to_live=data_table.get("rowTimeToLive"),
          rules=data_table.get("rules"),
          rule_associations_count=data_table.get("ruleAssociationsCount"),
      )
    except pydantic.ValidationError as e:
      LOGGER.error(
          "ValidationError occurred for data table %s\n%s",
          data_table,
          json.dumps(e.errors(), indent=4),
      )
      raise

    return parsed_data_table

  @classmethod
  def parse_data_tables(
      cls, data_tables: Sequence[Mapping[str, Any]]
  ) -> list[DataTable]:
    """Parse a list of data tables into a list of DataTable objects."""
    parsed_data_tables = []

    for data_table in data_tables:
      parsed_data_tables.append(DataTables.parse_data_table(data_table))

    return parsed_data_tables

  @classmethod
  def load_data_table_config(
      cls,
      data_table_config_file: pathlib.Path = DATA_TABLE_CONFIG_FILE,
      data_tables_dir: pathlib.Path = DATA_TABLES_DIR,
  ) -> Mapping[str, Any]:
    """Load data table config from file."""
    data_table_config_parsed = {}

    LOGGER.info(
        "Loading data table config from file %s", data_table_config_file
    )
    with open(data_table_config_file, "r", encoding="utf-8") as f:
      data_table_config = ruamel_yaml.load(f)

    if not data_table_config:
      LOGGER.info("Data table config file is empty.")
      return {}

    DataTables.check_data_table_config(data_table_config)

    for data_table_name, data_table_config_entry in data_table_config.items():
      try:
        data_table_config_entry_parsed = DataTableConfigEntry(
            name=data_table_name,
            resource_name=data_table_config_entry.get("resource_name"),
            uuid=data_table_config_entry.get("uuid"),
            description=data_table_config_entry.get("description"),
            create_time=data_table_config_entry.get("create_time"),
            update_time=data_table_config_entry.get("update_time"),
            columns=DataTables.parse_data_table_config_entry_columns(
                columns=data_table_config_entry.get("columns")
            ),
            row_time_to_live=data_table_config_entry.get("row_time_to_live"),
            rules=data_table_config_entry.get("rules"),
            rule_associations_count=data_table_config_entry.get(
                "rule_associations_count"
            ),
        )
      except pydantic.ValidationError as e:
        LOGGER.error(
            "ValidationError occurred for data table config entry %s\n%s",
            data_table_name,
            json.dumps(e.errors(), indent=4),
        )
        raise

      data_table_config_parsed[data_table_config_entry_parsed.name] = (
          data_table_config_entry_parsed.model_dump(exclude={"name"})
      )

    LOGGER.info(
        "Loaded metadata and config for %s data tables from directory %s",
        len(data_table_config_parsed),
        data_tables_dir,
    )

    data_table_files = list(data_tables_dir.glob("*.csv"))
    non_data_table_files = [
        file_path
        for file_path in data_tables_dir.glob("*")
        if not file_path.name.endswith(".csv")
    ]

    if non_data_table_files:
      LOGGER.warning(
          "%s files found in data_tables directory without .csv extension."
          " These files will not be processed.",
          len(non_data_table_files),
      )

    data_table_names = []

    # Raise an exception if a data table config entry is found that doesn't
    # have a corresponding csv file in the data tables dir
    for data_table_file_path in data_table_files:
      data_table_names.append(data_table_file_path.stem)
    for key in data_table_config:
      if key not in data_table_names:
        raise DataTableConfigError(
            f"Data table file not found with name {key}.csv in"
            f" {data_tables_dir}"
        )

    # Raise an exception if the csv file for the data table does not have a
    # corresponding entry in the data table config file
    for data_table_file_path in data_table_files:
      data_table_name = data_table_file_path.stem
      if data_table_config.get(data_table_name) is None:
        raise DataTableConfigError(
            f"Data table {data_table_name} not found in data table config"
            f" file {data_table_config_file}"
        )

    return data_table_config_parsed

  @classmethod
  def parse_data_table_config_entry(
      cls, data_table_name: str, data_table_config_entry: Mapping[str, Any]
  ):
    """Parse a data table config entry into a DataTableConfigEntry object."""
    try:
      data_table_config_entry_parsed = DataTableConfigEntry(
          name=data_table_name,
          resource_name=data_table_config_entry.get("resource_name"),
          uuid=data_table_config_entry.get("uuid"),
          description=data_table_config_entry.get("description"),
          create_time=data_table_config_entry.get("create_time"),
          update_time=data_table_config_entry.get("update_time"),
          columns=DataTables.parse_data_table_config_entry_columns(
              columns=data_table_config_entry.get("columns")
          ),
          row_time_to_live=data_table_config_entry.get("row_time_to_live"),
          rules=data_table_config_entry.get("rules"),
          rule_associations_count=data_table_config_entry.get(
              "rule_associations_count"
          ),
      )
    except pydantic.ValidationError as e:
      LOGGER.error(
          "ValidationError occurred for data table %s\n%s",
          data_table_name,
          json.dumps(e.errors(), indent=4),
      )
      raise

    return data_table_config_entry_parsed

  @classmethod
  def parse_data_table_config_entry_columns(
      cls, columns: Sequence[Mapping[str, Any]]
  ) -> Sequence[DataTableColumn]:
    """Parse a list of data table columns from the local data table config file into a list of DataTableColumn objects.
    """
    parsed_columns = []

    for column in columns:
      try:
        parsed_columns.append(
            DataTableColumn(
                column_index=column["column_index"],
                original_column=column["original_column"],
                column_type=column.get("column_type"),
                mapped_column_path=column.get("mapped_column_path"),
                key_column=column.get("key_column"),
            )
        )
      except pydantic.ValidationError as e:
        LOGGER.error(
            "ValidationError occurred for data table column %s\n%s",
            column,
            json.dumps(e.errors(), indent=4),
        )
        raise

    return parsed_columns

  @classmethod
  def parse_data_table_columns(
      cls, columns: Sequence[Mapping[str, Any]]
  ) -> DataTableColumn:
    """Parse a list of data columns retrieved from Google SecOps API into a list of DataTableColumn objects."""
    parsed_columns = []

    for column in columns:
      # This column should have an index of 0 (it's the first column)
      if column.get("columnIndex") is None:
        column["columnIndex"] = 0

      try:
        parsed_columns.append(
            DataTableColumn(
                column_index=column["columnIndex"],
                original_column=column["originalColumn"],
                column_type=column.get("columnType"),
                mapped_column_path=column.get("mappedColumnPath"),
                key_column=column.get("keyColumn"),
            )
        )
      except pydantic.ValidationError as e:
        LOGGER.error(
            "ValidationError occurred for data table column %s\n%s",
            column,
            json.dumps(e.errors(), indent=4),
        )
        raise

    return parsed_columns

  @classmethod
  def check_data_table_config(cls, config: Mapping[str, Any]):
    """Check data table config file for invalid keys."""
    required_keys = ["columns"]
    allowed_keys = [
        "resource_name",
        "uuid",
        "description",
        "create_time",
        "update_time",
        "columns",
        "row_time_to_live",
        "rules",
        "rule_associations_count",
    ]
    invalid_keys = []

    for data_table_name, data_table_config in config.items():
      for key in list(data_table_config.keys()):
        if key not in allowed_keys:
          invalid_keys.append(key)

      if invalid_keys:
        raise DataTableConfigError(
            f"Invalid keys ({invalid_keys}) found for data table -"
            f" {data_table_name}"
        )

      for key in required_keys:
        if key not in list(data_table_config.keys()):
          raise DataTableConfigError(
              f"Required key ({key}) not found for data table -"
              f" {data_table_name}"
          )

  def dump_data_table_config(self):
    """Dump the configuration and metadata for a collection of data tables."""
    data_table_config = {}

    for data_table in self.data_tables:
      try:
        data_table_config_entry = DataTableConfigEntry(
            name=data_table.name,
            resource_name=data_table.resource_name,
            uuid=data_table.uuid,
            description=data_table.description,
            create_time=data_table.create_time,
            update_time=data_table.update_time,
            columns=data_table.columns,
            row_time_to_live=data_table.row_time_to_live,
            rules=data_table.rules,
            rule_associations_count=data_table.rule_associations_count,
        )
      except pydantic.ValidationError as e:
        LOGGER.error(
            "ValidationError occurred for data table config entry %s\n%s",
            data_table,
            json.dumps(e.errors(), indent=4),
        )
        raise

      data_table_config[data_table.name] = data_table_config_entry.model_dump(
          exclude={"name"}
      )

    data_table_config_file_path = ROOT_DIR / "data_table_config.yaml"

    LOGGER.info("Writing data table config to %s", data_table_config_file_path)
    with open(
        data_table_config_file_path, "w", encoding="utf-8"
    ) as data_table_config_file:
      yaml.dump(data_table_config, data_table_config_file, sort_keys=True)

  @classmethod
  def get_remote_data_tables(
      cls, http_session: requests.AuthorizedSession
  ) -> "DataTables":
    """Retrieve the latest version of all data tables from Google SecOps."""
    raw_data_tables = []
    next_page_token = None

    LOGGER.info("Attempting to retrieve all data tables from Google SecOps")
    while True:
      retrieved_data_tables, next_page_token = list_data_tables(
          http_session=http_session,
          page_size=None,
          page_token=next_page_token,
      )

      if retrieved_data_tables is not None:
        LOGGER.info("Retrieved %s data tables", len(retrieved_data_tables))
        raw_data_tables.extend(retrieved_data_tables)

      if next_page_token:
        LOGGER.info(
            "Attempting to retrieve data tables with page token %s",
            next_page_token,
        )
      else:
        # Break if there are no more pages of data tables to retrieve
        break

    raw_data_tables_count = len(raw_data_tables)

    LOGGER.info("Retrieved a total of %s data tables", raw_data_tables_count)

    parsed_data_tables = DataTables.parse_data_tables(
        data_tables=raw_data_tables
    )

    return DataTables(data_tables=parsed_data_tables)

  @classmethod
  def get_remote_data_table_rows(
      cls,
      http_session: requests.AuthorizedSession,
      data_table_name: str,
      data_table_resource_name: str,
      write_to_file: bool | None = False,
  ) -> Sequence[str | None]:
    """Retrieve the rows for a data table in Google SecOps and optionally write them to a local file.

    Args:
      http_session: Authorized session for HTTP requests.
      data_table_name: The name of the data table.
      data_table_resource_name: The resource name of the data table to update. Format:
        projects/{project}/locations/{location}/instances/{instance}/dataTables/{data_table_name}
      write_to_file (optional): Whether to write the rows to a local file.

    Returns:
      A list of data table row values.
    """
    data_table_file_path = DATA_TABLES_DIR / f"{data_table_name}.csv"
    if write_to_file:
      data_table_file_path.touch()  # Create an empty file

      LOGGER.info(
          "Attempting to retrieve all rows for data table %s from Google SecOps"
          " and write them to local file %s",
          data_table_name,
          data_table_file_path,
      )

    else:
      LOGGER.info(
          "Attempting to retrieve all rows for data table %s from Google"
          " SecOps",
          data_table_name,
      )

    next_page_token = None
    row_values = []

    while True:
      retrieved_data_table_rows, next_page_token = list_data_table_rows(
          http_session=http_session,
          resource_name=data_table_resource_name,
          page_size=1000,
          page_token=next_page_token,
      )

      if retrieved_data_table_rows is None:
        LOGGER.info("Retrieved 0 rows for data table %s", data_table_name)

      else:
        LOGGER.info(
            "Retrieved %s data table rows for data table %s",
            len(retrieved_data_table_rows),
            data_table_name,
        )
        row_values.extend([row["values"] for row in retrieved_data_table_rows])

      if next_page_token:
        LOGGER.info(
            "Attempting to retrieve data table rows for data table %s with page"
            " token %s",
            data_table_name,
            next_page_token,
        )
      else:
        # Break if there are no more pages of data table rows to retrieve
        break

    if write_to_file:
      # Write the rows to the open file
      LOGGER.info(
          "Attempting to write %s data table rows to file %s",
          len(row_values),
          data_table_file_path,
      )

      with open(data_table_file_path, "a", encoding="utf-8", newline="") as f:
        csv_writer = csv.writer(f)
        csv_writer.writerows(row_values)

    return row_values

  @classmethod
  def compare_data_table_content(
      cls,
      data_table_1_row_values: Sequence[str],
      data_table_2_row_values: Sequence[str],
  ) -> bool:
    """Compare the content (row values) of two data tables."""
    # When a data table is created in Google SecOps, the original order of the
    # rows is not preserved. Create a set to compare the contents (row values)
    # of the local and remote data table
    data_table_1_set = {
        tuple(row_values) for row_values in data_table_1_row_values
    }
    data_table_2_set = {
        tuple(row_values) for row_values in data_table_2_row_values
    }

    if data_table_1_set == data_table_2_set:
      return False
    else:
      # Return True if the content of the two data tables is different.
      return True

  @classmethod
  def update_remote_data_tables(
      cls,
      http_session: requests.AuthorizedSession,
      data_tables_dir: pathlib.Path = DATA_TABLES_DIR,
      data_table_config_file: pathlib.Path = DATA_TABLE_CONFIG_FILE,
  ) -> Mapping[str, Sequence[tuple[str, str]]] | None:
    """Update data tables in Google SecOps based on local files."""
    LOGGER.info(
        "Attempting to update data tables in Google SecOps based on local files"
    )

    data_table_config = DataTables.load_data_table_config(
        data_table_config_file=data_table_config_file,
        data_tables_dir=data_tables_dir,
    )

    if not data_table_config:
      return

    LOGGER.info(
        "Attempting to retrieve latest version of all data tables from"
        " Google SecOps"
    )
    remote_data_tables = DataTables.get_remote_data_tables(
        http_session=http_session
    )

    # Create a dictionary containing the remote data tables using the
    # data table's name as the key for each item.
    remote_data_tables_dict = {}

    if remote_data_tables.data_tables:
      for remote_data_table in remote_data_tables.data_tables:
        remote_data_tables_dict[remote_data_table.name] = remote_data_table

    # Keep track of data table updates to log a final summary of changes
    # made.
    update_summary = {
        "created": [],
        "config_updated": [],
        "content_updated": [],
    }

    for data_table_name, local_data_table in data_table_config.items():
      update_remote_data_table_config = False

      if data_table_name not in remote_data_tables_dict:
        # A new data table will be created if a remote data table isn't
        # found with the same name
        LOGGER.info(
            "Local data table name %s not found in remote data tables."
            " Creating a new data table",
            data_table_name,
        )

        response = upload_data_table(
            http_session=http_session,
            name=data_table_name,
            description=local_data_table.get("description"),
            column_info=local_data_table["columns"],
            file_path=DATA_TABLES_DIR / f"{data_table_name}.csv",
            row_time_to_live=local_data_table.get("row_time_to_live"),
        )
        # The upload data table API method returns an Operation object that can
        # be monitored for completion Reference:
        # https://cloud.google.com/chronicle/docs/reference/rest/Shared.Types/ListOperationsResponse#Operation
        LOGGER.info("Upload data table response: %s", response)
        update_summary["created"].append(data_table_name)

      if data_table_name in remote_data_tables_dict:
        # Data table exists in Google SecOps with same name as local
        # data table.
        remote_data_table = remote_data_tables_dict[data_table_name]

        # Check if the data table's description should be updated
        LOGGER.debug(
            "Data table %s - Comparing the description of the local and"
            " remote data table",
            data_table_name,
        )
        if local_data_table["description"] != remote_data_table.description:
          LOGGER.info(
              "Data table %s - Description for local and remote data"
              " table is different. Remote data table config will be updated",
              data_table_name,
          )
          update_remote_data_table_config = True

        # Check if the data table's row time-to-live should be updated
        LOGGER.debug(
            "Data table %s - Comparing the row time-to-live of the local and"
            " remote data table",
            data_table_name,
        )
        if (
            local_data_table["row_time_to_live"]
            != remote_data_table.row_time_to_live
        ):
          LOGGER.info(
              "Data table %s - Row time-to-live for local and remote data"
              " table is different. Remote data table config will be updated",
              data_table_name,
          )
          update_remote_data_table_config = True

        if update_remote_data_table_config:
          LOGGER.info(
              "Data table %s - Updating remote data table config",
              data_table_name,
          )
          update_data_table(
              http_session=http_session,
              resource_name=local_data_table["resource_name"],
              updates={
                  "description": local_data_table["description"],
                  "row_time_to_live": local_data_table["row_time_to_live"],
              },
              update_mask=["description", "row_time_to_live"],
          )
          update_summary["config_updated"].append(data_table_name)

        # Compare the content (rows) in the local and remote data table to
        # determine whether the rows in the data table in Google SecOps should
        # be updated
        remote_data_table_rows = DataTables.get_remote_data_table_rows(
            http_session=http_session,
            data_table_name=data_table_name,
            data_table_resource_name=local_data_table["resource_name"],
        )

        data_table_file_path = DATA_TABLES_DIR / f"{data_table_name}.csv"
        # Read in the contents of the csv file
        with open(data_table_file_path, "r", encoding="utf-8") as f:
          reader = csv.reader(f)
          local_data_table_rows = list(reader)

        LOGGER.debug(
            "Data table %s - Comparing the content of the local "
            "and remote data table",
            data_table_name,
        )
        if (
            DataTables.compare_data_table_content(
                data_table_1_row_values=remote_data_table_rows,
                data_table_2_row_values=local_data_table_rows,
                )
            ):
          LOGGER.info(
              "Data table %s - Content is different in local and "
              "remote data table. Remote data table will be updated",
              data_table_name,
          )

          DataTables.update_remote_data_table_rows(
              http_session=http_session,
              data_table_name=data_table_name,
              data_table_resource_name=local_data_table["resource_name"],
              row_values=local_data_table_rows,
          )
          update_summary["content_updated"].append(data_table_name)

    return update_summary

  @classmethod
  def update_remote_data_table_rows(
      cls,
      http_session: requests.AuthorizedSession,
      data_table_name: str,
      data_table_resource_name: str,
      row_values: Sequence[str],
  ):
    """Update the content (rows) for a data table in Google SecOps based on the contents of a local file.

    Args:
      http_session: Authorized session for HTTP requests.
      data_table_name: The name of the data table.
      data_table_resource_name: The resource name of the data table to update. Format:
        projects/{project}/locations/{location}/instances/{instance}/dataTables/{data_table_name}
      row_values: A list of data table row values. Example: [["user1",
        "desktop1"], ["user2", "desktop2"]]

    Returns:
      None.
    """
    # As of 5/13/2025, API methods do not exist to delete all rows from an
    # existing data table and update the rows of the data table by uploading
    # a file. We are using the dataTableRows.bulkReplace method to replace all
    # rows in the remote data table with a maximum of 1,000 new rows from the
    # local data table file. If the local data table file contains more than
    # 1,000 rows, the dataTableRows.bulkCreate API method is then used to
    # populate the data table with the remaining rows.
    # Replacing the rows in the data tables in Google SecOps based on local
    # files each time will reset the time-to-live (TTL) timer for each row.
    total_row_count = len(row_values)
    LOGGER.debug(
        "Local data table %s contains %s rows", data_table_name, total_row_count
    )

    if total_row_count == 0:
      LOGGER.error(
          "No rows found in local data table %s\n"
          "Either create one or more rows in the local data table file or "
          "delete the empty data table.",
          data_table_name,
      )
      raise ValueError(f"No rows found in local data table {data_table_name}")

    # Use the dataTableRows.bulkReplace API method to replace all rows in the
    # data table with a maximum of 1,000 rows. The remaining rows (if there are
    # more than 1,000) will be written using the dataTableRows.bulkCreate API
    # method
    rows_to_create = row_values[:1000]
    LOGGER.debug(
        "Attempting to replace all rows in data table %s with %s rows",
        data_table_name,
        len(rows_to_create),
    )

    bulk_replace_data_table_rows(
        http_session=http_session,
        resource_name=data_table_resource_name,
        row_values=rows_to_create,
    )
    LOGGER.info(
        "Successfully replaced all rows in data table %s with %s rows",
        data_table_name,
        len(rows_to_create),
    )

    # Use the dataTableRows.bulkCreate API method to populate the data table
    # with the remaining rows from the local file (if there are any). Maximum
    # of 1,000 rows per request.
    if total_row_count > 1000:
      # Store the remaining number of rows that need to be created
      rows_to_create = row_values[1000:]

      LOGGER.info(
          "Attempting to create %s remaining rows in data table %s",
          len(rows_to_create),
          data_table_name,
      )
      start_index = 0
      while start_index < len(rows_to_create):
        end_index = min(start_index + 1000, len(rows_to_create))
        batch = rows_to_create[start_index:end_index]
        LOGGER.debug(
            "Attempting to create rows %s-%s in data table %s",
            start_index + 1001,  # Adjust for the initial 1000 rows
            end_index + 1000,
            data_table_name,
        )

        bulk_create_data_table_rows(
            http_session=http_session,
            resource_name=data_table_resource_name,
            row_values=batch,
        )
        LOGGER.debug(
            "Successfully created rows %s-%s in data table %s",
            start_index + 1001,
            end_index + 1000,
            data_table_name,
        )
        start_index = end_index

    LOGGER.info(
        "Created a total of %s rows in data table %s",
        total_row_count,
        data_table_name,
    )

    return
