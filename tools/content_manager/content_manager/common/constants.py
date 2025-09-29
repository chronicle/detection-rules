import os
import pathlib


class Constants:
    """Handles constants used throughout the content manager."""
    ROOT_DIR = os.getenv("ROOT_DIR", pathlib.Path(__file__).parent.parent)
    # Variables for a future support
    # RULES_DIR = ROOT_DIR / pathlib.Path(os.getenv("RULES_DIR", "rules"))
    # RULE_CONFIG_FILE = ROOT_DIR / pathlib.Path(os.getenv("RULE_CONFIG_FILE", "rules"))
    # REF_LISTS_DIR = ROOT_DIR / pathlib.Path(os.getenv("REF_LISTS_DIR", "rules"))
    # DATA_TABLES_DIR = ROOT_DIR / pathlib.Path(os.getenv("DATA_TABLES_DIR", "rules"))
    # DATA_TABLE_CONFIG_FILE = ROOT_DIR / pathlib.Path(os.getenv("DATA_TABLE_CONFIG_FILE", "rules"))
    # RULE_EXCLUSION_CONFIG_FILE = ROOT_DIR / pathlib.Path(os.getenv("RULE_EXCLUSION_CONFIG_FILE", "rules"))