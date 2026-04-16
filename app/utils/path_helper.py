"""Path helper utility."""
from pathlib import Path


def get_project_root() -> Path:
    """Returns the absolute path to the project root directory."""
    return Path(__file__).resolve().parent.parent.parent
