"""Aiken blueprint (plutus.json) reader for compiled validators."""

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ValidatorInfo:
    """Info about a compiled validator from the Aiken blueprint."""

    title: str
    compiled_code: str
    hash: str


def read_blueprint(
    path: str = "contracts/governance-suggestion/plutus.json",
) -> dict[str, ValidatorInfo]:
    """Read the Aiken blueprint and return compiled validators keyed by title.

    Args:
        path: Path to the plutus.json blueprint file.

    Returns:
        Dict mapping validator title to ValidatorInfo.

    Raises:
        FileNotFoundError: If the blueprint file does not exist.
    """
    blueprint_path = Path(path)
    if not blueprint_path.exists():
        raise FileNotFoundError(f"Blueprint not found at {path}")

    with open(blueprint_path) as f:
        blueprint = json.load(f)

    validators = {}
    for v in blueprint.get("validators", []):
        title = v["title"]
        validators[title] = ValidatorInfo(
            title=title,
            compiled_code=v["compiledCode"],
            hash=v["hash"],
        )

    return validators
