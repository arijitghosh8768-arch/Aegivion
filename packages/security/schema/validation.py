import os
import json
from jsonschema import validate, ValidationError
from typing import Dict, Any, Tuple

# Path to the frozen contract
CONTRACTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "docs", "contracts"))
ASSET_SCHEMA_PATH = os.path.join(CONTRACTS_DIR, "asset.schema.json")
FINDING_SCHEMA_PATH = os.path.join(CONTRACTS_DIR, "finding.schema.json")

def load_schema(schema_path: str) -> Dict[str, Any]:
    with open(schema_path, "r") as f:
        return json.load(f)

def validate_asset(asset_data: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validates a normalized asset against the frozen JSON contract.
    Returns (True, "") if valid, or (False, "error message") if invalid.
    """
    try:
        schema = load_schema(ASSET_SCHEMA_PATH)
        validate(instance=asset_data, schema=schema)
        return True, ""
    except ValidationError as e:
        return False, f"Validation error at {'.'.join(str(p) for p in e.path)}: {e.message}"
    except Exception as e:
        return False, f"Schema validation failed: {str(e)}"

def validate_finding(finding_data: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validates a security finding against the frozen JSON contract.
    """
    try:
        schema = load_schema(FINDING_SCHEMA_PATH)
        validate(instance=finding_data, schema=schema)
        return True, ""
    except ValidationError as e:
        return False, f"Validation error at {'.'.join(str(p) for p in e.path)}: {e.message}"
    except Exception as e:
        return False, f"Schema validation failed: {str(e)}"
