"""Azure ingestion for Aegivion Algorithm #3 (Part 5).

Azure Activity Monitor Activity Log -> canonical
:class:`ResourceActivityEvent`. Provider-neutral schemas mean this
package mirrors :mod:`ingestion.aws` without touching detection
logic. Defensive only: it normalizes telemetry, never acts on it.
"""

from ingestion.azure.activity_log import (
    AZURE_NORMALIZER_VERSION,
    AzureActivityLogIngestor,
    AzureActivityLogNormalizer,
    IngestResult,
    raw_reference_for,
)

__all__ = [
    "AZURE_NORMALIZER_VERSION",
    "AzureActivityLogIngestor",
    "AzureActivityLogNormalizer",
    "IngestResult",
    "raw_reference_for",
]
