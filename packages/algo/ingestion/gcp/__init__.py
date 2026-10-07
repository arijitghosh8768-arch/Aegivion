"""GCP ingestion for Aegivion Algorithm #3 (Part 5).

GCP Cloud Audit Log (Admin Activity + Data Access) -> canonical
:class:`ResourceActivityEvent`. Provider-neutral schemas mean this
package mirrors :mod:`ingestion.aws` and :mod:`ingestion.azure`
without touching detection logic. Defensive only: it normalizes
telemetry, never acts on it.
"""

from ingestion.gcp.audit_log import (
    GCP_NORMALIZER_VERSION,
    GcpAuditLogIngestor,
    GcpAuditLogNormalizer,
    IngestResult,
    raw_reference_for,
)

__all__ = [
    "GCP_NORMALIZER_VERSION",
    "GcpAuditLogIngestor",
    "GcpAuditLogNormalizer",
    "IngestResult",
    "raw_reference_for",
]
