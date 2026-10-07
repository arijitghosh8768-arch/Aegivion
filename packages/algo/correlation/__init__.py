"""Aegivion Threat Correlation — integration seam (Part 5).

Threat Correlation lives outside every algorithm package. This
package is where Algorithm #3 findings meet correlation context
from the rest of Aegivion. It is dependency-free by design:
nothing here imports ``detection.*`` or ``ingestion.*``, so the
strict independence contract between algorithms is preserved
while still allowing cross-algorithm correlation through this
one, explicit seam.
"""

from correlation.threat_correlation import (
    CorrelationContext,
    CorrelationRecord,
    ThreatCorrelationBroker,
    finding_digest,
)

__all__ = [
    "CorrelationContext",
    "CorrelationRecord",
    "ThreatCorrelationBroker",
    "finding_digest",
]
