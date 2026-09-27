"""Aegivion ingestion layer.

Provider-specific telemetry adapters live here. They transform raw cloud logs
into the provider-neutral ``IdentityActivityEvent`` consumed by detection.
"""

__all__ = ["aws"]
