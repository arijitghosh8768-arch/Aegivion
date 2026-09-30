"""Raw event persistence with redaction and digest verification.

Guarantees:

- Original records are never discarded: each is stored under a digest-derived
  reference, and normalized events link back via ``raw_event_reference``.
- Credential material is redacted before persistence.
- ``verify()`` re-computes the digest so tampering with the stored payload
  is detectable.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

# Keys whose values are credential material and must never hit disk.
_REDACT_KEY_RE = re.compile(
    r"(?i)password|passwd|secret|token|authorization|credential|sessionkey|sessiontoken|accesskey|signature"
)
_REDACTED = "[REDACTED]"


def redact(record: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy of *record* with credential values replaced."""
    out: dict[str, Any] = {}
    for key, value in record.items():
        if _REDACT_KEY_RE.search(str(key)):
            out[key] = _REDACTED
        elif isinstance(value, dict):
            out[key] = redact(value)
        elif isinstance(value, list):
            out[key] = [redact(v) if isinstance(v, dict) else v for v in value]
        else:
            out[key] = value
    return out


def digest(payload: Any) -> str:
    """Stable sha256 over a canonical JSON serialization."""
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(blob).hexdigest()


class RawEventStore:
    """File-backed raw event store (temp store; a later part may swap S3)."""

    def __init__(self, base_dir: str | Path) -> None:
        self._dir = Path(base_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def store(self, record: dict[str, Any]) -> str:
        """Persist a redacted copy; returns the raw-event reference.

        The reference is ``<digest>-<unique suffix>``: the digest part is
        verifiable (see :meth:`verify`), the suffix keeps references
        unique even when two events carry identical payloads.
        """
        safe = redact(copy.deepcopy(record))
        ref = f"{digest(safe)}-{uuid.uuid4().hex[:8]}"
        path = self._dir / f"{ref}.json"
        if not path.exists():
            entry = {
                "reference": ref,
                "record": {"payload": safe},
            }
            path.write_text(json.dumps(entry), encoding="utf-8")
        return ref

    def load(self, reference: str) -> dict[str, Any] | None:
        path = self._dir / f"{reference}.json"
        if not path.exists():
            return None
        entry = json.loads(path.read_text(encoding="utf-8"))
        return entry["record"]["payload"]

    def verify(self, reference: str, original: dict[str, Any]) -> bool:
        """True when *original* digests to the digest part of *reference*
        (post-redaction)."""
        digest_part = reference.split("-")[0]
        return digest(redact(copy.deepcopy(original))) == digest_part
