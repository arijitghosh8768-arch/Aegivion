"""Root pytest bootstrap.

Makes the repository root importable so tests can use absolute imports such as
``from algo.detection.credential_compromise.schemas import IdentityActivityEvent``.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
