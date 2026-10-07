"""Root pytest bootstrap for the Aegivion Algorithm #3 repository.

Makes the repository root importable so tests can use absolute imports such as
``from detection.cloud_destruction.schemas import ResourceActivityEvent``.

Independence guarantee: this conftest does not touch ``Aegivion_algo_1`` or
``Aegivion_algo_2``. A dedicated boundary test (``test_independence.py``)
asserts at runtime that Algorithm #3 never imports from them.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
