"""Destination analysis: where data went, and what we already knew.

Part 1 reports observations: destinations seen, which of them were in the
supplied known-set, network diversity, and public/private character.
Classifying a destination as *suspicious* is Part 2's job.

The known-destination universe may be supplied per call (from resource
profiles or asset inventory). When it is not supplied we say so explicitly
instead of treating every destination as unknown-by-default.
"""

from __future__ import annotations

from typing import Any

from algo.data_exfiltration.data_exfiltration.base import AnalysisModule, AnalysisResult
from algo.data_exfiltration.data_exfiltration.enrichment import is_public_destination
from algo.data_exfiltration.data_exfiltration.schemas import DataAccessSession


class DestinationAnalyzer(AnalysisModule):
    name = "destination"

    def __init__(self, known_destinations: set[str] | None = None) -> None:
        self._known = known_destinations

    def analyze(self, session: DataAccessSession, context: dict[str, Any] | None = None) -> AnalysisResult:
        signals: dict[str, Any] = {"session_id": session.session_id}

        destinations = list(session.unique_destinations)
        signals["destinations"] = destinations
        signals["destination_count"] = len(destinations)

        known = self._known
        if context and isinstance(context.get("known_destinations"), (set, list)):
            known = set(context["known_destinations"])

        if known is None:
            signals["known_destination_universe"] = "not supplied"
            signals["unrecognized_destinations"] = None
        else:
            unknown = [d for d in destinations if d not in known]
            signals["known_destination_universe"] = "supplied"
            signals["unrecognized_destinations"] = unknown

        public_flags = {d: is_public_destination(d) for d in destinations}
        public_destinations = [d for d, flag in public_flags.items() if flag is True]
        signals["public_destinations"] = public_destinations
        signals["destination_classification"] = {
            d: ("public" if flag is True else "private" if flag is False else "unknown")
            for d, flag in public_flags.items()
        }

        signals["unique_asns"] = session.unique_asns
        signals["unique_countries"] = session.unique_countries
        signals["asn_diversity"] = len(session.unique_asns)
        signals["country_diversity"] = len(session.unique_countries)

        return AnalysisResult(analysis_name=self.name, signals=signals)
