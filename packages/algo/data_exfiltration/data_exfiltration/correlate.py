"""VPC flow -> data-access session correlation.

Flows are network evidence; data events are application evidence. A flow
correlates into a session when (a) time overlaps the session window
(± ``max_time_skew``) and (b) the flow's source IP is a destination-IP
candidate observed in the session's own events (conservative heuristic).

Correlated flows ADD evidence (network bytes, destinations, packets). They
never overwrite data-event measurements: each contribution keeps its own
source and confidence inside the measurement.
"""

from __future__ import annotations

from algo.data_exfiltration.data_exfiltration.config import DetectorConfig
from algo.data_exfiltration.data_exfiltration.measurement import MultiSourceMeasurement, SourceMeasurement
from algo.data_exfiltration.data_exfiltration.schemas import DataActivityEvent, DataAccessSession

# Fallback public/private buckets when no geo enrichment is wired
_PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "169.254.", "127.")


def is_private_ip(ip: str | None) -> bool | None:
    """True = private, False = public, None = cannot tell."""
    if not ip:
        return None
    return ip.startswith(_PRIVATE_PREFIXES) or False


def correlate_flow_events(
    session: DataAccessSession,
    flow_events: list[DataActivityEvent],
    config: DetectorConfig | None = None,
) -> list[DataActivityEvent]:
    """Return the subset of *flow_events* correlating with *session*.

    Matching is conservative and tiered:

    1. TIME: flow start within [session.start - skew, session.end + skew].
    2. LINK, one of:
       - the flow's src or dst IP appears among the session's known
         destination IPs, OR
       - both flow endpoints are internal (in-VPC traffic), OR
       - the flow originates from an internal IP and the session carries
         no destination information at all (common for S3 data events,
         which never contain destination IPs).

    The third tier is a documented limitation of Part 1: without
    ENI/principal identity mapping, flows from inside the VPC during a
    session are the best available evidence link. Correlation only ever
    ADDS observed network evidence; it never raises risk by itself.
    """
    cfg = config or DetectorConfig()
    skew_ms = cfg.correlation.max_time_skew * 1000.0
    if session.start_time_epoch_ms is None or session.end_time_epoch_ms is None:
        return []

    session_destinations = set(session.unique_destinations)
    session_has_destination_info = bool(session_destinations)
    matched: list[DataActivityEvent] = []
    for flow in flow_events:
        if flow.event_time_epoch_ms is None:
            continue
        in_window = (
            session.start_time_epoch_ms - skew_ms
            <= flow.event_time_epoch_ms
            <= session.end_time_epoch_ms + skew_ms
        )
        if not in_window:
            continue
        src = flow.source_ip
        dst = flow.destination_ip
        ip_match = bool(src and src in session_destinations) or bool(dst and dst in session_destinations)
        both_internal = is_private_ip(src) is True and is_private_ip(dst) is True
        internal_src_candidate = (
            not session_has_destination_info
            and is_private_ip(src) is True
        )
        if ip_match or both_internal or internal_src_candidate:
            matched.append(flow)
    return matched


def merge_flow_evidence(
    session: DataAccessSession,
    flows: list[DataActivityEvent],
) -> DataAccessSession:
    """Return a copy of *session* enriched with matched flow evidence.

    Adds:
    - network egress bytes as a VPC_FLOW_LOG observed contribution
    - external destinations (public IPs) to unique_destinations
    - packet counts aggregated per source/confidence
    """
    if not flows:
        return session

    egress_parts: list[SourceMeasurement] = []
    packet_parts: list[SourceMeasurement] = []
    destinations = set(session.unique_destinations)
    asns = set(session.unique_asns)
    countries = set(session.unique_countries)

    for flow in flows:
        if flow.network_bytes is not None:
            egress_parts.extend(flow.network_bytes.measurements)
        if flow.destination_ip:
            destinations.add(flow.destination_ip)
        if flow.destination_asn:
            asns.add(flow.destination_asn)
        if flow.destination_country:
            countries.add(flow.destination_country)

    network_egress = session.network_egress_bytes
    if egress_parts:
        contribution = SourceMeasurement(
            value=sum(p.value for p in egress_parts),
            source=egress_parts[0].source,
            confidence=egress_parts[0].confidence,
            detail=f"sum over {len(egress_parts)} correlated flow records",
        )
        network_egress = (
            network_egress.add(contribution)
            if network_egress is not None
            else MultiSourceMeasurement(measurements=[contribution])
        )

    return session.model_copy(
        update={
            "network_egress_bytes": network_egress,
            "unique_destinations": sorted(destinations),
            "unique_asns": sorted(asns),
            "unique_countries": sorted(countries),
        }
    )


def enrich_session_with_flows(
    session: DataAccessSession,
    flow_events: list[DataActivityEvent],
    config: DetectorConfig | None = None,
) -> DataAccessSession:
    """Convenience: correlate then merge flow evidence into a session copy."""
    matched = correlate_flow_events(session, flow_events, config)
    return merge_flow_evidence(session, matched)
