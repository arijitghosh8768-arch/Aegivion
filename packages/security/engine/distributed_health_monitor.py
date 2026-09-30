import logging
from typing import Optional, List
from datetime import timedelta
from security.utils.clock import Clock
from security.models.distributed_health import (
    WorkerIdentity, HealthState, NodeHealth, DistributedHealthSnapshot
)
from security.engine.persistence.health_repository import WorkerHealthRepository

logger = logging.getLogger(__name__)

class DistributedHealthMonitor:
    def __init__(
        self, 
        repository: WorkerHealthRepository,
        stale_timeout_seconds: int = 15,
        critical_worker_types: Optional[List[str]] = None
    ):
        self.repository = repository
        self.stale_timeout = timedelta(seconds=stale_timeout_seconds)
        self.critical_worker_types = critical_worker_types or ["EVENT_INGESTION", "DETECTION_CORRELATION"]
        
    async def check_stale_workers(self):
        workers = await self.repository.list_workers()
        now = Clock.get_instance().now()
        
        for w in workers:
            if w.state in (HealthState.HEALTHY, HealthState.DEGRADED):
                if now - w.last_heartbeat > self.stale_timeout:
                    await self.repository.mark_stale(w.worker_id)
                    logger.warning(f"Worker {w.worker_id} marked as STALE. Last heartbeat: {w.last_heartbeat}")

    async def get_health_snapshot(self) -> DistributedHealthSnapshot:
        workers = await self.repository.list_workers()
        now = Clock.get_instance().now()
        
        nodes_map = {}
        for w in workers:
            if w.node_id not in nodes_map:
                nodes_map[w.node_id] = {
                    "workers": [],
                    "healthy": 0,
                    "degraded": 0,
                    "stale": 0,
                    "failed": 0,
                    "queue_depth": 0,
                    "queue_capacity": 0,
                    "retry": 0,
                    "dlq": 0,
                    "last_heartbeat": w.last_heartbeat
                }
            
            nm = nodes_map[w.node_id]
            nm["workers"].append(w)
            
            if w.state == HealthState.HEALTHY:
                nm["healthy"] += 1
            elif w.state == HealthState.DEGRADED:
                nm["degraded"] += 1
            elif w.state == HealthState.STALE:
                nm["stale"] += 1
            elif w.state == HealthState.FAILED:
                nm["failed"] += 1
                
            nm["queue_depth"] += w.queue_depth
            nm["queue_capacity"] += w.queue_capacity
            nm["retry"] += w.retry_wait_count
            nm["dlq"] += w.dead_letter_count
            
            if w.last_heartbeat > nm["last_heartbeat"]:
                nm["last_heartbeat"] = w.last_heartbeat

        node_healths = []
        for node_id, nm in nodes_map.items():
            q_util = nm["queue_depth"] / nm["queue_capacity"] if nm["queue_capacity"] > 0 else 0.0
            
            if nm["healthy"] > 0 and nm["failed"] == 0 and nm["stale"] == 0:
                node_state = HealthState.HEALTHY
            elif nm["healthy"] > 0 and (nm["failed"] > 0 or nm["stale"] > 0):
                node_state = HealthState.DEGRADED
            elif nm["healthy"] == 0 and nm["degraded"] > 0:
                node_state = HealthState.DEGRADED
            elif nm["healthy"] == 0 and nm["degraded"] == 0 and nm["failed"] > 0:
                node_state = HealthState.FAILED
            elif nm["healthy"] == 0 and nm["degraded"] == 0 and nm["stale"] > 0:
                node_state = HealthState.FAILED
            else:
                node_state = HealthState.UNKNOWN

            nh = NodeHealth(
                node_id=node_id,
                state=node_state,
                worker_count=len(nm["workers"]),
                healthy_workers=nm["healthy"],
                degraded_workers=nm["degraded"],
                stale_workers=nm["stale"],
                failed_workers=nm["failed"],
                queue_depth=nm["queue_depth"],
                queue_capacity=nm["queue_capacity"],
                queue_utilization=q_util,
                last_heartbeat=nm["last_heartbeat"],
                updated_at=now
            )
            node_healths.append(nh)

        # Cluster metrics
        total_workers = sum(n.worker_count for n in node_healths)
        total_healthy = sum(n.healthy_workers for n in node_healths)
        total_degraded = sum(n.degraded_workers for n in node_healths)
        total_stale = sum(n.stale_workers for n in node_healths)
        total_failed = sum(n.failed_workers for n in node_healths)
        
        t_depth = sum(n.queue_depth for n in node_healths)
        t_cap = sum(n.queue_capacity for n in node_healths)
        t_util = t_depth / t_cap if t_cap > 0 else 0.0
        
        # Calculate cluster state based on critical capacity
        # For simplicity, if we have 0 critical capacity -> FAILED
        # If we have degraded critical capacity -> DEGRADED
        
        ingestion_workers = [w for w in workers if w.worker_type == "EVENT_INGESTION"]
        ingestion_healthy = sum(1 for w in ingestion_workers if w.state == HealthState.HEALTHY)
        ingestion_failed_stale = sum(1 for w in ingestion_workers if w.state in (HealthState.FAILED, HealthState.STALE))
        
        correlation_workers = [w for w in workers if w.worker_type == "DETECTION_CORRELATION"]
        correlation_healthy = sum(1 for w in correlation_workers if w.state == HealthState.HEALTHY)
        correlation_failed_stale = sum(1 for w in correlation_workers if w.state in (HealthState.FAILED, HealthState.STALE))

        cluster_state = HealthState.HEALTHY
        reason = "All systems operational"
        
        if len(ingestion_workers) > 0 and ingestion_healthy == 0:
            cluster_state = HealthState.FAILED
            reason = "No healthy ingestion capacity"
        elif len(correlation_workers) > 0 and correlation_healthy == 0:
            cluster_state = HealthState.FAILED
            reason = "No healthy correlation capacity"
        elif ingestion_failed_stale > 0 or correlation_failed_stale > 0:
            cluster_state = HealthState.DEGRADED
            reason = "Partial critical capacity lost"
        elif total_stale > 0 or total_failed > 0:
            cluster_state = HealthState.DEGRADED
            reason = "Non-critical workers degraded/stale"
        elif t_util >= 0.90:
            cluster_state = HealthState.DEGRADED
            reason = "Critical queue pressure"

        if len(workers) == 0:
            cluster_state = HealthState.UNKNOWN
            reason = "No workers registered"

        return DistributedHealthSnapshot(
            timestamp=now,
            nodes=node_healths,
            total_workers=total_workers,
            healthy_workers=total_healthy,
            degraded_workers=total_degraded,
            stale_workers=total_stale,
            failed_workers=total_failed,
            total_queue_depth=t_depth,
            total_queue_capacity=t_cap,
            queue_utilization=t_util,
            healthy_capacity=total_healthy,
            degraded_capacity=total_degraded,
            failed_capacity=total_failed,
            retry_wait_count=sum(nm["retry"] for nm in nodes_map.values()),
            dead_letter_count=sum(nm["dlq"] for nm in nodes_map.values()),
            overall_state=cluster_state,
            health_reason=reason
        )
