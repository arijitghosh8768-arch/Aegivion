import uuid
import hashlib
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field

from security.engine.detectors.base import DetectionResult

class BoundedTenantContext:
    def __init__(self, org_id: str, max_events: int = 1000, max_detections: int = 500, max_window_minutes: int = 60):
        self.org_id = org_id
        self.max_events = max_events
        self.max_detections = max_detections
        self.max_window_minutes = max_window_minutes
        
        self.events: List[Dict[str, Any]] = []
        self.detections: List[Dict[str, Any]] = []
        self._event_ids: Set[str] = set()
        self._detection_ids: Set[str] = set()

    def _evict_expired(self, current_time: datetime):
        cutoff = current_time - timedelta(minutes=self.max_window_minutes)
        
        # Evict events
        valid_events = []
        for e in self.events:
            dt = e.get("occurred_at")
            if dt and isinstance(dt, str):
                try:
                    dt = datetime.fromisoformat(dt)
                except ValueError:
                    dt = current_time
            elif not isinstance(dt, datetime):
                dt = current_time
                
            if dt >= cutoff:
                valid_events.append(e)
            else:
                self._event_ids.discard(e.get("event_id"))
        
        self.events = valid_events
        
        # Evict detections
        valid_detections = []
        for d in self.detections:
            dt = d.get("timestamp")
            if dt and isinstance(dt, str):
                try:
                    dt = datetime.fromisoformat(dt)
                except ValueError:
                    dt = current_time
            elif not isinstance(dt, datetime):
                dt = current_time
                
            if dt >= cutoff:
                valid_detections.append(d)
            else:
                self._detection_ids.discard(d.get("detection_id"))
                
        self.detections = valid_detections

    def _evict_capacity(self):
        # Sort and truncate
        # Assumes already sorted by time asc
        if len(self.events) > self.max_events:
            evicted = self.events[:-self.max_events]
            self.events = self.events[-self.max_events:]
            for e in evicted:
                self._event_ids.discard(e.get("event_id"))
                
        if len(self.detections) > self.max_detections:
            evicted = self.detections[:-self.max_detections]
            self.detections = self.detections[-self.max_detections:]
            for d in evicted:
                self._detection_ids.discard(d.get("detection_id"))

    def add_event(self, event: Dict[str, Any]):
        event_id = event.get("event_id")
        if not event_id or event_id in self._event_ids:
            return False # Duplicate or invalid
            
        current_time = datetime.now(timezone.utc)
        
        # Check if the new event is already expired
        dt = event.get("occurred_at")
        if dt and isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt)
            except ValueError:
                dt = current_time
        elif not isinstance(dt, datetime):
            dt = current_time
            
        cutoff = current_time - timedelta(minutes=self.max_window_minutes)
        if dt < cutoff:
            return False # Already expired
            
        self._evict_expired(current_time)
        
        self.events.append(event)
        self._event_ids.add(event_id)
        
        # Sort events by timestamp ASC, then event_id ASC
        def sort_key(e):
            dt = e.get("occurred_at")
            if isinstance(dt, str):
                try:
                    dt = datetime.fromisoformat(dt)
                except:
                    dt = current_time
            elif not isinstance(dt, datetime):
                dt = current_time
            return (dt, e.get("event_id", ""))
            
        self.events.sort(key=sort_key)
        self._evict_capacity()
        return True

    def add_detection(self, detection: Dict[str, Any]):
        detection_id = detection.get("detection_id")
        if not detection_id or detection_id in self._detection_ids:
            return False
            
        current_time = datetime.now(timezone.utc)
        
        # Check if the new detection is already expired
        dt = detection.get("timestamp")
        if dt and isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt)
            except ValueError:
                dt = current_time
        elif not isinstance(dt, datetime):
            dt = current_time
            
        cutoff = current_time - timedelta(minutes=self.max_window_minutes)
        if dt < cutoff:
            return False # Already expired
            
        self._evict_expired(current_time)
        
        self.detections.append(detection)
        self._detection_ids.add(detection_id)
        
        def sort_key(d):
            dt = d.get("timestamp")
            if isinstance(dt, str):
                try:
                    dt = datetime.fromisoformat(dt)
                except:
                    dt = current_time
            elif not isinstance(dt, datetime):
                dt = current_time
            return (dt, d.get("detection_id", ""))
            
        self.detections.sort(key=sort_key)
        self._evict_capacity()
        return True

    def get_related_detections(self, detection: Dict[str, Any]) -> List[Dict[str, Any]]:
        related = []
        for d in self.detections:
            if d.get("detection_id") == detection.get("detection_id"):
                continue
            
            # Related if same actor, target, or correlation_id
            d_actor = d.get("actor_id")
            my_actor = detection.get("actor_id")
            if d_actor and my_actor and d_actor == my_actor:
                related.append(d)
                continue
                
            d_corr = d.get("correlation_id")
            my_corr = detection.get("correlation_id")
            if d_corr and my_corr and d_corr == my_corr:
                related.append(d)
                continue
                
        return related

class DetectionContext:
    def __init__(self, max_events_per_tenant: int = 1000, max_detections_per_tenant: int = 500, max_window_minutes: int = 60):
        self.max_events = max_events_per_tenant
        self.max_detections = max_detections_per_tenant
        self.max_window_minutes = max_window_minutes
        self._tenants: Dict[str, BoundedTenantContext] = {}

    def _get_tenant(self, org_id: str) -> BoundedTenantContext:
        if org_id not in self._tenants:
            self._tenants[org_id] = BoundedTenantContext(
                org_id=org_id, 
                max_events=self.max_events, 
                max_detections=self.max_detections, 
                max_window_minutes=self.max_window_minutes
            )
        return self._tenants[org_id]

    def add_event(self, org_id: str, event: Dict[str, Any]) -> bool:
        tenant = self._get_tenant(org_id)
        return tenant.add_event(event)

    def add_detection(self, org_id: str, detection: Dict[str, Any]) -> bool:
        tenant = self._get_tenant(org_id)
        return tenant.add_detection(detection)

    def generate_detection_id(self, org_id: str, event_id: str, detector_name: str) -> str:
        s = f"{org_id}|{event_id}|{detector_name}"
        return hashlib.sha256(s.encode("utf-8")).hexdigest()
        
    def get_context_for_correlation(self, org_id: str, new_detection: Dict[str, Any]) -> List[Dict[str, Any]]:
        tenant = self._get_tenant(org_id)
        return tenant.get_related_detections(new_detection)
