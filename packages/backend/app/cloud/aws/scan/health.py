from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime

class CollectorStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_ATTEMPTED = "not_attempted"

class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"

@dataclass
class CollectorHealth:
    name: str
    status: CollectorStatus
    assets_discovered: int
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'status': self.status.value,
            'assets': self.assets_discovered,
            'errors': self.errors,
            'warnings': self.warnings,
            'duration_ms': self.duration_ms
        }

@dataclass
class ScanHealth:
    scan_id: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime]
    collectors: List[CollectorHealth]
    total_assets: int
    total_relationships: int
    coverage_percentage: float  # 0.0 - 1.0
    missing_critical_data: bool
    warnings: List[str] = field(default_factory=list)

class ScanHealthService:
    """Track and report scan health"""
    
    def __init__(self):
        self.scans: Dict[str, ScanHealth] = {}
    
    def create_scan_record(self, scan_id: str) -> None:
        """Create a new scan record"""
        self.scans[scan_id] = ScanHealth(
            scan_id=scan_id,
            status=ScanStatus.QUEUED,
            started_at=datetime.utcnow(),
            completed_at=None,
            collectors=[],
            total_assets=0,
            total_relationships=0,
            coverage_percentage=0.0,
            missing_critical_data=False,
            warnings=[]
        )
    
    def update_collector_status(
        self, 
        scan_id: str, 
        collector_name: str,
        status: CollectorStatus,
        assets: int = 0,
        errors: List[str] = None,
        warnings: List[str] = None,
        duration: int = 0
    ) -> None:
        """Update a collector's status"""
        if scan_id not in self.scans:
            self.create_scan_record(scan_id)
        
        health = self.scans[scan_id]
        
        # Find or create collector entry
        collector = next(
            (c for c in health.collectors if c.name == collector_name),
            None
        )
        
        if collector:
            collector.status = status
            collector.assets_discovered = assets
            collector.errors = errors or []
            collector.warnings = warnings or []
            collector.duration_ms = duration
        else:
            health.collectors.append(CollectorHealth(
                name=collector_name,
                status=status,
                assets_discovered=assets,
                errors=errors or [],
                warnings=warnings or [],
                duration_ms=duration
            ))
        
        self._recalculate_scan_health(scan_id)
    
    def _recalculate_scan_health(self, scan_id: str) -> None:
        """Recalculate overall scan health"""
        health = self.scans[scan_id]
        
        # Count statuses
        status_counts = {
            CollectorStatus.SUCCESS: 0,
            CollectorStatus.PARTIAL: 0,
            CollectorStatus.FAILED: 0,
            CollectorStatus.NOT_ATTEMPTED: 0
        }
        
        for collector in health.collectors:
            status_counts[collector.status] = status_counts.get(collector.status, 0) + 1
        
        total = len(health.collectors)
        
        if total == 0:
            health.status = ScanStatus.RUNNING
            health.coverage_percentage = 0.0
            return
        
        # Determine scan status
        if status_counts[CollectorStatus.FAILED] == total:
            health.status = ScanStatus.FAILED
        elif status_counts[CollectorStatus.FAILED] > 0:
            health.status = ScanStatus.PARTIAL
        elif status_counts[CollectorStatus.PARTIAL] > 0:
            health.status = ScanStatus.PARTIAL
        else:
            health.status = ScanStatus.COMPLETED
        
        # Calculate coverage
        successful = status_counts[CollectorStatus.SUCCESS]
        health.coverage_percentage = successful / total
        
        # Check for critical missing data
        critical_collectors = ['iam', 's3', 'network', 'security_groups', 'iam_user', 's3_bucket']
        for collector in health.collectors:
            if collector.name.lower() in critical_collectors:
                if collector.status in [CollectorStatus.FAILED, CollectorStatus.PARTIAL]:
                    health.missing_critical_data = True
                    msg = f"Critical collector '{collector.name}' has incomplete data"
                    if msg not in health.warnings:
                        health.warnings.append(msg)
        
        # Calculate total assets
        health.total_assets = sum(c.assets_discovered for c in health.collectors)
        
        # Complete scan
        if health.status in [ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED]:
            health.completed_at = datetime.utcnow()
    
    def get_scan_health(self, scan_id: str) -> Optional[ScanHealth]:
        """Get scan health by ID"""
        return self.scans.get(scan_id)
    
    def get_scan_summary(self, scan_id: str) -> Dict[str, Any]:
        """Get user-friendly scan summary"""
        health = self.scans.get(scan_id)
        if not health:
            return {'error': 'Scan not found'}
        
        return {
            'scan_id': health.scan_id,
            'status': health.status.value,
            'started_at': health.started_at.isoformat(),
            'completed_at': health.completed_at.isoformat() if health.completed_at else None,
            'collectors': [c.to_dict() for c in health.collectors],
            'total_assets': health.total_assets,
            'coverage_percentage': int(health.coverage_percentage * 100),
            'missing_critical_data': health.missing_critical_data,
            'warnings': health.warnings
        }
