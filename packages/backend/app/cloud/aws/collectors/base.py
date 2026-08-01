from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseCollector(ABC):
    """Base class for all AWS collectors"""
    
    def __init__(self, session, region: str):
        self.session = session
        self.region = region
        self.collector_name = "base"
        
    @abstractmethod
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect assets from region"""
        pass
