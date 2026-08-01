from app.cloud.aws.collectors.base import BaseCollector

class VPCCollector(BaseCollector):
    def __init__(self, session, region: str):
        super().__init__(session, region)
        self.collector_name = "vpc"
        
    async def collect(self):
        return []
