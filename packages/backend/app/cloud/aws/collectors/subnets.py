from app.cloud.aws.collectors.base import BaseCollector

class SubnetCollector(BaseCollector):
    def __init__(self, session, region: str):
        super().__init__(session, region)
        self.collector_name = "subnet"
        
    async def collect(self):
        return []
