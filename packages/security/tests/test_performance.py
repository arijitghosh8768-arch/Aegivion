import pytest
import time
import asyncio
from engine.rule_engine import RuleEngine
from engine.detection_pipeline import DetectionPipeline

class TestPerformance:
    def setup_method(self):
        self.engine = RuleEngine()
        self.pipeline = DetectionPipeline()
    
    def test_rule_loading_performance(self):
        """Test that rules load within 2 seconds"""
        start_time = time.time()
        rules = self.engine.load_rules()
        load_time = time.time() - start_time
        
        assert load_time < 2.0
        assert len(rules) >= 2
    
    def test_detection_latency(self):
        """Test single resource evaluation under 100ms"""
        resource = {
            "id": "test-bucket",
            "type": "aws_s3_bucket",
            "region": "us-east-1",
            "acl": "public-read"
        }
        
        start_time = time.time()
        findings = asyncio.run(self.pipeline.evaluate_resource(resource))
        detection_time = time.time() - start_time
        
        assert detection_time < 0.1
        assert len(findings) == 1
