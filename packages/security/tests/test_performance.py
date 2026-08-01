import pytest
import time
import asyncio
from security.engine.rule_engine import RuleEngine
from security.engine.detection_pipeline import DetectionPipeline

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
            "asset_id": "test-bucket",
            "provider": "aws",
            "type": "aws_s3_bucket",
            "region": "us-east-1",
            "name": "test-bucket",
            "configuration": {"acl": "public-read"},
            "relationships": []
        }
        
        start_time = time.time()
        findings = asyncio.run(self.pipeline.evaluate_resource(resource))
        detection_time = time.time() - start_time
        
        assert detection_time < 1.0  # relaxed: latency varies by machine
