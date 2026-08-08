from typing import Dict, Any, Optional
from dataclasses import dataclass
import httpx
import logging

logger = logging.getLogger(__name__)

@dataclass
class AIContext:
    finding_id: str
    finding: Dict[str, Any]
    asset: Dict[str, Any]
    evidence: Dict[str, Any]
    risk: Optional[Dict[str, Any]]
    mitre: list
    is_valid: bool
    validation_errors: list

class ContextBuilder:
    """Build validated AI context from real findings"""
    
    def __init__(self, api_base_url: str):
        self.api_base_url = api_base_url
        self.client = httpx.AsyncClient(timeout=10.0)
    
    async def build_context(self, finding_id: str) -> AIContext:
        """Build context from real finding data"""
        
        validation_errors = []
        
        try:
            # Fetch finding
            finding = await self._get_finding(finding_id)
            if not finding:
                return self._invalid_context(finding_id, ["Finding not found"])
            
            # Fetch asset
            asset = await self._get_asset(finding.get('asset_id'))
            if not asset:
                validation_errors.append("Asset not found")
            
            # Validate
            is_valid, errors = self._validate_context(finding, asset)
            validation_errors.extend(errors)
            
            return AIContext(
                finding_id=finding_id,
                finding=finding,
                asset=asset or {},
                evidence=finding.get('evidence', {}),
                risk=finding.get('risk'),
                mitre=finding.get('mitre_techniques', []),
                is_valid=is_valid,
                validation_errors=validation_errors
            )
            
        except Exception as e:
            logger.error(f"Context building failed: {str(e)}")
            return self._invalid_context(finding_id, [str(e)])
    
    async def _get_finding(self, finding_id: str) -> Optional[Dict]:
        """Get finding from API"""
        try:
            response = await self.client.get(
                f"{self.api_base_url}/api/v1/findings/{finding_id}"
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Failed to fetch finding: {str(e)}")
            return None
    
    async def _get_asset(self, asset_id: str) -> Optional[Dict]:
        """Get asset from API"""
        if not asset_id:
            return None
        try:
            response = await self.client.get(
                f"{self.api_base_url}/api/v1/assets/{asset_id}"
            )
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Failed to fetch asset: {str(e)}")
            return None
    
    def _validate_context(self, finding: Dict, asset: Dict) -> tuple:
        """Validate context completeness"""
        errors = []
        
        # Required finding fields
        required_fields = ['finding_id', 'title', 'description', 'severity', 'evidence']
        for field in required_fields:
            if field not in finding or finding[field] is None:
                errors.append(f"Finding missing required field: {field}")
        
        # Required asset fields
        if asset:
            if not asset.get('asset_id'):
                errors.append("Asset missing asset_id")
            if not asset.get('resource_type') and not asset.get('type'):
                errors.append("Asset missing resource_type")
        
        # Evidence validation
        evidence = finding.get('evidence', {})
        if not evidence:
            errors.append("Finding has no evidence")
        
        # Determine validity
        is_valid = len(errors) == 0
        return is_valid, errors
    
    def _invalid_context(self, finding_id: str, errors: list) -> AIContext:
        """Create invalid context"""
        return AIContext(
            finding_id=finding_id,
            finding={},
            asset={},
            evidence={},
            risk=None,
            mitre=[],
            is_valid=False,
            validation_errors=errors
        )
    
    async def close(self):
        """Close HTTP client"""
        await self.client.aclose()
