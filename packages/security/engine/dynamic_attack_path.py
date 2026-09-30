from typing import Dict, Any, List
from datetime import datetime, timezone
import uuid
from pydantic import BaseModel, Field
from enum import Enum

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RiskContribution(BaseModel):
    element_id: str
    element_type: str  # "node" or "edge"
    factor: str
    contribution: float
    classification: str  # "OBSERVED", "INFERRED", "UNKNOWN"

class DynamicAttackPathRiskResult(BaseModel):
    path_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str
    entry_node: str
    target_node: str
    path_nodes: List[str]
    path_edges: List[str]
    path_length: int
    risk_score: float
    risk_level: RiskLevel
    node_contributions: List[RiskContribution]
    edge_contributions: List[RiskContribution]
    dominant_factors: List[str]
    target_impact: float
    recalculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    algorithm_version: str = "1.0"

class DynamicAttackPathRiskEngine:
    """
    Calculates the inherent security risk of an actual graph path through the cloud environment.
    This does NOT check if the path is currently activated by a detection, it only measures
    the structural and config-based risk of the path itself.
    """
    
    def calculate_risk(self, organization_id: str, path_nodes: List[Dict[str, Any]], path_edges: List[Dict[str, Any]]) -> DynamicAttackPathRiskResult:
        if not path_nodes:
            raise ValueError("Path must contain at least one node")
            
        entry_node = path_nodes[0]
        target_node = path_nodes[-1]
        
        node_contribs = []
        edge_contribs = []
        
        # We will calculate a base risk score through multiplicative attenuation and additive factors.
        # Initial score is based on the entry node risk
        
        # 1. ENTRY RISK
        entry_risk = float(entry_node.get("risk_score", 0.1))
        node_contribs.append(RiskContribution(
            element_id=entry_node.get("id", "unknown"),
            element_type="node",
            factor="ENTRY_RISK",
            contribution=entry_risk,
            classification="OBSERVED" if "risk_score" in entry_node else "UNKNOWN"
        ))
        
        score = entry_risk
        
        # Evaluate all nodes
        has_privileged_identity = False
        target_criticality_score = 0.1
        
        for i, node in enumerate(path_nodes):
            node_id = node.get("id", f"node-{i}")
            
            # 2. IDENTITY / PRIVILEGE RISK
            if node.get("type") in ["CloudIdentity", "IAMRole", "IAMUser"]:
                privilege = node.get("privilege_level", "standard").lower()
                priv_bump = 0.0
                if privilege == "administrative":
                    priv_bump = 0.4
                    has_privileged_identity = True
                elif privilege in ["elevated", "write", "delete"]:
                    priv_bump = 0.2
                    has_privileged_identity = True
                
                if priv_bump > 0:
                    node_contribs.append(RiskContribution(
                        element_id=node_id,
                        element_type="node",
                        factor="PRIVILEGED_ACCESS",
                        contribution=priv_bump,
                        classification="OBSERVED"
                    ))
                    score += priv_bump
                    
            # 4. ASSET CRITICALITY & 7. TARGET IMPACT
            criticality = node.get("criticality", "unknown").lower()
            crit_bump = 0.0
            if criticality in ["mission_critical", "production", "sensitive"]:
                crit_bump = 0.3
            elif criticality in ["high", "database", "identity_infrastructure"]:
                crit_bump = 0.2
                
            if crit_bump > 0:
                # If it's the target node, we weight it higher
                if i == len(path_nodes) - 1:
                    target_criticality_score = crit_bump * 1.5
                    node_contribs.append(RiskContribution(
                        element_id=node_id,
                        element_type="node",
                        factor="TARGET_IMPACT",
                        contribution=target_criticality_score,
                        classification="OBSERVED"
                    ))
                    score += target_criticality_score
                else:
                    node_contribs.append(RiskContribution(
                        element_id=node_id,
                        element_type="node",
                        factor="INTERMEDIATE_CRITICALITY",
                        contribution=crit_bump,
                        classification="OBSERVED"
                    ))
                    score += crit_bump

        # 5. RELATIONSHIP RISK
        edge_multiplier = 1.0
        for edge in path_edges:
            edge_id = f"{edge.get('source')} -> {edge.get('target')}"
            edge_type = edge.get("type", "UNKNOWN").upper()
            
            # Different edges transmit risk differently
            if edge_type in ["OWNS", "ASSUMES_ROLE"]:
                edge_bump = 0.15
                edge_multiplier *= 0.95  # strong link, minimal attenuation
            elif edge_type in ["HAS_PERMISSION", "CAN_ACCESS"]:
                edge_bump = 0.1
                edge_multiplier *= 0.90
            elif edge_type in ["CONNECTED_TO"]:
                edge_bump = 0.05
                edge_multiplier *= 0.80  # weaker link, more attenuation
            else:
                edge_bump = 0.0
                edge_multiplier *= 0.70
                
            edge_contribs.append(RiskContribution(
                element_id=edge_id,
                element_type="edge",
                factor=f"RELATIONSHIP_{edge_type}",
                contribution=edge_bump,
                classification="OBSERVED" if edge_type != "UNKNOWN" else "UNKNOWN"
            ))
            score += edge_bump
            
        # 3. REACHABILITY RISK & 6. PATH LENGTH
        # The longer the path, the more friction there is to traverse it, attenuating the total score.
        # But a direct path to a critical resource is highly dangerous.
        path_length = len(path_edges)
        if path_length == 1:
            # Direct path: high risk
            reachability_factor = 1.2
            node_contribs.append(RiskContribution(
                element_id="path",
                element_type="node",
                factor="DIRECT_REACHABILITY",
                contribution=0.1,
                classification="INFERRED"
            ))
            score += 0.1
        else:
            reachability_factor = max(0.5, 1.0 - (path_length * 0.05))
            
        # Apply multipliers
        final_score = score * edge_multiplier * reachability_factor
        
        # Normalization and caps
        final_score = min(1.0, max(0.0, final_score))
        
        # Risk level mapping
        if final_score >= 0.85:
            risk_level = RiskLevel.CRITICAL
        elif final_score >= 0.65:
            risk_level = RiskLevel.HIGH
        elif final_score >= 0.40:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
            
        dominant_factors = []
        if has_privileged_identity: dominant_factors.append("PRIVILEGED_ACCESS")
        if target_criticality_score >= 0.3: dominant_factors.append("HIGH_TARGET_IMPACT")
        if path_length == 1: dominant_factors.append("DIRECT_REACHABILITY")
            
        return DynamicAttackPathRiskResult(
            organization_id=organization_id,
            entry_node=entry_node.get("id", "unknown"),
            target_node=target_node.get("id", "unknown"),
            path_nodes=[n.get("id", "unknown") for n in path_nodes],
            path_edges=[f"{e.get('source')} -> {e.get('target')}" for e in path_edges],
            path_length=path_length,
            risk_score=round(final_score, 2),
            risk_level=risk_level,
            node_contributions=node_contribs,
            edge_contributions=edge_contribs,
            dominant_factors=dominant_factors,
            target_impact=target_criticality_score
        )
