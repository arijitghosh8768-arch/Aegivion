from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass, field

@dataclass
class AttackPath:
    path_id: str
    nodes: List[str]
    edges: List[str]
    risk_score: int
    confidence: str
    evidence: List[Dict[str, Any]]

class AttackGraphEngine:
    """Attack Graph Engine for finding and scoring potential security attack paths"""

    def __init__(self):
        self.nodes: List[Dict[str, Any]] = []
        self.relationships: List[Dict[str, Any]] = []
        self.adjacency: Dict[str, List[Dict[str, Any]]] = {}

    def load_data(self, assets: List[Dict], relationships: List[Dict]):
        self.nodes = assets
        self.relationships = relationships
        self.adjacency = {}
        
        # Build node indices
        for asset in assets:
            aid = asset.get("resource_id", asset.get("asset_id"))
            self.adjacency[aid] = []

        # Add "INTERNET" virtual node
        if "INTERNET" not in self.adjacency:
            self.adjacency["INTERNET"] = []

        # Build adjacency map of valid security edges
        for rel in relationships:
            src = rel.get("source_asset_id", rel.get("source_id"))
            tgt = rel.get("target_asset_id", rel.get("target_id"))
            rel_type = rel.get("relationship_type", rel.get("type"))
            
            # Map network exposure
            if rel_type == "EXPOSED_TO" or (rel_type == "PROTECTED_BY" and rel.get("evidence", {}).get("public_ip")):
                self.adjacency["INTERNET"].append({
                    "target": src,
                    "type": "EXPOSED_TO",
                    "rel_data": rel
                })

            if src in self.adjacency:
                self.adjacency[src].append({
                    "target": tgt,
                    "type": rel_type,
                    "rel_data": rel
                })

    def find_paths(self, start_node: str = "INTERNET", max_depth: int = 5) -> List[AttackPath]:
        """Perform depth-limited DFS to find attack paths ending at S3 buckets or privileged roles"""
        paths: List[AttackPath] = []
        visited = set()

        def dfs(current: str, current_nodes: List[str], current_edges: List[str], current_evidence: List[Dict], depth: int):
            if depth > max_depth:
                return
            
            # Check if target reached (e.g. S3 bucket, RDS instance, or role with policy)
            is_target = "s3:" in current.lower() or "bucket" in current.lower() or "role" in current.lower()
            if is_target and len(current_nodes) > 1:
                # Generate unique path ID
                nodes_hash = "-".join(current_nodes)
                path_id = f"PATH-{abs(hash(nodes_hash)) % 10000:04d}"
                
                # Determine risk and confidence
                risk_score = 94 if "critical" in str(current_evidence).lower() or any(e.lower() == "uses_role" for e in current_edges) else 75
                confidence = "HIGH" if all(ev.get("confidence", "CONFIRMED") == "CONFIRMED" for ev in current_evidence) else "MEDIUM"
                
                paths.append(AttackPath(
                    path_id=path_id,
                    nodes=list(current_nodes),
                    edges=list(current_edges),
                    risk_score=risk_score,
                    confidence=confidence,
                    evidence=list(current_evidence)
                ))

            if current not in self.adjacency:
                return

            for neighbor in self.adjacency[current]:
                target = neighbor["target"]
                if target not in visited:
                    visited.add(target)
                    current_nodes.append(target)
                    current_edges.append(neighbor["type"])
                    current_evidence.append(neighbor["rel_data"])
                    
                    dfs(target, current_nodes, current_edges, current_evidence, depth + 1)
                    
                    current_evidence.pop()
                    current_edges.pop()
                    current_nodes.pop()
                    visited.remove(target)

        visited.add(start_node)
        dfs(start_node, [start_node], [], [], 0)
        return paths
