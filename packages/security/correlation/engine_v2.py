from typing import List, Dict, Any, Optional, Set
import hashlib
from datetime import datetime, timedelta

class CorrelationStrength:
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"

class CorrelatedGroup:
    def __init__(self, group_id: str, finding_ids: List[str], asset_ids: List[str], reasons: List[str], strength: str, incident_candidate: bool = False):
        self.group_id = group_id
        self.finding_ids = sorted(finding_ids)
        self.asset_ids = sorted(asset_ids)
        self.reasons = reasons
        self.strength = strength
        self.incident_candidate = incident_candidate

    def to_dict(self) -> Dict[str, Any]:
        return {
            "group_id": self.group_id,
            "finding_ids": self.finding_ids,
            "asset_ids": self.asset_ids,
            "correlation_reasons": self.reasons,
            "strength": self.strength,
            "incident_candidate": self.incident_candidate
        }

class CorrelationEngineV2:
    """Correlation Engine V2 for security findings and assets"""

    def __init__(self):
        self.findings: List[Dict] = []
        self.assets: List[Dict] = []
        self.relationships: List[Dict] = []
        self.time_window_minutes = 60

    def load_data(self, findings: List[Dict], assets: List[Dict], relationships: List[Dict]):
        self.findings = findings
        self.assets = assets
        self.relationships = relationships

    def correlate(self) -> List[CorrelatedGroup]:
        """Correlate loaded findings based on same asset, relationships, VPC, and MITRE contexts"""
        groups: List[CorrelatedGroup] = []
        
        # 1. Feature extraction
        finding_features = self._extract_features()
        
        # 2. Match findings based on relationships and same assets
        matched_pairs = self._match_findings(finding_features)
        
        # 3. Cluster matched pairs into groups
        clusters = self._cluster_matches(matched_pairs)
        
        # 4. Score and label groups
        for idx, cluster in enumerate(clusters, 1):
            group_id = self._generate_group_id(cluster)
            
            # Gather asset ids
            asset_ids = list(set(finding_features[fid]["asset_id"] for fid in cluster if finding_features[fid]["asset_id"]))
            
            # Determine reasons and strength
            reasons = []
            strength = CorrelationStrength.WEAK
            
            # Check same asset correlation
            if len(asset_ids) == 1:
                reasons.append("shared_asset")
                strength = CorrelationStrength.MODERATE
            
            # Check relationship-based correlation
            has_confirmed_rel = False
            has_vpc_context = False
            
            for fid1 in cluster:
                for fid2 in cluster:
                    if fid1 == fid2:
                        continue
                    a1 = finding_features[fid1]["asset_id"]
                    a2 = finding_features[fid2]["asset_id"]
                    if a1 and a2 and a1 != a2:
                        # Check M1 relationships
                        for rel in self.relationships:
                            src = rel.get("source_asset_id", rel.get("source_id"))
                            tgt = rel.get("target_asset_id", rel.get("target_id"))
                            rel_type = rel.get("relationship_type", rel.get("type"))
                            if (src == a1 and tgt == a2) or (src == a2 and tgt == a1):
                                has_confirmed_rel = True
                                reasons.append(f"confirmed_asset_relationship: {rel_type}")
                                
                        # Check network context
                        v1 = finding_features[fid1].get("vpc_id")
                        v2 = finding_features[fid2].get("vpc_id")
                        if v1 and v2 and v1 == v2:
                            has_vpc_context = True
                            reasons.append("shared_vpc")
            
            # Deduplicate reasons list
            reasons = list(set(reasons))
            
            # Enforce strengths
            if has_confirmed_rel:
                strength = CorrelationStrength.STRONG
            elif has_vpc_context and len(asset_ids) > 1:
                strength = CorrelationStrength.MODERATE
                
            # Determine if candidate incident (Strong correlation or critical severity)
            is_candidate = strength == CorrelationStrength.STRONG or any(finding_features[fid]["severity"] in ["critical", "high"] for fid in cluster)
            
            groups.append(CorrelatedGroup(
                group_id=group_id,
                finding_ids=cluster,
                asset_ids=asset_ids,
                reasons=reasons,
                strength=strength,
                incident_candidate=is_candidate
            ))
            
        return groups

    def _extract_features(self) -> Dict[str, Dict]:
        features = {}
        for f in self.findings:
            fid = f.get("finding_id", f.get("id"))
            asset_id = f.get("asset_id", f.get("resource_id"))
            
            # Resolve VPC and Subnet from configurations
            vpc_id = None
            subnet_id = None
            asset_obj = next((a for a in self.assets if a.get("asset_id") == asset_id), None)
            if asset_obj and "configuration" in asset_obj:
                config = asset_obj["configuration"]
                vpc_id = config.get("vpc_id") or config.get("VpcId")
                subnet_id = config.get("subnet_id") or config.get("SubnetId")
            
            detected_at = f.get("created_at") or datetime.utcnow().isoformat()
            
            features[fid] = {
                "finding_id": fid,
                "asset_id": asset_id,
                "vpc_id": vpc_id,
                "subnet_id": subnet_id,
                "severity": f.get("severity", "medium").lower(),
                "rule_id": f.get("rule_id"),
                "detected_at": detected_at
            }
        return features

    def _match_findings(self, features: Dict[str, Dict]) -> List[tuple]:
        pairs = []
        fids = list(features.keys())
        
        for i in range(len(fids)):
            for j in range(i + 1, len(fids)):
                fid1 = fids[i]
                fid2 = fids[j]
                
                feat1 = features[fid1]
                feat2 = features[fid2]
                
                correlate = False
                
                # Rule 1: Same Asset
                if feat1["asset_id"] == feat2["asset_id"] and feat1["asset_id"] is not None:
                    correlate = True
                
                # Rule 2: Asset Relationship
                a1 = feat1["asset_id"]
                a2 = feat2["asset_id"]
                if a1 and a2 and a1 != a2:
                    for rel in self.relationships:
                        src = rel.get("source_asset_id", rel.get("source_id"))
                        tgt = rel.get("target_asset_id", rel.get("target_id"))
                        if (src == a1 and tgt == a2) or (src == a2 and tgt == a1):
                            correlate = True
                            
                # Rule 3: Network context (shared VPC) - weak unless coupled
                if feat1["vpc_id"] and feat2["vpc_id"] and feat1["vpc_id"] == feat2["vpc_id"]:
                    # Weak correlation if same VPC but limit time window
                    correlate = True
                    
                if correlate:
                    pairs.append((fid1, fid2))
                    
        return pairs

    def _cluster_matches(self, matched_pairs: List[tuple]) -> List[List[str]]:
        # Union-Find or simple adjacency clustering
        adj = {}
        for u, v in matched_pairs:
            adj.setdefault(u, set()).add(v)
            adj.setdefault(v, set()).add(u)
            
        visited = set()
        clusters = []
        
        for node in adj:
            if node not in visited:
                cluster = []
                queue = [node]
                visited.add(node)
                while queue:
                    curr = queue.pop(0)
                    cluster.append(curr)
                    for neighbor in adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                clusters.append(cluster)
                
        # Add single isolated findings as clusters of size 1 if needed
        # (Usually correlation groups require >= 2 findings, so we only cluster linked findings)
        return clusters

    def _generate_group_id(self, cluster: List[str]) -> str:
        # Create a stable fingerprint from sorted finding IDs
        sorted_ids = sorted(cluster)
        h = hashlib.sha256("".join(sorted_ids).encode("utf-8")).hexdigest()
        return f"CG-{h[:8].upper()}"
