from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timezone
import uuid
import copy
from pydantic import BaseModel, Field
from enum import Enum

from security.engine.next_stage_prediction import AttackStage, NextStagePredictionResult

class SimulationAsset(BaseModel):
    asset_id: str
    provider: str = "UNKNOWN"
    asset_type: str = "UNKNOWN"
    region: Optional[str] = None
    criticality: Optional[str] = None
    sensitivity: Optional[str] = None
    public: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SimulationIdentity(BaseModel):
    identity_id: str
    provider: str = "UNKNOWN"
    identity_type: str = "UNKNOWN"
    privileges: List[str] = Field(default_factory=list)
    compromised: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SimulationRelationship(BaseModel):
    source_id: str
    target_id: str
    relationship_type: str = "ACCESS"
    permissions: List[str] = Field(default_factory=list)
    active: bool = True

class SimulationState(BaseModel):
    organization_id: str
    assets: Dict[str, SimulationAsset] = Field(default_factory=dict)
    identities: Dict[str, SimulationIdentity] = Field(default_factory=dict)
    relationships: List[SimulationRelationship] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class HypotheticalChange(BaseModel):
    change_type: str
    source_id: Optional[str] = None
    target_id: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)

class SimulationScenario(BaseModel):
    scenario_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str
    predicted_stage: AttackStage = AttackStage.UNKNOWN
    actor_id: Optional[str] = None
    target_asset_ids: List[str] = Field(default_factory=list)
    assumptions: List[str] = Field(default_factory=list)
    hypothetical_changes: List[HypotheticalChange] = Field(default_factory=list)

class SimulationBaseline(BaseModel):
    reachable_assets: Set[str] = Field(default_factory=set)
    attack_paths: List[Any] = Field(default_factory=list)
    critical_assets: Set[str] = Field(default_factory=set)
    path_risk_score: float = 0.0

class SimulatedAttackPath(BaseModel):
    nodes: List[str]
    relationships: List[str]
    path_length: int
    risk_score: float
    reaches_critical_asset: bool

class BlastRadius(BaseModel):
    affected_assets: int = 0
    affected_identities: int = 0
    critical_assets: int = 0
    sensitive_assets: int = 0
    providers_affected: int = 0
    regions_affected: int = 0
    new_reachable_assets: int = 0
    new_attack_paths: int = 0
    max_path_depth: int = 0

class WhatIfSimulationResult(BaseModel):
    simulation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_id: str
    organization_id: str
    simulated_stage: AttackStage
    baseline: SimulationBaseline
    simulated_reachable_assets: Set[str] = Field(default_factory=set)
    new_reachable_assets: Set[str] = Field(default_factory=set)
    lost_reachable_assets: Set[str] = Field(default_factory=set)
    new_attack_paths: List[SimulatedAttackPath] = Field(default_factory=list)
    blast_radius: BlastRadius
    baseline_risk_score: float
    simulated_risk_score: float
    risk_delta: float
    impact_level: str
    assumptions: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    uncertainty: str
    state: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

ALLOWED_SIMULATION_CHANGES = {
    "MARK_IDENTITY_COMPROMISED",
    "GRANT_SIMULATED_PRIVILEGE",
    "ADD_SIMULATED_RELATIONSHIP",
    "ENABLE_SIMULATED_ACCESS",
    "MARK_RESOURCE_REACHABLE",
    "SIMULATE_DATA_ACCESS",
    "SIMULATE_DATA_EXFILTRATION",
    "SIMULATE_DESTRUCTIVE_ACCESS",
    "REMOVE_SIMULATED_PRIVILEGE",
    "REMOVE_SIMULATED_RELATIONSHIP",
    "DISABLE_SIMULATED_IDENTITY"
}

class WhatIfSimulationEngine:
    
    def __init__(self, max_depth=10, max_paths=100, max_nodes=5000):
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.max_nodes = max_nodes

    def simulate(self, current_state: SimulationState, scenario: SimulationScenario) -> WhatIfSimulationResult:
        if current_state.organization_id != scenario.organization_id:
            raise ValueError("Simulation inputs belong to different organizations")
            
        # 1. Validate scenario changes
        for change in scenario.hypothetical_changes:
            if change.change_type not in ALLOWED_SIMULATION_CHANGES:
                raise ValueError(f"Unsupported simulation change type: {change.change_type}")

        # 2. Deep copy to ensure real state is untouched
        sim_state = copy.deepcopy(current_state)
        
        # 3. Baseline calculation
        baseline = self._calculate_graph(sim_state)
        
        evidence = ["INFERRED: Baseline calculated successfully"]
        state = "COMPLETED"
        uncertainty = "LOW"
        
        # 4. Apply hypothetical changes
        for change in scenario.hypothetical_changes:
            if change.change_type == "MARK_IDENTITY_COMPROMISED":
                if change.source_id in sim_state.identities:
                    sim_state.identities[change.source_id].compromised = True
                    evidence.append(f"SIMULATED: Marked identity {change.source_id} as compromised")
            elif change.change_type == "GRANT_SIMULATED_PRIVILEGE":
                if change.source_id in sim_state.identities:
                    priv = change.parameters.get("privilege", "admin")
                    sim_state.identities[change.source_id].privileges.append(priv)
                    evidence.append(f"SIMULATED: Granted privilege {priv} to {change.source_id}")
            elif change.change_type == "ADD_SIMULATED_RELATIONSHIP":
                if change.source_id and change.target_id:
                    rel = SimulationRelationship(
                        source_id=change.source_id,
                        target_id=change.target_id,
                        relationship_type=change.parameters.get("relationship_type", "ACCESS")
                    )
                    sim_state.relationships.append(rel)
                    evidence.append(f"SIMULATED: Added relationship from {change.source_id} to {change.target_id}")
            elif change.change_type == "SIMULATE_DATA_EXFILTRATION":
                if change.target_id in sim_state.assets:
                    sim_state.assets[change.target_id].metadata["simulated_exfiltrated"] = True
                    evidence.append(f"SIMULATED: Data exfiltration from {change.target_id}")
            elif change.change_type == "SIMULATE_DESTRUCTIVE_ACCESS":
                if change.target_id in sim_state.assets:
                    sim_state.assets[change.target_id].metadata["simulated_destroyed"] = True
                    evidence.append(f"SIMULATED: Destructive access to {change.target_id}")
            elif change.change_type == "DISABLE_SIMULATED_IDENTITY":
                if change.source_id in sim_state.identities:
                    sim_state.identities[change.source_id].compromised = False # Not compromised if disabled, or just metadata
                    sim_state.identities[change.source_id].metadata["simulated_disabled"] = True
                    # Remove all relationships originating from this identity
                    sim_state.relationships = [r for r in sim_state.relationships if r.source_id != change.source_id]
                    evidence.append(f"SIMULATED: Disabled identity {change.source_id}")
            elif change.change_type == "REMOVE_SIMULATED_PRIVILEGE":
                if change.source_id in sim_state.identities:
                    priv = change.parameters.get("privilege", "admin")
                    if priv in sim_state.identities[change.source_id].privileges:
                        sim_state.identities[change.source_id].privileges.remove(priv)
                    evidence.append(f"SIMULATED: Removed privilege {priv} from {change.source_id}")
            elif change.change_type == "REMOVE_SIMULATED_RELATIONSHIP":
                if change.source_id and change.target_id:
                    sim_state.relationships = [
                        r for r in sim_state.relationships 
                        if not (r.source_id == change.source_id and r.target_id == change.target_id)
                    ]
                    evidence.append(f"SIMULATED: Removed relationship from {change.source_id} to {change.target_id}")
            # ... handle others
        
        # 5. Recalculate graph
        simulated = self._calculate_graph(sim_state)
        
        if len(sim_state.assets) == 0 and len(sim_state.identities) == 0:
            return self._build_empty_result(scenario, baseline)
            
        # 6. Compare Before/After
        new_reachable = simulated.reachable_assets - baseline.reachable_assets
        lost_reachable = baseline.reachable_assets - simulated.reachable_assets
        
        # Simplified paths for comparison
        base_paths_hashes = {str(p.nodes) for p in baseline.attack_paths}
        new_attack_paths = [p for p in simulated.attack_paths if str(p.nodes) not in base_paths_hashes]
        
        risk_delta = simulated.path_risk_score - baseline.path_risk_score
        
        # 7. Blast Radius
        br = self._calculate_blast_radius(sim_state, new_reachable, new_attack_paths)
        
        # 8. Impact Level
        impact_level = self._determine_impact(br)
        if impact_level == "UNKNOWN" and len(sim_state.assets) > 0:
            # Metadata missing logic
            uncertainty = "HIGH"
            state = "PARTIAL"

        return WhatIfSimulationResult(
            scenario_id=scenario.scenario_id,
            organization_id=scenario.organization_id,
            simulated_stage=scenario.predicted_stage,
            baseline=baseline,
            simulated_reachable_assets=simulated.reachable_assets,
            new_reachable_assets=new_reachable,
            lost_reachable_assets=lost_reachable,
            new_attack_paths=new_attack_paths,
            blast_radius=br,
            baseline_risk_score=baseline.path_risk_score,
            simulated_risk_score=simulated.path_risk_score,
            risk_delta=round(risk_delta, 3),
            impact_level=impact_level,
            assumptions=scenario.assumptions,
            evidence=evidence,
            uncertainty=uncertainty,
            state=state
        )

    def _calculate_graph(self, state: SimulationState) -> SimulationBaseline:
        adj = {}
        for r in state.relationships:
            adj.setdefault(r.source_id, []).append(r.target_id)
            
        reachable = set()
        paths = []
        path_count = 0
        
        # Start BFS from all compromised identities
        starts = [uid for uid, u in state.identities.items() if u.compromised]
            
        for start in starts:
            queue = [(start, [start])]
            visited = {start}
            while queue:
                if path_count >= self.max_paths:
                    break
                curr, path = queue.pop(0)
                if len(path) > self.max_depth:
                    continue
                    
                if curr in state.assets:
                    reachable.add(curr)
                    # Score simplistic mock logic
                    is_crit = state.assets[curr].criticality == "CRITICAL"
                    paths.append(SimulatedAttackPath(
                        nodes=path,
                        relationships=[],
                        path_length=len(path)-1,
                        risk_score=0.8 if is_crit else 0.4,
                        reaches_critical_asset=is_crit
                    ))
                    path_count += 1
                    
                for nxt in adj.get(curr, []):
                    if nxt not in visited or curr in state.assets:
                        # Allow revisiting nodes if they are assets, but be careful with cycles
                        # Actually to prevent cycles properly:
                        if nxt not in path:
                            visited.add(nxt)
                            queue.append((nxt, path + [nxt]))
                            
        crit_assets = {a for a in reachable if a in state.assets and state.assets[a].criticality == "CRITICAL"}
        
        risk_score = 0.0
        if paths:
            risk_score = max(p.risk_score for p in paths)
            
        return SimulationBaseline(
            reachable_assets=reachable,
            attack_paths=paths,
            critical_assets=crit_assets,
            path_risk_score=risk_score
        )
        
    def _calculate_blast_radius(self, state: SimulationState, new_reachable: Set[str], new_paths: List[SimulatedAttackPath]) -> BlastRadius:
        providers = set()
        regions = set()
        crit = 0
        sens = 0
        
        for a_id in new_reachable:
            if a_id in state.assets:
                a = state.assets[a_id]
                providers.add(a.provider)
                if a.region:
                    regions.add(a.region)
                if a.criticality == "CRITICAL":
                    crit += 1
                if a.sensitivity == "SENSITIVE":
                    sens += 1
                    
        max_depth = 0
        if new_paths:
            max_depth = max(p.path_length for p in new_paths)
            
        return BlastRadius(
            affected_assets=len(new_reachable),
            affected_identities=0, # Simplified for now
            critical_assets=crit,
            sensitive_assets=sens,
            providers_affected=len(providers),
            regions_affected=len(regions),
            new_reachable_assets=len(new_reachable),
            new_attack_paths=len(new_paths),
            max_path_depth=max_depth
        )
        
    def _determine_impact(self, br: BlastRadius) -> str:
        if br.affected_assets == 0:
            return "LOW"
        
        if br.critical_assets > 1:
            return "CRITICAL"
        elif br.critical_assets > 0 or br.sensitive_assets > 0:
            return "HIGH"
        elif br.affected_assets > 1:
            return "MEDIUM"
        else:
            return "UNKNOWN"

    def _build_empty_result(self, scenario, baseline):
        return WhatIfSimulationResult(
            scenario_id=scenario.scenario_id,
            organization_id=scenario.organization_id,
            simulated_stage=scenario.predicted_stage,
            baseline=baseline,
            simulated_reachable_assets=set(),
            new_reachable_assets=set(),
            lost_reachable_assets=set(),
            new_attack_paths=[],
            blast_radius=BlastRadius(),
            baseline_risk_score=0.0,
            simulated_risk_score=0.0,
            risk_delta=0.0,
            impact_level="UNKNOWN",
            uncertainty="HIGH",
            state="INSUFFICIENT_DATA"
        )
