from typing import List, Dict, Any
from security.models.attack_simulation_schema import AttackSimulationSchema
from security.models.security_correlation_schema import SecurityCorrelationSchema

class AttackSimulationEngine:
    """
    Engine to simulate the potential blast radius (What-If analysis) of a suspicious identity.
    Relies purely on the Digital Twin (read-only graph analysis), never mutates cloud state.
    """
    
    @staticmethod
    def simulate_blast_radius(storyline: SecurityCorrelationSchema, twin_context: Dict[str, Any]) -> AttackSimulationSchema:
        """
        Calculates reachable assets and blast radius based on the given storyline and twin context.
        """
        identity = storyline.actors[0] if storyline.actors else "unknown"
        
        # In a full graph implementation, this would query the Digital Twin relationships (e.g., using NetworkX or Neo4j logic).
        # For the contract, we extract from the twin context provided by SecurityDigitalTwin.
        reachable = 0
        sensitive = 0
        paths = []
        
        if twin_context and "target_context" in twin_context:
            target = twin_context["target_context"]
            reachable += 1
            if target.get("criticality") == "high":
                sensitive += 1
            paths.append({"asset_id": target.get("asset_id"), "access_vector": "direct_event_target"})
            
        # Qualitative blast radius calculation
        blast_radius = "low"
        if sensitive > 0:
            blast_radius = "high"
        elif reachable > 5:
            blast_radius = "medium"
            
        return AttackSimulationSchema(
            identity=identity,
            reachable_assets=reachable,
            sensitive_assets=sensitive,
            blast_radius=blast_radius,
            paths=paths
        )
