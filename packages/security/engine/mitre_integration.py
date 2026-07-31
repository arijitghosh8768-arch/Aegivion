from typing import List, Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass

class MitreTactic(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"

@dataclass
class MitreTechnique:
    id: str
    name: str
    tactic: MitreTactic
    description: str

class MitreService:
    def __init__(self):
        self.techniques = {
            "T1530": MitreTechnique("T1530", "Data from Cloud Shared Storage", MitreTactic.COLLECTION, "Adversaries may access data from cloud shared storage to exfiltrate sensitive files."),
            "T1078": MitreTechnique("T1078", "Valid Accounts", MitreTactic.INITIAL_ACCESS, "Adversaries may obtain credentials to gain access to cloud administrative roles."),
            "T1562": MitreTechnique("T1562", "Impair Defenses", MitreTactic.DEFENSE_EVASION, "Adversaries may disable security logging or firewalls to evade detection.")
        }
        self.attack_graph = {
            'T1078': ['T1530', 'T1562'],
            'T1562': ['T1530']
        }
    
    def map_finding_to_mitre(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        mapped_techniques = []
        resource_type = finding.get('resource_type', '').lower()
        
        mappings = {
            'aws_s3_bucket': ['T1530'],
            'azure_virtual_machine': ['T1562'],
            'user': ['T1078']
        }
        
        target_ids = mappings.get(resource_type, [])
        for tid in target_ids:
            tech = self.techniques.get(tid)
            if tech:
                mapped_techniques.append({
                    'technique_id': tech.id,
                    'technique_name': tech.name,
                    'tactic': tech.tactic.value,
                    'description': tech.description
                })
        return mapped_techniques
    
    def find_attack_paths(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        techniques = []
        for finding in findings:
            mapped = self.map_finding_to_mitre(finding)
            techniques.extend([m['technique_id'] for m in mapped])
            
        paths = []
        for tech in set(techniques):
            if tech in self.attack_graph:
                for target in self.attack_graph[tech]:
                    if target in techniques:
                        paths.append({
                            'source': tech,
                            'target': target,
                            'path': [tech, target]
                        })
        return paths
