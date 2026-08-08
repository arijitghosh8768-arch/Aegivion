from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

@dataclass
class MitreTechnique:
    id: str
    name: str
    tactic: str
    description: str
    url: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class MitreMapping:
    technique_id: str
    technique_name: str
    relationship: str  # relevant_to, specifically_targets, evidence_of
    confidence: float  # 0.0 - 1.0
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class MitreService:
    """MITRE ATT&CK mapping service with defensible mappings"""
    
    def __init__(self):
        self.mitre_data = self._load_mitre_data()
        self.rule_mappings = self._load_rule_mappings()
    
    def _load_mitre_data(self) -> Dict[str, MitreTechnique]:
        """Load MITRE technique data"""
        return {
            'T1046': MitreTechnique(
                id='T1046',
                name='Network Service Discovery',
                tactic='Discovery',
                description='Adversaries may attempt to get a listing of services running on remote hosts.',
                url='https://attack.mitre.org/techniques/T1046/'
            ),
            'T1078': MitreTechnique(
                id='T1078',
                name='Valid Accounts',
                tactic='Initial Access',
                description='Adversaries may obtain and abuse credentials of existing accounts.',
                url='https://attack.mitre.org/techniques/T1078/'
            ),
            'T1098': MitreTechnique(
                id='T1098',
                name='Account Manipulation',
                tactic='Persistence',
                description='Adversaries may manipulate accounts to maintain access.',
                url='https://attack.mitre.org/techniques/T1098/'
            ),
            'T1190': MitreTechnique(
                id='T1190',
                name='Exploit Public-Facing Application',
                tactic='Initial Access',
                description='Adversaries may attempt to exploit a weakness in an internet-facing system.',
                url='https://attack.mitre.org/techniques/T1190/'
            ),
            'T1530': MitreTechnique(
                id='T1530',
                name='Data from Cloud Storage',
                tactic='Exfiltration',
                description='Adversaries may access data from cloud storage services.',
                url='https://attack.mitre.org/techniques/T1530/'
            ),
            'T1526': MitreTechnique(
                id='T1526',
                name='Cloud Service Discovery',
                tactic='Discovery',
                description='Adversaries may attempt to enumerate cloud services.',
                url='https://attack.mitre.org/techniques/T1526/'
            )
        }
    
    def _load_rule_mappings(self) -> Dict[str, List[Dict]]:
        """Load rule to MITRE mappings"""
        return {
            # Network rules
            'AWS-SG-001': [
                {
                    'technique_id': 'T1046',
                    'relationship': 'relevant_to',
                    'confidence': 0.85,
                    'reason': 'SSH exposure increases service discovery surface'
                },
                {
                    'technique_id': 'T1190',
                    'relationship': 'relevant_to',
                    'confidence': 0.75,
                    'reason': 'Public-facing service accessible without restrictions'
                }
            ],
            'AWS-SG-002': [
                {
                    'technique_id': 'T1190',
                    'relationship': 'relevant_to',
                    'confidence': 0.80,
                    'reason': 'Public-facing RDP service accessible'
                }
            ],
            'AWS-SG-007': [
                {
                    'technique_id': 'T1190',
                    'relationship': 'relevant_to',
                    'confidence': 0.80,
                    'reason': 'Public-facing instance exposes workload port services'
                }
            ],
            # IAM rules
            'AWS-IAM-001': [
                {
                    'technique_id': 'T1078',
                    'relationship': 'relevant_to',
                    'confidence': 0.90,
                    'reason': 'Console access without additional authentication'
                }
            ],
            'AWS-IAM-004': [
                {
                    'technique_id': 'T1098',
                    'relationship': 'relevant_to',
                    'confidence': 0.85,
                    'reason': 'Administrative privileges increase risk of account manipulation'
                }
            ],
            'AWS-IAM-007': [
                {
                    'technique_id': 'T1098',
                    'relationship': 'relevant_to',
                    'confidence': 0.85,
                    'reason': 'Privileged user manipulation risks account hijacking'
                }
            ],
            # S3 rules
            'AWS-S3-001': [
                {
                    'technique_id': 'T1530',
                    'relationship': 'relevant_to',
                    'confidence': 0.90,
                    'reason': 'Public access increases data exfiltration risk'
                }
            ]
        }
    
    def get_mappings_for_finding(self, finding: Dict) -> List[MitreMapping]:
        """Get MITRE mappings for a finding"""
        rule_id = finding.get('rule_id')
        
        if rule_id not in self.rule_mappings:
            return []
        
        mappings = []
        for mapping in self.rule_mappings[rule_id]:
            technique = self.mitre_data.get(mapping['technique_id'])
            if technique:
                mappings.append(MitreMapping(
                    technique_id=technique.id,
                    technique_name=technique.name,
                    relationship=mapping['relationship'],
                    confidence=mapping['confidence'],
                    reason=mapping['reason']
                ))
        
        return mappings
    
    def get_technique_by_id(self, technique_id: str) -> Optional[MitreTechnique]:
        """Get MITRE technique by ID"""
        return self.mitre_data.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[MitreTechnique]:
        """Get techniques by tactic"""
        return [
            t for t in self.mitre_data.values()
            if t.tactic == tactic
        ]
