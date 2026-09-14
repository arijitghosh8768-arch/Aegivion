from typing import Dict, Optional

class MitreMapper:
    """Maps security findings to MITRE ATT&CK techniques."""
    
    CATEGORY_MAP = {
        'PUBLIC_EXPOSURE': 'T1133', # External Remote Services
        'PRIVILEGE_ESCALATION': 'T1078', # Valid Accounts (can also be T1548)
        'LATERAL_MOVEMENT': 'T1021', # Remote Services
        'VULNERABILITY': 'T1190', # Exploit Public-Facing Application
        'STORAGE_EXPOSURE': 'T1530', # Data from Cloud Storage Object
        'CREDENTIAL_EXPOSURE': 'T1552', # Unsecured Credentials
    }
    
    TECHNIQUE_NAMES = {
        'T1133': 'External Remote Services',
        'T1078': 'Valid Accounts',
        'T1021': 'Remote Services',
        'T1190': 'Exploit Public-Facing Application',
        'T1530': 'Data from Cloud Storage Object',
        'T1552': 'Unsecured Credentials',
        'T1098': 'Account Manipulation',
        'T1548': 'Abuse Elevation Control Mechanism'
    }
    
    @classmethod
    def get_technique_for_category(cls, category: str) -> Optional[str]:
        return cls.CATEGORY_MAP.get(category.upper())
        
    @classmethod
    def get_technique_name(cls, technique_id: str) -> str:
        return cls.TECHNIQUE_NAMES.get(technique_id, "Unknown Technique")
        
    @classmethod
    def enrich_finding(cls, finding: Dict) -> Dict:
        """Enrich a finding with MITRE ATT&CK metadata."""
        category = finding.get('category', '')
        if category:
            technique_id = cls.get_technique_for_category(category)
            if technique_id:
                finding['mitre_technique'] = technique_id
                finding['mitre_tactic'] = cls.get_technique_name(technique_id)
        return finding
