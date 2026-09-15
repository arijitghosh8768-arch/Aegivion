from typing import List, Dict, Any
from datetime import datetime, timedelta

def detect_credential_compromise(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects credential compromise (e.g. Impossible Travel, Brute Force, Token Theft)
    by analyzing authentication events over time.
    """
    alerts = []
    
    # Simple Brute Force Detection: 5+ failed logins followed by a success within 10 minutes
    user_failures = {}
    for event in events:
        if event.get("event_type") == "ConsoleLogin" and event.get("status") == "Failure":
            user = event.get("user_identity", {}).get("arn")
            if not user:
                continue
            if user not in user_failures:
                user_failures[user] = []
            user_failures[user].append(event)
            
        elif event.get("event_type") == "ConsoleLogin" and event.get("status") == "Success":
            user = event.get("user_identity", {}).get("arn")
            if user in user_failures and len(user_failures[user]) >= 5:
                # Check timeframe
                first_fail_time = datetime.fromisoformat(user_failures[user][0]["event_time"].replace("Z", "+00:00"))
                success_time = datetime.fromisoformat(event["event_time"].replace("Z", "+00:00"))
                if (success_time - first_fail_time).total_seconds() <= 600:
                    alerts.append({
                        "id": f"credential-compromise-{user}",
                        "title": "Credential Compromise: Brute Force Success",
                        "severity": "CRITICAL",
                        "description": f"User {user} had {len(user_failures[user])} failed login attempts followed by a successful login within 10 minutes.",
                        "mitre_technique": "T1110 - Brute Force",
                        "affected_resource": user
                    })
                # Reset
                user_failures[user] = []
    return alerts

def detect_data_exfiltration(events: List[Dict[str, Any]], assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects potential data exfiltration (e.g. bulk S3 downloads, large DB snapshots shared publicly).
    """
    alerts = []
    
    # 1. Bulk S3 downloads from a single identity
    s3_downloads_by_user = {}
    for event in events:
        if event.get("event_name") in ["GetObject", "ListObjects"]:
            user = event.get("user_identity", {}).get("arn", "unknown")
            if user not in s3_downloads_by_user:
                s3_downloads_by_user[user] = 0
            s3_downloads_by_user[user] += 1
            
            # Arbitrary threshold for bulk access (e.g. >1000 objects in short time window)
            if s3_downloads_by_user[user] > 1000:
                alerts.append({
                    "id": f"data-exfiltration-{user}",
                    "title": "Data Exfiltration: Bulk S3 Access",
                    "severity": "HIGH",
                    "description": f"Identity {user} requested an unusually large volume of S3 objects (>1000) recently.",
                    "mitre_technique": "T1530 - Data from Cloud Storage",
                    "affected_resource": user
                })
                s3_downloads_by_user[user] = -999999 # Suppress further alerts
                
    # 2. Publicly shared DB snapshots
    for event in events:
        if event.get("event_name") == "ModifyDBSnapshotAttribute":
            attrs = event.get("request_parameters", {})
            if attrs.get("AttributeName") == "restore" and "all" in attrs.get("ValuesToAdd", []):
                alerts.append({
                    "id": f"data-exfiltration-db-{event.get('event_id')}",
                    "title": "Data Exfiltration: Public DB Snapshot",
                    "severity": "CRITICAL",
                    "description": "A database snapshot was just modified to allow restoration by all AWS accounts (Publicly shared).",
                    "mitre_technique": "T1537 - Transfer Data to Cloud Account",
                    "affected_resource": event.get("request_parameters", {}).get("DBSnapshotIdentifier")
                })
                
    return alerts

def detect_ransomware(events: List[Dict[str, Any]], assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects Ransomware activity (e.g. mass KMS key deletion, S3 mass encryption/deletion, disabling CloudTrail).
    """
    alerts = []
    
    kms_deletions = 0
    s3_deletions = 0
    trail_disabled = False
    
    for event in events:
        name = event.get("event_name")
        if name in ["ScheduleKeyDeletion", "DisableKey"]:
            kms_deletions += 1
        elif name in ["DeleteObject", "DeleteBucket"]:
            s3_deletions += 1
        elif name in ["StopLogging", "DeleteTrail"]:
            trail_disabled = True
            alerts.append({
                "id": f"ransomware-trail-{event.get('event_id')}",
                "title": "Ransomware Precursor: CloudTrail Disabled",
                "severity": "CRITICAL",
                "description": "CloudTrail logging was stopped or deleted, which is often a precursor to a ransomware attack.",
                "mitre_technique": "T1562.008 - Disable Cloud Logs",
                "affected_resource": "CloudTrail"
            })
            
    if kms_deletions > 5:
        alerts.append({
            "id": f"ransomware-kms-{datetime.utcnow().timestamp()}",
            "title": "Ransomware Indicator: Mass KMS Key Deletion",
            "severity": "CRITICAL",
            "description": f"Detected {kms_deletions} KMS keys scheduled for deletion. Attackers do this to lock you out of encrypted data.",
            "mitre_technique": "T1485 - Data Destruction",
            "affected_resource": "AWS KMS"
        })
        
    if s3_deletions > 1000:
        alerts.append({
            "id": f"ransomware-s3-{datetime.utcnow().timestamp()}",
            "title": "Ransomware Indicator: Mass S3 Deletions",
            "severity": "CRITICAL",
            "description": f"Detected {s3_deletions} S3 Object deletion events in a short timeframe.",
            "mitre_technique": "T1485 - Data Destruction",
            "affected_resource": "AWS S3"
        })
        
    return alerts
