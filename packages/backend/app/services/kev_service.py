import requests
from typing import Dict, List, Set
from datetime import datetime

class KEVService:
    """Service to sync and check CISA Known Exploited Vulnerabilities"""
    
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def __init__(self):
        self.kev_cache: Set[str] = set()
        self.last_sync = None
        
    def sync_feed(self) -> int:
        """Fetch the latest KEV catalog and update cache"""
        try:
            response = requests.get(self.KEV_URL, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                # Extract CVE IDs
                new_cache = set()
                for vuln in vulnerabilities:
                    if "cveID" in vuln:
                        new_cache.add(vuln["cveID"])
                        
                self.kev_cache = new_cache
                self.last_sync = datetime.utcnow()
                return len(self.kev_cache)
        except Exception as e:
            print(f"Error syncing KEV feed: {e}")
            
        return len(self.kev_cache)
        
    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the CISA KEV catalog"""
        if not self.kev_cache:
            # Sync on first use if not explicitly synced
            self.sync_feed()
            
        return cve_id in self.kev_cache

kev_service = KEVService()
