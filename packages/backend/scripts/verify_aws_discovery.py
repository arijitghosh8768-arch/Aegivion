import os
import sys
import uuid
import logging
from pprint import pprint
from dotenv import load_dotenv

# Ensure we can import app modules
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from app.database import SessionLocal
from app.repositories.twin_persistence_repository import TwinPersistenceRepository
from app.services.aws_discovery_service import AWSDiscoveryService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def verify_discovery():
    load_dotenv()
    
    # 1. Verification of credentials existence
    if not (os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE")):
        logger.warning("No AWS_ACCESS_KEY_ID or AWS_PROFILE found. Make sure you have read-only credentials configured.")
        
    db_session = SessionLocal()
    
    # Create a test organization for this validation
    test_org_id = str(uuid.uuid4())
    test_account_id = os.getenv("TEST_AWS_ACCOUNT_ID", "unknown_account")
    
    logger.info(f"Initializing TwinPersistenceRepository for test ORG {test_org_id}")
    persistence = TwinPersistenceRepository(db_session, test_org_id)
    
    logger.info("Initializing AWSDiscoveryService...")
    discovery_service = AWSDiscoveryService(persistence, test_org_id, test_account_id)
    
    # 2. Run Discovery #1
    logger.info("--- RUNNING DISCOVERY #1 ---")
    result1 = discovery_service.discover_all()
    
    if result1["status"] != "success":
        logger.error(f"Discovery #1 failed: {result1.get('reason')}")
        db_session.close()
        return
        
    logger.info("Discovery #1 Stats:")
    pprint(result1["stats"])
    
    # 3. Verify Idempotency (Discovery #2)
    logger.info("--- RUNNING DISCOVERY #2 (Idempotency Check) ---")
    result2 = discovery_service.discover_all()
    
    if result2["status"] != "success":
        logger.error(f"Discovery #2 failed: {result2.get('reason')}")
    else:
        logger.info("Discovery #2 Stats (Should safely update without duplicates):")
        pprint(result2["stats"])
        
    # 4. Read back the assets to verify Twin insertion
    logger.info("--- VERIFYING DIGITAL TWIN STATE ---")
    assets_result = db_session.table("cloud_assets").select("*").eq("organization_id", test_org_id).execute()
    identities_result = db_session.table("cloud_identities").select("*").eq("organization_id", test_org_id).execute()
    
    logger.info(f"Digital Twin contains {len(assets_result.data)} assets and {len(identities_result.data)} identities.")
    
    logger.info("✅ Read-only AWS discovery validation complete!")
    db_session.close()

if __name__ == "__main__":
    verify_discovery()
