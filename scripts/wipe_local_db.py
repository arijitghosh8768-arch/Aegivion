import certifi
from pymongo import MongoClient

try:
    print(f"Connecting to Local MongoDB...")
    client = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=2000)
    
    db_names = client.list_database_names()
    print(f"Available databases: {db_names}")
    
    for db_name in db_names:
        if db_name in ("admin", "config", "local"):
            continue
        db = client[db_name]
        print(f"Using database: {db_name}")
        collections_to_wipe = ["cloud_assets", "findings", "asset_relationships", "incidents", "audit_logs"]
        for coll in collections_to_wipe:
            db[coll].drop()
            print(f"  Dropped {coll}")
            
    print("Local database wiped successfully!")
except Exception as e:
    print(f"Error: {e}")
