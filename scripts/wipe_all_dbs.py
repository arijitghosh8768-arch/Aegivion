import certifi
from pymongo import MongoClient

try:
    print(f"Connecting to MongoDB Atlas...")
    client = MongoClient("mongodb+srv://arijitghosh8768_db_user:NkITBDqEW4qi99bA@cluster0.vym1z8g.mongodb.net", tlsAllowInvalidCertificates=True, tlsCAFile=certifi.where())
    
    db_names = client.list_database_names()
    print(f"Available databases: {db_names}")
    
    for db_name in db_names:
        if db_name in ("admin", "local", "config", "sample_mflix"):
            continue
        db = client[db_name]
        print(f"Using database: {repr(db_name)}")
        collections_to_wipe = ["cloud_assets", "findings", "asset_relationships", "incidents", "audit_logs"]
        for coll in collections_to_wipe:
            db[coll].drop()
            print(f"  Dropped {coll}")
            
    print("Database wiped successfully!")
except Exception as e:
    print(f"Error: {e}")
