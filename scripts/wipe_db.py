import os
import certifi
from pymongo import MongoClient

# The user's connection string from the summary
MONGODB_URI = "mongodb+srv://arijitghosh8768_db_user:NkITBDqEW4qi99bA@cluster0.vym1z8g.mongodb.net"

try:
    print(f"Connecting to MongoDB...")
    client = MongoClient(MONGODB_URI, tlsAllowInvalidCertificates=True, tlsCAFile=certifi.where())
    
    # Extract DB name (cluster0 doesn't specify one, usually it's aegivion or test)
    # Let's list databases
    db_names = client.list_database_names()
    print(f"Available databases: {db_names}")
    
    db_name = "aegivion" if "aegivion" in db_names else "test"
    db = client[db_name]
    
    print(f"Using database: {db_name}")
    print(f"Collections: {db.list_collection_names()}")
    
    # Drop seeded collections
    collections_to_wipe = ["cloud_assets", "findings", "asset_relationships", "incidents", "audit_logs"]
    
    for coll in collections_to_wipe:
        print(f"Dropping collection {coll}...")
        db[coll].drop()
        
    print("Database wiped successfully!")
    
except Exception as e:
    print(f"Error: {e}")
