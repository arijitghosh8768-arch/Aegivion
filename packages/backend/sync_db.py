import os
import pymongo

MONGODB_URI = os.environ.get("MONGODB_URI", "")
client = pymongo.MongoClient(MONGODB_URI)
db_src = client['aegivion']
db_dest = client['aegivion\n']

admin = db_src['users'].find_one({'email': 'superadmin@aegivion.com'})
if admin:
    db_dest['users'].update_one({'email': admin['email']}, {'$set': admin}, upsert=True)
    print('Copied superadmin to aegivion\\n')

roles = db_src['roles'].find({})
for r in roles:
    db_dest['roles'].update_one({'name': r['name']}, {'$set': r}, upsert=True)
    print(f'Copied role {r["name"]} to aegivion\\n')
