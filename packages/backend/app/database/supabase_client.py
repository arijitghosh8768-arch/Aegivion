import os
from supabase import create_client, Client
from dotenv import load_dotenv

# Load env variables (assuming loaded at app startup as well)
load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://mock.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "mock-key")

# Create a singleton client
def get_supabase() -> Client:
    # If using real credentials, create client. Otherwise, return a mock or actual client depending on environment
    return create_client(SUPABASE_URL, SUPABASE_KEY)

supabase = get_supabase()
