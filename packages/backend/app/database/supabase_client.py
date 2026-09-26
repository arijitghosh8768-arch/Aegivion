import logging
import os

from dotenv import load_dotenv
from supabase import Client, create_client

load_dotenv()

logger = logging.getLogger(__name__)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")


def get_supabase() -> Client:
    if not SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is not configured")

    if not SUPABASE_KEY:
        raise RuntimeError("SUPABASE_KEY is not configured")

    try:
        return create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as exc:
        logger.exception("Failed to initialize Supabase client")
        raise RuntimeError("Supabase initialization failed") from exc


supabase = get_supabase()
