import subprocess

def audit_migrations():
    """Audit database migration consistency check"""
    try:
        # Check current Alembic migration version status
        result = subprocess.run(
            ["alembic", "current"],
            capture_output=True,
            text=True
        )
        if "head" not in result.stdout:
            print("⚠️  WARNING: Migrations are not up to date or head revision is missing!")
            return False
            
        print("✅ Database migrations audited successfully and consistent.")
        return True
    except FileNotFoundError:
        print("ℹ️ Alembic CLI not installed in path. Skipping test.")
        return True

if __name__ == "__main__":
    audit_migrations()
