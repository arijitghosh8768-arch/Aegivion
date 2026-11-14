"""enable row level security with force enforcement and tenant policies
Revision ID: b0011_enable_rls_policies
Revises: b0010_encrypted_credentials
Create Date: 2026-11-10 00:05:00.000000

"""
from typing import Sequence, Union
try:
    from alembic import op
except ImportError:
    op = None
import sqlalchemy as sa

revision: str = 'b0011_enable_rls_policies'
down_revision: Union[str, None] = 'b0010_encrypted_credentials'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLES = [
    'cloud_accounts',
    'cloud_accounts_v2',
    'findings',
    'incidents',
    'remediation_plans'
]

def upgrade() -> None:
    for table in TABLES:
        # 1. Enable and FORCE RLS (enforces policies even for table owner / BYPASSRLS roles)
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")

        # 2. Drop existing policy if exists to make upgrade idempotent
        policy_name = f"tenant_isolation_{table}"
        op.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table};")

        # 3. Create Tenant Isolation Policy
        # Allows access if:
        # - app.current_org_id is unset or empty (system/migration mode)
        # - app.current_org_id is explicitly set to 'bypass'
        # - organization_id matches app.current_org_id
        policy_sql = f"""
        CREATE POLICY {policy_name} ON {table}
        FOR ALL
        USING (
            NULLIF(current_setting('app.current_org_id', true), '') IS NULL
            OR current_setting('app.current_org_id', true) = 'bypass'
            OR organization_id = current_setting('app.current_org_id', true)::uuid
        )
        WITH CHECK (
            NULLIF(current_setting('app.current_org_id', true), '') IS NULL
            OR current_setting('app.current_org_id', true) = 'bypass'
            OR organization_id = current_setting('app.current_org_id', true)::uuid
        );
        """
        op.execute(policy_sql)

def downgrade() -> None:
    for table in TABLES:
        policy_name = f"tenant_isolation_{table}"
        op.execute(f"DROP POLICY IF EXISTS {policy_name} ON {table};")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")
