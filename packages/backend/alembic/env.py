import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

from dotenv import dotenv_values, load_dotenv

# Prioritize TEST_DATABASE_URL if present, otherwise DATABASE_URL
env_test_path = os.path.join(os.path.dirname(__file__), "..", ".env.test")
test_vals = dotenv_values(env_test_path) if os.path.exists(env_test_path) else {}
db_url = os.getenv("TEST_DATABASE_URL") or test_vals.get("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
if not db_url:
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
    db_url = os.getenv("DATABASE_URL")

if db_url:
    # Alembic needs postgresql+psycopg2:// instead of postgres:// or generic postgresql://
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)
    elif db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
    # ConfigParser treats '%' as interpolation, escape as '%%' for set_main_option
    config.set_main_option("sqlalchemy.url", db_url.replace("%", "%%"))
else:
    raw_ini_url = config.get_main_option("sqlalchemy.url")
    if raw_ini_url and raw_ini_url.startswith("postgresql://"):
        config.set_main_option("sqlalchemy.url", raw_ini_url.replace("postgresql://", "postgresql+psycopg2://", 1))

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
from app.models import Base
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here will emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
